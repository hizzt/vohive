package swu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

var ErrInvalidTUNTunnelManager = errors.New("invalid swu tun tunnel manager")

type TUNDeviceFactory func(context.Context, TunnelConfig, TunnelResult) (InnerPacketDevice, string, error)

type TUNRoutingConfigFactory func(TunnelConfig, TunnelResult, string) (TUNRoutingConfig, error)

type TUNRoutingManager interface {
	Apply(context.Context, TUNRoutingConfig) (TUNRoutingState, error)
	Cleanup(context.Context, TUNRoutingState) error
}

type EPDGRouteResolver func(context.Context, string) ([]net.IP, error)

type TUNTunnelManagerConfig struct {
	Base                 TunnelManager
	TUN                  TUNDeviceConfig
	DeviceFactory        TUNDeviceFactory
	RoutingManager       TUNRoutingManager
	RoutingConfigFactory TUNRoutingConfigFactory
	DisableRouting       bool
	DefaultRoutes        bool
	ProtectEPDGRoutes    bool
	EPDGRouteResolver    EPDGRouteResolver
	MTU                  int
	Addresses            []string
	EPDGRouteExclusions  []EPDGRouteExclusion
	Routes               []TUNRoute
	Rules                []TUNRule
	OnPumpError          func(PacketPumpDirection, error)
}

type TUNTunnelManager struct {
	Config TUNTunnelManagerConfig
}

type TUNPacketTunnelSession struct {
	mu             sync.Mutex
	base           PacketTunnelReadSession
	pump           *PacketPump
	routing        TUNRoutingManager
	routingState   TUNRoutingState
	routingApplied bool
	result         TunnelResult
	closed         bool
}

var _ TunnelManager = (*TUNTunnelManager)(nil)
var _ TunnelSession = (*TUNPacketTunnelSession)(nil)
var _ PSCFRestoreNotifier = (*TUNPacketTunnelSession)(nil)

// SetOnPSCFRestore 转发给内层 PacketSession（responder 在其上）。
func (t *TUNPacketTunnelSession) SetOnPSCFRestore(fn func(newPSCF string)) {
	if t == nil {
		return
	}
	if base, ok := t.base.(*PacketSession); ok {
		base.SetOnPSCFRestore(fn)
	}
}

func NewTUNTunnelManager(cfg TUNTunnelManagerConfig) *TUNTunnelManager {
	return &TUNTunnelManager{Config: cfg}
}

func NewTUNIKETunnelManager(ikeCfg IKEPacketTunnelManagerConfig, tunCfg TUNTunnelManagerConfig) *TUNTunnelManager {
	tunCfg.Base = NewIKEPacketTunnelManager(ikeCfg)
	return NewTUNTunnelManager(tunCfg)
}

func (m *TUNTunnelManager) EstablishTunnel(ctx context.Context, cfg TunnelConfig) (TunnelSession, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: manager is nil", ErrInvalidTUNTunnelManager)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	base := m.Config.Base
	if base == nil {
		return nil, fmt.Errorf("%w: base manager is nil", ErrInvalidTUNTunnelManager)
	}
	baseSession, err := base.EstablishTunnel(ctx, cfg)
	if err != nil {
		return nil, err
	}
	packetSession, ok := baseSession.(PacketTunnelReadSession)
	if !ok {
		_ = baseSession.Close(ctx)
		return nil, fmt.Errorf("%w: base session cannot read packet tunnel traffic", ErrInvalidTUNTunnelManager)
	}
	result := completeTUNResult(packetSession.Result())
	device, iface, err := m.openDevice(ctx, cfg, result)
	if err != nil {
		_ = packetSession.Close(ctx)
		return nil, err
	}
	routing := m.Config.RoutingManager
	if routing == nil {
		routing = LinuxTUNRoutingManager{}
	}
	var routingState TUNRoutingState
	routingApplied := false
	if !m.Config.DisableRouting {
		routingCfg, err := m.routingConfig(ctx, cfg, result, iface)
		if err != nil {
			_ = closeInnerPacketDevice(ctx, device)
			_ = packetSession.Close(ctx)
			return nil, err
		}
		routingState, err = routing.Apply(ctx, routingCfg)
		if err != nil {
			_ = closeInnerPacketDevice(ctx, device)
			_ = packetSession.Close(ctx)
			return nil, err
		}
		routingApplied = true
	}
	pump, err := NewPacketPump(PacketPumpConfig{
		Session: packetSession,
		Device:  device,
		OnError: m.Config.OnPumpError,
	})
	if err != nil {
		if routingApplied {
			_ = routing.Cleanup(ctx, routingState)
		}
		_ = closeInnerPacketDevice(ctx, device)
		_ = packetSession.Close(ctx)
		return nil, err
	}
	if err := pump.Start(context.Background()); err != nil {
		if routingApplied {
			_ = routing.Cleanup(ctx, routingState)
		}
		_ = pump.Close(ctx)
		return nil, err
	}
	// 空闲保活：每 20s 发 ESP 层 ICMP echo（对端必回，双向 ESP 流维持
	// ePDG/代理链路），无响应判定死链关会话触发重建。设备实测 IKE 空
	// INFORMATIONAL 探测在本环境 ~40s 后被 ePDG 无视，ESP 层探测始终有效。
	if livenessSession, ok := packetSession.(*PacketSession); ok {
		livenessSession.StartLivenessLoop(context.Background())
		livenessSession.StartRekeyLoop(context.Background())
	}
	return &TUNPacketTunnelSession{
		base:           packetSession,
		pump:           pump,
		routing:        routing,
		routingState:   routingState,
		routingApplied: routingApplied,
		result:         result,
	}, nil
}

func (m *TUNTunnelManager) openDevice(ctx context.Context, cfg TunnelConfig, result TunnelResult) (InnerPacketDevice, string, error) {
	if m.Config.DeviceFactory != nil {
		device, name, err := m.Config.DeviceFactory(ctx, cfg, result)
		if err != nil {
			return nil, "", err
		}
		if device == nil {
			return nil, "", fmt.Errorf("%w: device factory returned nil", ErrInvalidTUNTunnelManager)
		}
		name = firstPacketNonEmpty(name, innerPacketDeviceName(device), m.Config.TUN.Name)
		if strings.TrimSpace(name) == "" && !m.Config.DisableRouting {
			return nil, "", fmt.Errorf("%w: tun interface name is empty", ErrInvalidTUNTunnelManager)
		}
		return device, name, nil
	}
	device, err := OpenTUNDevice(m.Config.TUN)
	if err != nil {
		return nil, "", err
	}
	name := firstPacketNonEmpty(device.Name(), m.Config.TUN.Name)
	if strings.TrimSpace(name) == "" {
		_ = device.Close(ctx)
		return nil, "", fmt.Errorf("%w: tun interface name is empty", ErrInvalidTUNTunnelManager)
	}
	return device, name, nil
}

func (m *TUNTunnelManager) routingConfig(ctx context.Context, cfg TunnelConfig, result TunnelResult, iface string) (TUNRoutingConfig, error) {
	if m.Config.RoutingConfigFactory != nil {
		return m.Config.RoutingConfigFactory(cfg, result, iface)
	}
	addresses := append([]string(nil), m.Config.Addresses...)
	if len(addresses) == 0 && strings.TrimSpace(result.LocalInnerIP) != "" {
		addresses = append(addresses, strings.TrimSpace(result.LocalInnerIP))
	}
	routes := cloneTUNRoutes(m.Config.Routes)
	if m.Config.DefaultRoutes && len(routes) == 0 {
		routes = append(routes, TUNRoute{Destination: "default"})
	}
	exclusions := cloneEPDGRouteExclusions(m.Config.EPDGRouteExclusions)
	if m.Config.ProtectEPDGRoutes {
		defaultExclusions, err := m.defaultEPDGRouteExclusions(ctx, cfg, result, routes)
		if err != nil {
			return TUNRoutingConfig{}, err
		}
		exclusions = append(exclusions, defaultExclusions...)
	}
	return TUNRoutingConfig{
		InterfaceName:       iface,
		MTU:                 m.Config.MTU,
		Addresses:           addresses,
		EPDGRouteExclusions: exclusions,
		Routes:              routes,
		Rules:               cloneTUNRules(m.Config.Rules),
	}, nil
}

func (m *TUNTunnelManager) defaultEPDGRouteExclusions(ctx context.Context, cfg TunnelConfig, result TunnelResult, routes []TUNRoute) ([]EPDGRouteExclusion, error) {
	outerIface := strings.TrimSpace(cfg.LocalInterface)
	// LocalInterface 语义是"ePDG 出站网络接口名"（如 wlan0），但 runtimehost 把
	// modem.DeviceID（设备逻辑 ID，非网络接口）填了进来——若它不是真实接口，
	// 回退到默认路由的接口名，否则 ip route add 会 "Cannot find device"。
	if outerIface != "" {
		if _, err := net.InterfaceByName(outerIface); err != nil {
			fallback := defaultRouteInterface()
			if fallback == "" {
				return nil, fmt.Errorf("%w: LocalInterface %q is not a real interface and no default route found", ErrInvalidTUNTunnelManager, outerIface)
			}
			outerIface = fallback
		}
	}
	if outerIface == "" {
		return nil, fmt.Errorf("%w: ePDG route protection requires outer interface", ErrInvalidTUNTunnelManager)
	}
	host := tunnelAddressHost(firstPacketNonEmpty(result.EPDGAddress, cfg.EPDGAddress))
	if host == "" {
		return nil, nil
	}
	ips, err := m.resolveEPDGRouteIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, nil
	}
	tables := routingTablesForRoutes(routes)
	out := make([]EPDGRouteExclusion, 0, len(ips))
	for _, ip := range ips {
		normalized := normalizedMOBIKEIP(ip)
		if normalized == nil {
			continue
		}
		out = append(out, EPDGRouteExclusion{
			Address:       normalized.String(),
			InterfaceName: outerIface,
			Source:        strings.TrimSpace(cfg.OuterLocalIP),
			Tables:        tables,
		})
	}
	return out, nil
}

func (m *TUNTunnelManager) resolveEPDGRouteIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return []net.IP{append(net.IP(nil), ip...)}, nil
	}
	resolver := m.Config.EPDGRouteResolver
	if resolver != nil {
		return resolver(ctx, host)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve ePDG route host %q: %v", ErrInvalidTUNTunnelManager, host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, append(net.IP(nil), addr.IP...))
	}
	return ips, nil
}

func routingTablesForRoutes(routes []TUNRoute) []string {
	seen := map[string]bool{}
	var out []string
	for _, route := range routes {
		if normalizeRouteDestinationForRoutingTables(route.Destination) != "default" {
			continue
		}
		table := strings.TrimSpace(route.Table)
		if table == "" || seen[table] {
			continue
		}
		seen[table] = true
		out = append(out, table)
	}
	return out
}

func normalizeRouteDestinationForRoutingTables(destination string) string {
	return strings.ToLower(strings.TrimSpace(destination))
}

func (s *TUNPacketTunnelSession) Result() TunnelResult {
	if s == nil {
		return TunnelResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTunnelResult(s.result)
}

// PumpDone 返回 packet pump 结束信号（pump 任一方向读/写出错退出即关闭）。
// 供上层监督：pump 死亡意味着数据面已停（socket 回收/链路断），会话应视为
// 失效并触发重建——设备实测 ESP read 错误退出后无任何日志，上层 store 的
// active 标记永真，目标态 reconcile 永不触发，VoWiFi 静默死亡。
func (s *TUNPacketTunnelSession) PumpDone() <-chan struct{} {
	if s == nil || s.pump == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return s.pump.Done()
}

// PumpErr 返回 pump 退出原因（PumpDone 关闭后有效；正常关闭返回 nil）。
// 注意 Wait 会阻塞到 pump 结束，只应在 PumpDone 触发后调用。
func (s *TUNPacketTunnelSession) PumpErr() error {
	if s == nil || s.pump == nil {
		return nil
	}
	select {
	case <-s.pump.Done():
		_, err := s.pump.Wait()
		return err
	default:
		return nil // pump 仍在运行
	}
}

func (s *TUNPacketTunnelSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if s == nil || s.base == nil {
		return MOBIKEResult{}, ErrInvalidTUNTunnelManager
	}
	res, err := s.base.MOBIKE(ctx, req)
	if err != nil {
		return MOBIKEResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if res.LocalInnerIP != "" {
		s.result.LocalInnerIP = res.LocalInnerIP
	}
	if res.RemoteInnerIP != "" {
		s.result.RemoteInnerIP = res.RemoteInnerIP
	}
	if len(res.DNSServers) > 0 {
		s.result.DNSServers = append([]string(nil), res.DNSServers...)
	}
	if res.IKEEstablished || res.IPsecEstablished {
		s.result.IKEEstablished = res.IKEEstablished
		s.result.IPsecEstablished = res.IPsecEstablished
		s.result.Ready = res.IKEEstablished && res.IPsecEstablished
	}
	if res.Reason != "" {
		s.result.Reason = res.Reason
	}
	return res, nil
}

func (s *TUNPacketTunnelSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pump := s.pump
	routing := s.routing
	routingState := s.routingState
	routingApplied := s.routingApplied
	s.mu.Unlock()

	var err error
	if pump != nil {
		err = pump.Close(ctx)
	}
	if routingApplied && routing != nil {
		err = errors.Join(err, routing.Cleanup(ctx, routingState))
	}
	return err
}

func completeTUNResult(result TunnelResult) TunnelResult {
	if result.Mode == "" {
		result.Mode = DataplaneModeUserspace
	}
	if result.Reason == "" {
		result.Reason = "tun packet pump ready"
	}
	return result
}

func innerPacketDeviceName(device InnerPacketDevice) string {
	named, ok := device.(interface{ Name() string })
	if !ok || named == nil {
		return ""
	}
	return strings.TrimSpace(named.Name())
}

func closeInnerPacketDevice(ctx context.Context, device InnerPacketDevice) error {
	if closer, ok := device.(InnerPacketDeviceCloser); ok {
		return closer.Close(ctx)
	}
	return nil
}

func cloneEPDGRouteExclusions(in []EPDGRouteExclusion) []EPDGRouteExclusion {
	out := make([]EPDGRouteExclusion, len(in))
	for i, item := range in {
		out[i] = item
		out[i].Tables = append([]string(nil), item.Tables...)
	}
	return out
}

func cloneTUNRoutes(in []TUNRoute) []TUNRoute {
	out := make([]TUNRoute, len(in))
	copy(out, in)
	return out
}

func cloneTUNRules(in []TUNRule) []TUNRule {
	out := make([]TUNRule, len(in))
	copy(out, in)
	return out
}

// defaultRouteInterface 返回默认路由的出站网络接口名（如 wlan0）。
func defaultRouteInterface() string {
	// /proc/net/route 列序：Iface Destination Gateway Flags RefCnt Use Metric Mask ...
	// 默认路由 = Destination 00000000 且 Gateway 非 00000000（Flags 在第 4 列）。
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		if flagsHasGateway(fields[3]) || fields[2] != "00000000" {
			return fields[0]
		}
	}
	return ""
}

func flagsHasGateway(flagsHex string) bool {
	flags, err := strconv.ParseUint(flagsHex, 16, 32)
	if err != nil {
		return false
	}
	return flags&0x2 != 0
}
