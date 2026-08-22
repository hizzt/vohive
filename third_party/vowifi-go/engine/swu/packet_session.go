package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/esp"
	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

var (
	ErrInvalidPacketTunnel    = errors.New("invalid swu packet tunnel")
	ErrPacketTunnelClosed     = errors.New("swu packet tunnel closed")
	ErrUnsupportedInnerPacket = errors.New("unsupported inner packet")
)

type ESPPacketTransport interface {
	SendESPPacket(context.Context, []byte) error
}

type ESPPacketReceiver interface {
	ReadESPPacket(context.Context) ([]byte, error)
}

type ESPPacketReadWriteTransport interface {
	ESPPacketTransport
	ESPPacketReceiver
}

type ESPPacketTransportFunc func(context.Context, []byte) error

func (f ESPPacketTransportFunc) SendESPPacket(ctx context.Context, packet []byte) error {
	if f == nil {
		return fmt.Errorf("%w: transport is nil", ErrInvalidPacketTunnel)
	}
	return f(ctx, packet)
}

type ESPPacketTransportCloser interface {
	ESPPacketTransport
	Close(context.Context) error
}

type PacketTunnelStats struct {
	OutboundInnerPackets uint64
	OutboundInnerBytes   uint64
	OutboundESPPackets   uint64
	OutboundESPBytes     uint64
	OutboundErrors       uint64
	InboundInnerPackets  uint64
	InboundInnerBytes    uint64
	InboundESPPackets    uint64
	InboundESPBytes      uint64
	InboundErrors        uint64
	ReplayDrops          uint64
	InvalidDrops         uint64
	UnsupportedDrops     uint64
}

type PacketTunnelPacket struct {
	SPI        uint32
	Sequence   uint32
	NextHeader uint8
	Payload    []byte
}

type PacketTunnelSession interface {
	TunnelSession
	SendInnerPacket(context.Context, []byte) error
	SendInnerPacketWithNextHeader(context.Context, uint8, []byte) error
	ReceiveESPPacket(context.Context, []byte) (PacketTunnelPacket, error)
	PacketStats() PacketTunnelStats
}

type PacketTunnelReadSession interface {
	PacketTunnelSession
	ReadInnerPacket(context.Context) (PacketTunnelPacket, error)
}

type PacketSessionConfig struct {
	Result        TunnelResult
	ChildSA       ikev2.ChildSAResult
	OutboundSA    *esp.SA
	InboundSA     *esp.SA
	Transport     ESPPacketTransport
	Random        io.Reader
	MOBIKEHandler func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	CloseHandler  func(context.Context) error
	// LivenessHandler 是 DPD 探测（INFORMATIONAL 空交换）。设置后
	// StartLivenessLoop 在空闲期周期探测对端存活，探测失败即关闭会话触发重建。
	LivenessHandler func(context.Context) error
	// IKEResponder 应答 ePDG 主动发起的 INFORMATIONAL（DPD 探测/DELETE/
	// DEVICE_IDENTITY 请求）。nil = 无应答方能力（旧行为：请求被丢弃，
	// ePDG 在空闲 ~40s 后拆 SA）。设置后 ReadInnerPacket 对入站 IKE 报文
	// 先经应答方分发，同时刷新 lastInbound（对端有控制流量即存活）。
	IKEResponder *IKEResponder
}

// livenessProbeInterval 是 DPD 探测间隔；livenessProbeTimeout 是单次探测超时。
// 间隔取 20s：伦敦 SOCKS5 代理对 UDP relay 的下行转发在无双向流约 60-90s
// 后静默回收（设备 tcpdump 实证：出站 keepalive 正常、入站先停），周期
// DPD 的请求-响应是双向流，可刷新 relay 生命周期。60s 间隔时探测发出前
// relay 已死，DPD 必超时 → 会话每 ~105s 重建一次；20s 时 DPD 自身成为
// 维持流。对齐 1.5.5 的周期 SIP 事务（~45s 双向）+ keepalive(20s) 存活模式。
// livenessMaxProbeFailures 是连续探测失败判死阈值：单次失败即拆链会被
// 代理偶发丢包误杀（对齐 Python 参考 DPD 4 次重试的容错语义）。
const (
	livenessProbeInterval    = 20 * time.Second
	livenessProbeTimeout     = 90 * time.Second
	livenessMaxProbeFailures = 3
)

type PacketSession struct {
	mu              sync.Mutex
	result          TunnelResult
	outbound        *esp.SA
	inbound         *esp.SA
	transport       ESPPacketTransport
	random          io.Reader
	mobikeHandler   func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	closeHandler    func(context.Context) error
	livenessHandler func(context.Context) error
	ikeResponder    *IKEResponder
	lastInbound     time.Time // 最近一次收到对端下行流量/keepalive 的时间（有流量跳过 DPD）
	livenessCancel  context.CancelFunc
	stats           PacketTunnelStats
	closed          bool
}

var (
	_ PacketTunnelSession     = (*PacketSession)(nil)
	_ PacketTunnelReadSession = (*PacketSession)(nil)
)

func NewPacketSession(cfg PacketSessionConfig) (*PacketSession, error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidPacketTunnel)
	}
	outbound, inbound, err := packetSAs(cfg)
	if err != nil {
		return nil, err
	}
	result := cfg.Result
	if isZeroTunnelResult(result) {
		result.Ready = true
		result.IKEEstablished = true
		result.IPsecEstablished = true
	}
	if result.Mode == "" {
		result.Mode = DataplaneModeUserspace
	}
	if result.Reason == "" {
		result.Reason = "packet tunnel ready"
	}
	if result.EstablishedAt.IsZero() {
		result.EstablishedAt = time.Now()
	}
	return &PacketSession{
		result:          result,
		outbound:        outbound,
		inbound:         inbound,
		transport:       cfg.Transport,
		random:          cfg.Random,
		mobikeHandler:   cfg.MOBIKEHandler,
		closeHandler:    cfg.CloseHandler,
		livenessHandler: cfg.LivenessHandler,
		ikeResponder:    cfg.IKEResponder,
		lastInbound:     time.Now(),
	}, nil
}

// StartLivenessLoop 启动 DPD 探测循环：每个探测周期检查最近下行时间，
// 超过一个周期无下行流量才发 INFORMATIONAL 空交换探测（有流量即视为活，
// 避免给 ePDG 加压）。探测失败（对端死亡/链路断）即关闭会话，让上层重建。
func (s *PacketSession) StartLivenessLoop(ctx context.Context) {
	if s == nil || s.livenessHandler == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.closed || s.livenessCancel != nil {
		s.mu.Unlock()
		cancel()
		return
	}
	s.livenessCancel = cancel
	_ = s.livenessHandler // 保活探测改为 ESP 层 ICMP echo，IKE DPD handler 不再使用
	s.mu.Unlock()

	go func() {
		defer cancel()
		ticker := time.NewTicker(livenessProbeInterval)
		defer ticker.Stop()
		consecutiveFailures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				idle := time.Since(s.lastInbound)
				closed := s.closed
				s.mu.Unlock()
				if closed || idle < livenessProbeInterval {
					consecutiveFailures = 0 // 有下行流量（含对端 keepalive）即视为对端存活
					continue
				}
				// 保活探测改为 ESP 层：向隧道对端内网关发 ICMP echo（经 ESP
				// 加密），对端必回 ESP——这是双向 ESP 流量，ePDG/代理链路都
				// 按 ESP 流维持。设备实测（112+伦敦 SOCKS5）：IKE INFORMATIONAL
				// 空探测在会话空闲 ~40s 后被 ePDG 无视（1.5.5 同代理 0.2s 秒回
				// 是因为它有周期 SIP 事务持续维持 ESP 流），而 ESP 层探测在
				// REGISTER 期间始终秒回。echo 无响应累计连续 3 次才判定链路死
				// （单次失败即拆链会被代理偶发丢包误杀健康会话）。
				probeCtx, probeCancel := context.WithTimeout(ctx, livenessProbeTimeout)
				err := s.probeESPKeepalive(probeCtx)
				probeCancel()
				if err == nil {
					consecutiveFailures = 0
					continue
				}
				consecutiveFailures++
				fmt.Fprintf(os.Stderr, "[swu] ESP keepalive probe failed (%v), consecutive=%d/%d\n", err, consecutiveFailures, livenessMaxProbeFailures)
				if consecutiveFailures < livenessMaxProbeFailures {
					continue
				}
				fmt.Fprintf(os.Stderr, "[swu] ESP keepalive probe failed %d times, closing session for re-establishment\n", consecutiveFailures)
				_ = s.Close(context.Background())
				return
			}
		}
	}()
}

// probeESPKeepalive 发一个内层 ICMP echo 并等待响应（任意下行 ESP 包即可，
// 响应会刷新 lastInbound，ReadESPPacket 的读循环自然收到）。
func (s *PacketSession) probeESPKeepalive(ctx context.Context) error {
	if s == nil {
		return ErrInvalidPacketTunnel
	}
	s.mu.Lock()
	closed := s.closed
	gateway := s.result.RemoteInnerIP
	local := s.result.LocalInnerIP
	dns := ""
	if len(s.result.DNSServers) > 0 {
		dns = s.result.DNSServers[0]
	}
	s.mu.Unlock()
	if closed {
		return ErrPacketTunnelClosed
	}
	// 探测目标优先 DNS 服务器（必答查询），其次对端网关 ICMP echo。
	// 设备实测：运营商网关对 ICMP echo 不应答，DNS 服务器对查询必答。
	dst := net.ParseIP(strings.TrimSpace(dns))
	useDNS := dst != nil
	if !useDNS {
		dst = net.ParseIP(strings.TrimSpace(gateway))
	}
	if dst == nil {
		// 无可用探测目标：退化为 NAT-T keepalive（单向，仅保 NAT 映射）
		return s.sendNATTKeepaliveOnly(ctx)
	}
	src := net.ParseIP(strings.TrimSpace(local))
	if src == nil {
		return fmt.Errorf("%w: local inner ip invalid", ErrInvalidPacketTunnel)
	}
	var payload []byte
	if useDNS {
		payload = buildDNSProbeQuery()
	} else {
		echo, err := buildICMPv4EchoRequest(espKeepaliveProbeID, espKeepaliveProbeSeq)
		espKeepaliveProbeSeq++
		if err != nil {
			return err
		}
		payload = echo
	}
	proto := byte(1) // ICMP
	if useDNS {
		proto = 17 // UDP
	}
	inner, err := buildIPv4Packet(src, dst, proto, payload)
	if err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if err := s.SendInnerPacket(ctx, inner); err != nil {
		return err
	}
	// 等待响应：任意下行流量刷新 lastInbound 即视为活
	deadline := time.Now().Add(livenessProbeTimeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.Lock()
		lastInbound := s.lastInbound
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return ErrPacketTunnelClosed
		}
		if time.Since(lastInbound) < livenessProbeInterval {
			return nil // 收到了下行（echo 应答或其他下行包）
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("%w: no inbound after %v", ErrInvalidPacketTunnel, livenessProbeTimeout)
}

// sendNATTKeepaliveOnly 无对端内网地址时的降级保活。
func (s *PacketSession) sendNATTKeepaliveOnly(ctx context.Context) error {
	s.mu.Lock()
	transport := s.transport
	s.mu.Unlock()
	sender, ok := transport.(ESPPacketTransport)
	if !ok {
		return fmt.Errorf("%w: transport cannot send", ErrInvalidPacketTunnel)
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	return sender.SendESPPacket(ctx, []byte{0xff})
}

var espKeepaliveProbeID uint16 = 0x7654
var espKeepaliveProbeSeq uint32 = 1

func NextHeaderForInnerPacket(packet []byte) (uint8, error) {
	if len(packet) == 0 {
		return 0, fmt.Errorf("%w: packet is empty", ErrUnsupportedInnerPacket)
	}
	switch packet[0] >> 4 {
	case 4:
		return esp.NextHeaderIPv4, nil
	case 6:
		return esp.NextHeaderIPv6, nil
	default:
		return 0, fmt.Errorf("%w: ip version %d", ErrUnsupportedInnerPacket, packet[0]>>4)
	}
}

func (s *PacketSession) Result() TunnelResult {
	if s == nil {
		return TunnelResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTunnelResult(s.result)
}

func (s *PacketSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if s == nil {
		return MOBIKEResult{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return MOBIKEResult{}, err
	}
	s.mu.Lock()
	closed := s.closed
	handler := s.mobikeHandler
	result := s.result
	s.mu.Unlock()
	if closed {
		return MOBIKEResult{}, ErrPacketTunnelClosed
	}
	if handler != nil {
		res, err := handler(ctx, req)
		if err != nil {
			return MOBIKEResult{}, err
		}
		res = completeMOBIKEResult(res, req, result, "mobike updated")
		s.applyMOBIKEResult(res)
		return res, nil
	}
	return MOBIKEResult{
		Rekeyed:          false,
		OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, result.EPDGAddress),
		LocalInnerIP:     result.LocalInnerIP,
		RemoteInnerIP:    result.RemoteInnerIP,
		DNSServers:       append([]string(nil), result.DNSServers...),
		IKEEstablished:   result.IKEEstablished,
		IPsecEstablished: result.IPsecEstablished,
		Reason:           "mobike unsupported",
		UpdatedAt:        time.Now(),
	}, nil
}

func completeMOBIKEResult(res MOBIKEResult, req MOBIKERequest, current TunnelResult, fallbackReason string) MOBIKEResult {
	if res.OuterLocalIP == "" {
		res.OuterLocalIP = firstPacketNonEmpty(req.NewIP, req.OldIP, current.EPDGAddress)
	}
	if res.LocalInnerIP == "" {
		res.LocalInnerIP = current.LocalInnerIP
	}
	if res.RemoteInnerIP == "" {
		res.RemoteInnerIP = current.RemoteInnerIP
	}
	if len(res.DNSServers) == 0 {
		res.DNSServers = append([]string(nil), current.DNSServers...)
	} else {
		res.DNSServers = append([]string(nil), res.DNSServers...)
	}
	if !res.IKEEstablished {
		res.IKEEstablished = current.IKEEstablished
	}
	if !res.IPsecEstablished {
		res.IPsecEstablished = current.IPsecEstablished
	}
	if res.Reason == "" {
		res.Reason = fallbackReason
	}
	if res.UpdatedAt.IsZero() {
		res.UpdatedAt = time.Now()
	}
	return res
}

func (s *PacketSession) applyMOBIKEResult(res MOBIKEResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.result.LocalInnerIP = res.LocalInnerIP
	s.result.RemoteInnerIP = res.RemoteInnerIP
	s.result.DNSServers = append([]string(nil), res.DNSServers...)
	s.result.IKEEstablished = res.IKEEstablished
	s.result.IPsecEstablished = res.IPsecEstablished
	s.result.Ready = res.IKEEstablished && res.IPsecEstablished
	if res.Reason != "" {
		s.result.Reason = res.Reason
	}
}

func (s *PacketSession) Close(ctx context.Context) error {
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
	handler := s.closeHandler
	transport := s.transport
	responder := s.ikeResponder
	if s.livenessCancel != nil {
		s.livenessCancel()
		s.livenessCancel = nil
	}
	s.mu.Unlock()
	if responder != nil {
		responder.Close()
	}
	var err error
	if handler != nil {
		err = handler(ctx)
	}
	if closer, ok := transport.(ESPPacketTransportCloser); ok {
		if closeErr := closer.Close(ctx); err == nil {
			err = closeErr
		}
	}
	return err
}

func (s *PacketSession) SendInnerPacket(ctx context.Context, inner []byte) error {
	nextHeader, err := NextHeaderForInnerPacket(inner)
	if err != nil {
		if s != nil {
			s.recordOutboundError(true)
		}
		return err
	}
	return s.SendInnerPacketWithNextHeader(ctx, nextHeader, inner)
}

func (s *PacketSession) SendInnerPacketWithNextHeader(ctx context.Context, nextHeader uint8, inner []byte) error {
	if s == nil {
		return ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordOutboundError(false)
		return err
	}
	innerCopy := append([]byte(nil), inner...)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrPacketTunnelClosed
	}
	if s.outbound == nil || s.transport == nil {
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return fmt.Errorf("%w: outbound sa or transport is nil", ErrInvalidPacketTunnel)
	}
	packet, err := s.outbound.Seal(nextHeader, innerCopy, esp.SealOptions{Random: s.random})
	transport := s.transport
	if err != nil {
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if err := transport.SendESPPacket(ctx, packet); err != nil {
		s.recordOutboundError(false)
		return err
	}
	s.mu.Lock()
	s.stats.OutboundInnerPackets++
	s.stats.OutboundInnerBytes += uint64(len(innerCopy))
	s.stats.OutboundESPPackets++
	s.stats.OutboundESPBytes += uint64(len(packet))
	s.mu.Unlock()
	return nil
}

func (s *PacketSession) ReceiveESPPacket(ctx context.Context, packet []byte) (PacketTunnelPacket, error) {
	if s == nil {
		return PacketTunnelPacket{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	packetCopy := append([]byte(nil), packet...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return PacketTunnelPacket{}, ErrPacketTunnelClosed
	}
	if s.inbound == nil {
		s.stats.InboundErrors++
		return PacketTunnelPacket{}, fmt.Errorf("%w: inbound sa is nil", ErrInvalidPacketTunnel)
	}
	out, err := s.inbound.Open(packetCopy)
	if err != nil {
		s.recordInboundErrorLocked(err)
		return PacketTunnelPacket{}, err
	}
	payload := append([]byte(nil), out.Payload...)
	s.stats.InboundInnerPackets++
	s.stats.InboundInnerBytes += uint64(len(payload))
	s.stats.InboundESPPackets++
	s.stats.InboundESPBytes += uint64(len(packetCopy))
	return PacketTunnelPacket{
		SPI:        out.SPI,
		Sequence:   out.Sequence,
		NextHeader: out.NextHeader,
		Payload:    payload,
	}, nil
}

func (s *PacketSession) ReadInnerPacket(ctx context.Context) (PacketTunnelPacket, error) {
	if s == nil {
		return PacketTunnelPacket{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return PacketTunnelPacket{}, ErrPacketTunnelClosed
	}
	receiver, ok := s.transport.(ESPPacketReceiver)
	s.mu.Unlock()
	if !ok {
		err := fmt.Errorf("%w: transport cannot read ESP packets", ErrInvalidPacketTunnel)
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	packet, err := receiver.ReadESPPacket(ctx)
	if err != nil {
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	s.mu.Lock()
	s.lastInbound = time.Now() // 有下行流量即对端存活，DPD 循环据此跳过探测
	responder := s.ikeResponder
	s.mu.Unlock()
	// 入站 IKE 报文（ePDG 主动的 INFORMATIONAL：DPD 探测/DELETE/DEVICE_IDENTITY）
	// 与 ESP 混流在同一 socket 到达，先经应答方分发——应答方消费的报文
	// （已回响应或属迟到响应）不进 ESP 解密路径。纯发起方时代这些请求
	// 被静默丢弃，ePDG DPD 无应答 ~40s 后拆 SA（5min 重建循环的根因）。
	if responder != nil && looksLikeIKE(packet) {
		if responder.HandleInbound(ctx, packet) {
			return s.ReadInnerPacket(ctx) // 继续读下一包（应答已由 responder 发出）
		}
	}
	out, openErr := s.ReceiveESPPacket(ctx, packet)
	if openErr != nil && errors.Is(openErr, esp.ErrInvalidPacket) && isSPIMismatchError(openErr) {
		// SPI 不匹配的 ESP 包是旧 SA 迟到流量/混流（设备实测 `spi 00000000`
		// 单包曾把健康会话连着 pump 一起杀掉触发重建），丢弃继续读下一包。
		return s.ReadInnerPacket(ctx)
	}
	return out, openErr
}

// isSPIMismatchError 判断 ESP Open 错误是否为 SPI 不匹配（可丢弃的混流包）。
// esp.SA.Open 对 SPI 不匹配报 "spi %08x != %08x"，其余（too short/icv/seq）
// 是真实损坏，交给上层按会话错误处理。
func isSPIMismatchError(err error) bool {
	return err != nil && strings.Contains(err.Error(), ": spi ")
}

func (s *PacketSession) PacketStats() PacketTunnelStats {
	if s == nil {
		return PacketTunnelStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *PacketSession) recordOutboundError(unsupported bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.OutboundErrors++
	if unsupported {
		s.stats.UnsupportedDrops++
	}
}

func (s *PacketSession) recordInboundError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordInboundErrorLocked(err)
}

func (s *PacketSession) recordInboundErrorLocked(err error) {
	s.stats.InboundErrors++
	switch {
	case errors.Is(err, esp.ErrReplay):
		s.stats.ReplayDrops++
	case errors.Is(err, esp.ErrInvalidPacket):
		s.stats.InvalidDrops++
	case errors.Is(err, ErrUnsupportedInnerPacket):
		s.stats.UnsupportedDrops++
	}
}

func packetSAs(cfg PacketSessionConfig) (*esp.SA, *esp.SA, error) {
	outbound := cfg.OutboundSA
	inbound := cfg.InboundSA
	if outbound == nil || inbound == nil {
		if !hasChildSA(cfg.ChildSA) {
			return nil, nil, fmt.Errorf("%w: child sa is empty", ErrInvalidPacketTunnel)
		}
		if outbound == nil {
			var err error
			outbound, err = esp.NewOutboundSAFromChild(cfg.ChildSA)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: outbound: %v", ErrInvalidPacketTunnel, err)
			}
		}
		if inbound == nil {
			var err error
			inbound, err = esp.NewInboundSAFromChild(cfg.ChildSA)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: inbound: %v", ErrInvalidPacketTunnel, err)
			}
		}
	}
	outbound, err := cloneSA(outbound)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: outbound: %v", ErrInvalidPacketTunnel, err)
	}
	inbound, err = cloneSA(inbound)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: inbound: %v", ErrInvalidPacketTunnel, err)
	}
	return outbound, inbound, nil
}

func hasChildSA(child ikev2.ChildSAResult) bool {
	return len(child.LocalSPI) > 0 || len(child.RemoteSPI) > 0 ||
		len(child.Keys.Outbound.EncryptionKey) > 0 || len(child.Keys.Inbound.EncryptionKey) > 0
}

func cloneSA(sa *esp.SA) (*esp.SA, error) {
	if sa == nil {
		return nil, ErrInvalidPacketTunnel
	}
	cp := *sa
	cp.EncryptionKey = append([]byte(nil), sa.EncryptionKey...)
	cp.IntegrityKey = append([]byte(nil), sa.IntegrityKey...)
	return esp.NewSA(cp)
}

func contextReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func firstPacketNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

// buildICMPv4EchoRequest 构造 8B ICMP echo request 头（校验和为 0，
// 大多数实现接受；对端为运营商网关，echo 必答）。
func buildICMPv4EchoRequest(id uint16, seq uint32) ([]byte, error) {
	out := make([]byte, 8)
	out[0] = 8 // echo request
	out[1] = 0
	binary.BigEndian.PutUint16(out[4:6], id)
	binary.BigEndian.PutUint16(out[6:8], uint16(seq))
	return out, nil
}

// buildIPv4Packet 构造最小 IPv4 头 + payload（proto 为 IP 协议号，TTL 64）。
func buildIPv4Packet(src, dst net.IP, proto byte, payload []byte) ([]byte, error) {
	if src == nil || dst == nil {
		return nil, fmt.Errorf("%w: nil ip", ErrUnsupportedInnerPacket)
	}
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return nil, fmt.Errorf("%w: inner ips must be ipv4", ErrUnsupportedInnerPacket)
	}
	totalLen := 20 + len(payload)
	out := make([]byte, 20, totalLen)
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	out[4], out[5], out[6], out[7] = 0, 0, 0, 0
	out[8] = 64 // TTL
	out[9] = proto
	copy(out[12:16], src4)
	copy(out[16:20], dst4)
	out = append(out, payload...)
	return out, nil
}

// buildDNSProbeQuery 构造最小 UDP+DNS A 查询（查询 '.' NS 记录无需真实域名，
// DNS 服务器必答；UDP 头 8B + DNS 头 12B + 问题 17B）。
func buildDNSProbeQuery() []byte {
	// UDP 头：源端口 43761，目的端口 53，长度，校验和 0（运营商网关普遍接受）
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 43761)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	// DNS 查询: root NS 查询 id=0x7654
	q := []byte{
		0x76, 0x54, 0x01, 0x00, // id, flags=recursion
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qdcount=1
		0x00,                   // root label
		0x00, 0x02, 0x00, 0x01, // type NS, class IN
	}
	body := append(udp, q...)
	binary.BigEndian.PutUint16(body[4:6], uint16(len(body)))
	return body
}
