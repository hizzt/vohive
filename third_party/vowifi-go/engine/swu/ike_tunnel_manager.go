package swu

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

var ErrInvalidIKETunnelManager = errors.New("invalid swu ike tunnel manager")

// socks5ProxyEnabled 判断隧道配置是否需要走 SOCKS5 前置代理（否则直连 ePDG）。
func socks5ProxyEnabled(p *ProxyConfig) bool {
	return p != nil && p.Enabled && strings.TrimSpace(p.Addr) != ""
}

type IKEInitRunner func(context.Context, ikev2.InitConfig) (ikev2.InitResult, error)

type IKEAuthRunner func(context.Context, ikev2.FullAuthConfig) (ikev2.FullAuthResult, error)

type IKEPacketSessionFactory func(PacketSessionConfig) (TunnelSession, error)

type IKETransportFactory func(TunnelConfig, IKETransportConfig) (ikev2.InitTransport, error)

type IKEESPTransportFactory func(TunnelConfig, ESPTransportConfig) (ESPPacketTransport, error)

type IKETransportConfig struct {
	EPDGAddress     string
	RemoteAddr      string
	RemoteAddrs     []string
	LocalAddr       string
	LocalIP         net.IP
	RemoteIP        net.IP
	LocalPort       uint16
	RemotePort      uint16
	Timeout         time.Duration
	UseNonESPMarker bool
}

type ESPTransportConfig struct {
	EPDGAddress string
	RemoteAddr  string
	RemoteAddrs []string
	LocalAddr   string
	Timeout     time.Duration
}

type IKEPacketTunnelManagerConfig struct {
	Transport                ikev2.InitTransport
	ESPTransport             ESPPacketTransport
	SIM                      sim.AKAProvider
	Random                   io.Reader
	Timeout                  time.Duration
	LocalIP                  net.IP
	RemoteIP                 net.IP
	LocalPort                uint16
	RemotePort               uint16
	UseNonESPMarker          bool
	EAPIdentity              string
	Reauthentication         EAPReauthenticationState
	OnReauthenticationState  func(EAPReauthenticationState)
	InitiatorID              ikev2.Identity
	IKETransportFactory      IKETransportFactory
	ESPTransportFactory      IKEESPTransportFactory
	InitRunner               IKEInitRunner
	AuthRunner               IKEAuthRunner
	PacketSessionFactory     IKEPacketSessionFactory
	SA                       ikev2.SecurityAssociation
	ChildSA                  ikev2.SecurityAssociation
	ChildSPI                 []byte
	TSi                      ikev2.TrafficSelectors
	TSr                      ikev2.TrafficSelectors
	Configuration            ikev2.Configuration
	AdditionalAddresses      []net.IP
	NoAdditionalAddresses    bool
	DisableControlPlaneHooks bool
}

type IKEPacketTunnelManager struct {
	Config IKEPacketTunnelManagerConfig

	// socks5Transport 在 EstablishTunnel 期间为 IKE 与 ESP 共享的 SOCKS5
	// UDP Associate 传输层（配置了前置代理时创建，一次隧道建立只建一个会话）。
	socks5Transport *Socks5UDPTransport
}

type IKETunnelManagerConfig = IKEPacketTunnelManagerConfig

type IKETunnelManager = IKEPacketTunnelManager

var _ TunnelManager = (*IKEPacketTunnelManager)(nil)

func NewIKEPacketTunnelManager(cfg IKEPacketTunnelManagerConfig) *IKEPacketTunnelManager {
	return &IKEPacketTunnelManager{Config: cfg}
}

func NewIKETunnelManager(cfg IKETunnelManagerConfig) *IKETunnelManager {
	return NewIKEPacketTunnelManager(cfg)
}

func (m *IKEPacketTunnelManager) EstablishTunnel(ctx context.Context, cfg TunnelConfig) (TunnelSession, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: manager is nil", ErrInvalidIKETunnelManager)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	mode := cfg.NormalizedMode()
	if mode == DataplaneModeDisabled {
		return nil, fmt.Errorf("%w: dataplane mode is disabled", ErrInvalidTunnelConfig)
	}
	if mode != DataplaneModeUserspace {
		return nil, fmt.Errorf("%w: unsupported dataplane mode %q", ErrInvalidTunnelConfig, mode)
	}
	provider := m.Config.SIM
	if provider == nil {
		return nil, fmt.Errorf("%w: SIM AKA provider is nil", ErrInvalidIKETunnelManager)
	}
	epdg := epdgAddressForTunnel(cfg)
	if epdg == "" {
		return nil, fmt.Errorf("%w: ePDG address is empty", ErrInvalidTunnelConfig)
	}
	identity, err := eapIdentityForTunnel(cfg, m.Config.EAPIdentity)
	if err != nil {
		return nil, err
	}
	initiatorID := m.Config.InitiatorID
	if initiatorID.Type == 0 {
		initiatorID = ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte(identity)}
	}
	random := m.Config.Random
	if random == nil {
		random = rand.Reader
	}
	transportCfg, espCfg := m.transportConfigs(cfg, epdg)
	transport, err := m.ikeTransport(cfg, transportCfg)
	if err != nil {
		return nil, err
	}
childSPI, err := m.childSPI(random)
	if err != nil {
		return nil, err
	}
	sa := m.Config.SA
	if len(sa.Proposals) == 0 {
		sa = ikeProposalForCarrier(m.carrierProfile(cfg))
	}
	initRunner := m.Config.InitRunner
	if initRunner == nil {
		initRunner = ikev2.RunIKE_SA_INIT
	}
	init, err := m.runIKEInitWithProfile(ctx, initRunner, transport, transportCfg, random, sa, m.carrierProfile(cfg))
	if err != nil {
		return nil, err
	}
	if init.NATDetected {
		prof := m.carrierProfile(cfg)
		if prof.Transport.EffectivePrefer4500OnNATOnly() {
			if natt, ok := transport.(interface{ SwitchToNATT() }); ok {
				fmt.Fprintf(os.Stderr, "[swu] NAT detected, switching to 4500 (profile %s)\n", prof.PresetID)
				natt.SwitchToNATT()
			} else {
				fmt.Fprintf(os.Stderr, "[swu] NAT detected but transport does not support SwitchToNATT\n")
			}
		}
	}
	authRunner := m.Config.AuthRunner
	if authRunner == nil {
		authRunner = ikev2.RunIKE_AUTH_Full
	}
	reauth := m.Config.Reauthentication.clone()
	if !reauth.Usable() {
		reauth = EAPReauthenticationState{}
	}
	childSA := m.Config.ChildSA
	if len(childSA.Proposals) == 0 {
		childSA = espProposalForCarrier(m.carrierProfile(cfg), childSPI)
	}
	tsi := m.Config.TSi
	if len(tsi.Selectors) == 0 {
		tsi = ikev2.IPv4AnyTrafficSelectors()
	}
	tsr := m.Config.TSr
	if len(tsr.Selectors) == 0 {
		tsr = ikev2.IPv4AnyTrafficSelectors()
	}
	cfgCP := m.Config.Configuration
	if len(cfgCP.Attributes) == 0 {
		cfgCP = ikev2.SWuConfigurationRequest()
		if m.carrierProfile(cfg).Transport.EffectiveRequestPCSCF() {
			cfgCP.Attributes = append(cfgCP.Attributes,
				ikev2.ConfigurationAttribute{Type: ikev2.ConfigInternalIPv4Pcscf},
				ikev2.ConfigurationAttribute{Type: ikev2.ConfigInternalIPv6Pcscf},
			)
		}
	}
	auth, err := authRunner(ctx, ikev2.FullAuthConfig{
		Transport:          transport,
		Init:               init,
		Keys:               init.Keys,
		SIM:                provider,
		EAPKeys:            reauth.Keys,
		InitiatorID:        initiatorID,
		EAPIdentity:        identity,
		EAPReauthIdentity:  reauth.Identity,
		EAPReauthCounter:   reauth.Counter,
		EAPReauthCounterOK: reauth.CounterOK,
		ChildSA:            childSA,
		ChildSPI:           childSPI,
		TSi:                tsi,
		TSr:                tsr,
		Configuration:      cfgCP,
		Random:             random,
	})
	if err != nil {
		return nil, err
	}
	if auth.ChildSA == nil {
		return nil, fmt.Errorf("%w: IKE_AUTH completed without CHILD_SA", ErrTunnelNotReady)
	}
	child := *auth.ChildSA
	m.updateReauthenticationState(auth)
	espTransport, err := m.espTransport(cfg, espCfg)
	if err != nil {
		return nil, err
	}
	result := tunnelResultFromIKE(cfg, epdg, init, child)
	closeHandler, mobikeHandler := m.controlHandlers(transport, init, auth, child, result, transportCfg)
	sessionFactory := m.Config.PacketSessionFactory
	if sessionFactory == nil {
		sessionFactory = func(pc PacketSessionConfig) (TunnelSession, error) {
			return NewPacketSession(pc)
		}
	}
	session, err := sessionFactory(PacketSessionConfig{
		Result:        result,
		ChildSA:       child,
		Transport:     espTransport,
		Random:        random,
		MOBIKEHandler: mobikeHandler,
		CloseHandler:  closeHandler,
	})
	if err != nil {
		if closer, ok := espTransport.(ESPPacketTransportCloser); ok {
			_ = closer.Close(ctx)
		}
		return nil, err
	}
	if session == nil {
		if closer, ok := espTransport.(ESPPacketTransportCloser); ok {
			_ = closer.Close(ctx)
		}
		return nil, fmt.Errorf("%w: packet session factory returned nil", ErrInvalidIKETunnelManager)
	}
	return session, nil
}

func (m *IKEPacketTunnelManager) carrierProfile(cfg TunnelConfig) carrier.EffectiveCarrierConfig {
	mcc, mnc := tunnelMCCMNC(cfg)
	return carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{MCC: mcc, MNC: mnc})
}

func ikeProposalForCarrier(prof carrier.EffectiveCarrierConfig) ikev2.SecurityAssociation {
	switch prof.IKE.ProposalSet {
	case "curve25519-single":
		return ikev2.DefaultIKEProposal()
	case "modp-mixed":
		return ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{
			{Number: 1, ProtocolID: ikev2.ProtocolIKE, Transforms: []ikev2.Transform{
				{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
				{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256},
				{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128},
				{Type: ikev2.TransformDHRGroup, ID: ikev2.DHGroup2048BitMODP},
			}},
			{Number: 2, ProtocolID: ikev2.ProtocolIKE, Transforms: []ikev2.Transform{
				{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
				{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256},
				{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128},
				{Type: ikev2.TransformDHRGroup, ID: ikev2.DHGroupCurve25519},
			}},
		}}
	default:
		return comprehensiveIKEProposal()
	}
}

func (m *IKEPacketTunnelManager) runIKEInitWithDHFallback(
	ctx context.Context,
	initRunner IKEInitRunner,
	transport ikev2.InitTransport,
	transportCfg IKETransportConfig,
	random io.Reader,
	sa ikev2.SecurityAssociation,
) (ikev2.InitResult, error) {
	return m.runIKEInitWithProfile(ctx, initRunner, transport, transportCfg, random, sa, m.carrierProfile(TunnelConfig{}))
}

func (m *IKEPacketTunnelManager) runIKEInitWithProfile(
	ctx context.Context,
	initRunner IKEInitRunner,
	transport ikev2.InitTransport,
	transportCfg IKETransportConfig,
	random io.Reader,
	sa ikev2.SecurityAssociation,
	prof carrier.EffectiveCarrierConfig,
) (ikev2.InitResult, error) {
	dhGroups := prof.IKE.DHGroups
	if len(dhGroups) == 0 {
		dhGroups = []uint16{ikev2.DHGroup2048BitMODP, ikev2.DHGroup1024BitMODP}
	}
	type dhAttempt struct {
		group uint16
		name  string
	}
	attempts := make([]dhAttempt, 0, len(dhGroups))
	for _, g := range dhGroups {
		attempts = append(attempts, dhAttempt{group: g, name: dhGroupName(g)})
	}

	var lastErr error
	for _, a := range attempts {
		filtered := filterProposalsByDHGroup(sa, a.group)
		if len(filtered.Proposals) == 0 {
			lastErr = fmt.Errorf("no proposals match DH group %d", a.group)
			continue
		}
		result, err := initRunner(ctx, ikev2.InitConfig{
				Transport: transport,
				Random:     random,
				SA:         filtered,
				DHGroup:    a.group,
				LocalIP:    transportCfg.LocalIP,
				LocalPort:  transportCfg.LocalPort,
				RemoteIP:   transportCfg.RemoteIP,
				RemotePort: transportCfg.RemotePort,
			})
			if err == nil {
				fmt.Fprintf(os.Stderr, "[swu] IKE_SA_INIT succeeded with DH group %s\n", a.name)
				return result, nil
			}
			lastErr = err
			if sg, ok, _ := ikev2.InvalidKEPayloadAlternativeGroupFromError(err); ok {
				fmt.Fprintf(os.Stderr, "[swu] ePDG suggested DH group %s (%d), will prefer it if available\n", dhGroupName(sg), sg)
			}
			if isIKEInitRetryableErrorForProfile(err, prof) {
				fmt.Fprintf(os.Stderr, "[swu] IKE_SA_INIT DH group %s failed (%v), retrying next group\n", a.name, err)
				continue
			}
			return ikev2.InitResult{}, err
	}
	return ikev2.InitResult{}, lastErr
}

// isIKEInitRetryableError 判断 IKE_SA_INIT 错误是否应降级重试。
// ePDG 可能拒绝 KE group（INVALID_KE_PAYLOAD）或直接超时，都应换 group 尝试。
func isIKEInitRetryableError(err error) bool {
	return isIKEInitRetryableErrorForProfile(err, carrier.EffectiveCarrierConfig{IKE: carrier.CarrierIKEProfile{RetryOnTimeout: func() *bool { b := true; return &b }()}})
}

func isIKEInitRetryableErrorForProfile(err error, prof carrier.EffectiveCarrierConfig) bool {
	if errors.Is(err, ikev2.ErrInvalidKEPayload) || errors.Is(err, ikev2.ErrNotifyInvalidKEPayload) {
		return true
	}
	if _, ok, _ := ikev2.InvalidKEPayloadAlternativeGroupFromError(err); ok {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return prof.IKE.EffectiveRetryOnTimeout()
	}
	return false
}

// filterProposalsByDHGroup 从 SA 中过滤出匹配指定 DH group 的提议。
// 每个 proposal 的 Transforms 中必须包含 TransformDHRGroup 且 ID 匹配 dhGroup。
func filterProposalsByDHGroup(sa ikev2.SecurityAssociation, dhGroup uint16) ikev2.SecurityAssociation {
	var filtered []ikev2.Proposal
	for _, p := range sa.Proposals {
		matched := false
		for _, t := range p.Transforms {
			if t.Type == ikev2.TransformDHRGroup && t.ID == dhGroup {
				matched = true
				break
			}
		}
		if matched {
			filtered = append(filtered, p)
		}
	}
	return ikev2.SecurityAssociation{Proposals: filtered}
}

func (m *IKEPacketTunnelManager) updateReauthenticationState(auth ikev2.FullAuthResult) {
	if m == nil || len(auth.EAPKeys.KAut) == 0 || len(auth.EAPKeys.KEncr) == 0 {
		return
	}
	current := m.Config.Reauthentication.clone()
	next := current
	if strings.TrimSpace(auth.EAPNextReauthID) != "" {
		next.Identity = strings.TrimSpace(auth.EAPNextReauthID)
	}
	if strings.TrimSpace(auth.EAPNextPseudonym) != "" {
		next.NextPseudonym = strings.TrimSpace(auth.EAPNextPseudonym)
	}
	if strings.TrimSpace(next.Identity) == "" {
		return
	}
	next.Keys = cloneEAPAKAKeys(auth.EAPKeys)
	next.Reauthenticated = auth.EAPReauthenticated
	next.CounterTooSmall = auth.EAPReauthCounterTooSmall
	switch {
	case auth.EAPReauthenticated:
		next.Counter = auth.EAPReauthCounter
		next.CounterOK = true
		next.LastAcceptedCounter = auth.EAPReauthCounter
	case auth.EAPReauthCounterTooSmall:
		next.CounterOK = current.CounterOK
		next.LastRejectedCounter = auth.EAPReauthCounter
	default:
		next.Counter = 0
		next.CounterOK = true
		next.LastAcceptedCounter = 0
		next.LastRejectedCounter = 0
	}
	next = next.clone()
	m.Config.Reauthentication = next
	if m.Config.OnReauthenticationState != nil {
		m.Config.OnReauthenticationState(next.clone())
	}
}

func (m *IKEPacketTunnelManager) transportConfigs(cfg TunnelConfig, epdg string) (IKETransportConfig, ESPTransportConfig) {
	remotePort := m.Config.RemotePort
	if remotePort == 0 {
		remotePort = 500 // IKE 标准端口；NAT-T (4500) 在检测到 NAT 后切换
	}
	localPort := m.Config.LocalPort
	if localPort == 0 {
		localPort = 500 // IKE 标准端口；NAT-D 载荷需要非零端口
	}
	localIP := normalizedMOBIKEIP(m.Config.LocalIP, cfg.OuterLocalIP)
	remoteIP := normalizedMOBIKEIP(m.Config.RemoteIP, tunnelAddressHost(epdg))
	// 若未配置本端 IP，选取默认路由接口的 IP（NAT 检测载荷需要 4 元组均有效才会生成）
	if localIP == nil {
		localIP = defaultLocalIP()
	}
// 当 ePDG 是域名时，在本地解析到 IP 再传递给传输层（SOCKS5 代理的 DNS 可能无法解析 3gppnetwork.org 域）
	// 同时收集所有 A 记录，SOCKS5 传输层会依次尝试。
	var remoteAddrs []string
	if net.ParseIP(tunnelAddressHost(epdg)) == nil {
		if ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), tunnelAddressHost(epdg)); err == nil && len(ips) > 0 {
			remoteAddrs = make([]string, 0, len(ips))
			for _, ip := range ips {
				if ip.IP != nil {
					remoteAddrs = append(remoteAddrs, tunnelUDPAddr(ip.IP.String(), remotePort))
				}
			}
			epdg = ips[0].IP.String()
			remoteIP = normalizedMOBIKEIP(nil, epdg)
		}
	}
	remoteAddr := tunnelUDPAddr(epdg, remotePort)
	// 如果解析出了多个 IP 且 remoteAddr 不在列表中，补上
	if remoteAddrs == nil {
		remoteAddrs = []string{remoteAddr}
	} else if len(remoteAddrs) > 0 && remoteAddrs[0] != remoteAddr {
		remoteAddrs = append([]string{remoteAddr}, remoteAddrs...)
	}
	localAddr := ""
	if local := firstPacketNonEmpty(cfg.OuterLocalIP); local != "" {
		localAddr = tunnelUDPAddr(local, localPort)
	}
	timeout := m.Config.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	useMarker := m.Config.UseNonESPMarker
	if !useMarker {
		useMarker = remotePort == 4500
	}
ikeCfg := IKETransportConfig{
			EPDGAddress:     epdg,
			RemoteAddr:      remoteAddr,
			RemoteAddrs:     remoteAddrs,
			LocalAddr:       localAddr,
			LocalIP:         localIP,
			RemoteIP:        remoteIP,
			LocalPort:       localPort,
			RemotePort:      remotePort,
			Timeout:         timeout,
			UseNonESPMarker: useMarker,
		}
		espCfg := ESPTransportConfig{
			EPDGAddress: epdg,
			RemoteAddr:  remoteAddr,
			RemoteAddrs: remoteAddrs,
			LocalAddr:   localAddr,
			Timeout:     timeout,
		}
	return ikeCfg, espCfg
}

func (m *IKEPacketTunnelManager) ikeTransport(cfg TunnelConfig, transportCfg IKETransportConfig) (ikev2.InitTransport, error) {
	if m.Config.Transport != nil {
		return m.Config.Transport, nil
	}
	if m.Config.IKETransportFactory != nil {
		return m.Config.IKETransportFactory(cfg, transportCfg)
	}
	if m.socks5Transport != nil || socks5ProxyEnabled(cfg.Proxy) {
		prof := m.carrierProfile(cfg)
		if m.socks5Transport == nil {
			m.socks5Transport = NewSocks5UDPTransport(
				*cfg.Proxy, transportCfg.RemoteAddrs, transportCfg.LocalAddr, transportCfg.Timeout,
			)
		}
		m.socks5Transport.SetKeepControlAlive(prof.Transport.EffectiveKeepSOCKSControlAlive())
		return m.socks5Transport, nil
	}
	return ikev2.UDPTransport{
		RemoteAddr:      transportCfg.RemoteAddr,
		LocalAddr:       transportCfg.LocalAddr,
		Timeout:         transportCfg.Timeout,
		UseNonESPMarker: transportCfg.UseNonESPMarker,
	}, nil
}

func (m *IKEPacketTunnelManager) espTransport(cfg TunnelConfig, transportCfg ESPTransportConfig) (ESPPacketTransport, error) {
	if m.Config.ESPTransport != nil {
		return m.Config.ESPTransport, nil
	}
	if m.Config.ESPTransportFactory != nil {
		return m.Config.ESPTransportFactory(cfg, transportCfg)
	}
	if m.socks5Transport != nil || socks5ProxyEnabled(cfg.Proxy) {
		prof := m.carrierProfile(cfg)
		if m.socks5Transport == nil {
			m.socks5Transport = NewSocks5UDPTransport(
				*cfg.Proxy, transportCfg.RemoteAddrs, transportCfg.LocalAddr, transportCfg.Timeout,
			)
		}
		m.socks5Transport.SetKeepControlAlive(prof.Transport.EffectiveKeepSOCKSControlAlive())
		return m.socks5Transport, nil
	}
	return &UDPESPPacketTransport{
		RemoteAddr: transportCfg.RemoteAddr,
		LocalAddr:  transportCfg.LocalAddr,
		Timeout:    transportCfg.Timeout,
	}, nil
}

func (m *IKEPacketTunnelManager) childSPI(random io.Reader) ([]byte, error) {
	if len(m.Config.ChildSPI) > 0 {
		if len(m.Config.ChildSPI) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidIKETunnelManager, len(m.Config.ChildSPI))
		}
		return append([]byte(nil), m.Config.ChildSPI...), nil
	}
	spi := make([]byte, 4)
	if _, err := io.ReadFull(random, spi); err != nil {
		return nil, err
	}
	if spi[0] == 0 && spi[1] == 0 && spi[2] == 0 && spi[3] == 0 {
		spi[3] = 1
	}
	return spi, nil
}

func (m *IKEPacketTunnelManager) controlHandlers(transport ikev2.InitTransport, init ikev2.InitResult, auth ikev2.FullAuthResult, child ikev2.ChildSAResult, result TunnelResult, transportCfg IKETransportConfig) (func(context.Context) error, func(context.Context, MOBIKERequest) (MOBIKEResult, error)) {
	if m.Config.DisableControlPlaneHooks || auth.NextMessageID == 0 || !ikeKeysUsable(init.Keys) {
		return nil, nil
	}
	control := &ikePacketTunnelControl{
		transport:             transport,
		init:                  init,
		keys:                  init.Keys,
		child:                 child,
		nextMessageID:         auth.NextMessageID,
		result:                result,
		localIP:               transportCfg.LocalIP,
		remoteIP:              transportCfg.RemoteIP,
		localPort:             transportCfg.LocalPort,
		remotePort:            transportCfg.RemotePort,
		additionalAddresses:   cloneIPs(m.Config.AdditionalAddresses),
		noAdditionalAddresses: m.Config.NoAdditionalAddresses,
		random:                m.Config.Random,
	}
	closeHandler := control.close
	var mobikeHandler func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	if init.MOBIKESupported {
		mobikeHandler = control.mobike
	}
	return closeHandler, mobikeHandler
}

type ikePacketTunnelControl struct {
	mu                    sync.Mutex
	transport             ikev2.InitTransport
	init                  ikev2.InitResult
	keys                  ikev2.IKEKeys
	child                 ikev2.ChildSAResult
	nextMessageID         uint32
	result                TunnelResult
	localIP               net.IP
	remoteIP              net.IP
	localPort             uint16
	remotePort            uint16
	additionalAddresses   []net.IP
	noAdditionalAddresses bool
	random                io.Reader
}

func (c *ikePacketTunnelControl) close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	messageID := c.nextMessageID
	c.nextMessageID++
	c.mu.Unlock()
	payloads, err := ikev2.TeardownDeletePayloads(c.child, true)
	if err != nil {
		return err
	}
	_, err = ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
		Transport: c.transport,
		Init:      c.init,
		Keys:      c.keys,
		MessageID: messageID,
		Payloads:  payloads,
		Random:    c.random,
	})
	return err
}

func (c *ikePacketTunnelControl) mobike(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if c == nil {
		return MOBIKEResult{}, ErrInvalidIKEControl
	}
	c.mu.Lock()
	messageID := c.nextMessageID
	c.nextMessageID++
	c.mu.Unlock()
	payloads, err := mobikeUpdatePayloads(IKEMOBIKEConfig{
		Init:                  c.init,
		Result:                c.result,
		LocalIP:               c.localIP,
		RemoteIP:              c.remoteIP,
		LocalPort:             c.localPort,
		RemotePort:            c.remotePort,
		AdditionalAddresses:   c.additionalAddresses,
		NoAdditionalAddresses: c.noAdditionalAddresses,
	}, c.additionalAddresses, req)
	if err != nil {
		return MOBIKEResult{}, err
	}
	res, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
		Transport: c.transport,
		Init:      c.init,
		Keys:      c.keys,
		MessageID: messageID,
		Payloads:  payloads,
		Random:    c.random,
	})
	if err != nil {
		return MOBIKEResult{}, err
	}
	if err := rejectMOBIKEResponse(res.ResponseInner); err != nil {
		return MOBIKEResult{}, err
	}
	return MOBIKEResult{
		Rekeyed:          false,
		OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, c.result.EPDGAddress),
		LocalInnerIP:     c.result.LocalInnerIP,
		RemoteInnerIP:    c.result.RemoteInnerIP,
		IKEEstablished:   true,
		IPsecEstablished: true,
		Reason:           "mobike update sa addresses sent",
		UpdatedAt:        time.Now(),
	}, nil
}

func tunnelResultFromIKE(cfg TunnelConfig, epdg string, init ikev2.InitResult, child ikev2.ChildSAResult) TunnelResult {
	return TunnelResult{
		Ready:             true,
		Mode:              DataplaneModeUserspace,
		EPDGAddress:       epdg,
		LocalInnerIP:      firstPacketNonEmpty(cfg.InnerLocalIP, childConfigurationAddress(child, ikev2.ConfigInternalIPv4Address), childConfigurationAddress(child, ikev2.ConfigInternalIPv6Address)),
		RemoteInnerIP:     strings.TrimSpace(cfg.RemoteInnerIP),
		DNSServers:        childConfigurationDNS(child),
		IKEEstablished:    true,
		IPsecEstablished:  true,
		MOBIKESupported:   init.MOBIKESupported,
		ChildSAIdentifier: childSAIdentifier(child),
		Reason:            "ike ipsec tunnel ready",
		EstablishedAt:     time.Now(),
	}
}

func childConfigurationAddress(child ikev2.ChildSAResult, attrType uint16) string {
	values := childConfigurationIPStrings(child, attrType)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func childConfigurationDNS(child ikev2.ChildSAResult) []string {
	return append(childConfigurationIPStrings(child, ikev2.ConfigInternalIPv4DNS), childConfigurationIPStrings(child, ikev2.ConfigInternalIPv6DNS)...)
}

func childConfigurationIPStrings(child ikev2.ChildSAResult, attrType uint16) []string {
	if child.Configuration == nil {
		return nil
	}
	width := 0
	switch attrType {
	case ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv4DNS:
		width = net.IPv4len
	case ikev2.ConfigInternalIPv6Address, ikev2.ConfigInternalIPv6DNS:
		width = net.IPv6len
	default:
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, attr := range child.Configuration.Attributes {
		if attr.Type != attrType {
			continue
		}
		for value := attr.Value; len(value) >= width; value = value[width:] {
			ip := net.IP(value[:width]).String()
			if ip != "" && !seen[ip] {
				out = append(out, ip)
				seen[ip] = true
			}
		}
	}
	return out
}

func childSAIdentifier(child ikev2.ChildSAResult) string {
	local := hex.EncodeToString(child.LocalSPI)
	remote := hex.EncodeToString(child.RemoteSPI)
	switch {
	case local != "" && remote != "":
		return local + "/" + remote
	case local != "":
		return local
	default:
		return remote
	}
}

func epdgAddressForTunnel(cfg TunnelConfig) string {
	if epdg := strings.TrimSpace(cfg.EPDGAddress); epdg != "" {
		return epdg
	}
	mcc, mnc := tunnelMCCMNC(cfg)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", leftPadTunnel(mnc, 3), mcc)
}

func eapIdentityForTunnel(cfg TunnelConfig, override string) (string, error) {
	raw := firstPacketNonEmpty(override, cfg.Identity.IMPI, cfg.IMSI, cfg.Identity.IMPU)
	if raw == "" {
		return "", fmt.Errorf("%w: EAP identity is empty", ErrInvalidTunnelConfig)
	}
	raw = normalizeTunnelIdentity(raw)
	if strings.Contains(raw, "@") {
		return raw, nil
	}
	mcc, mnc := tunnelMCCMNC(cfg)
	if mcc == "" || mnc == "" {
		return "", fmt.Errorf("%w: MCC/MNC is required for IMSI-derived EAP identity", ErrInvalidTunnelConfig)
	}
	prefix := ""
	if isDecimalString(raw) {
		prefix = "0"
	}
	return fmt.Sprintf("%s%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", prefix, raw, leftPadTunnel(mnc, 3), mcc), nil
}

func normalizeTunnelIdentity(identity string) string {
	identity = strings.TrimSpace(identity)
	identity = strings.Trim(identity, "<>")
	if strings.HasPrefix(strings.ToLower(identity), "sip:") {
		identity = identity[4:]
	}
	if semi := strings.IndexByte(identity, ';'); semi >= 0 {
		identity = identity[:semi]
	}
	return strings.TrimSpace(identity)
}

func tunnelMCCMNC(cfg TunnelConfig) (string, string) {
	mcc := strings.TrimSpace(cfg.MCC)
	mnc := strings.TrimSpace(cfg.MNC)
	imsi := strings.TrimSpace(cfg.IMSI)
	if mcc == "" && len(imsi) >= 3 {
		mcc = imsi[:3]
	}
	if mnc == "" && len(imsi) >= 6 {
		mnc = imsi[3:6]
	}
	return mcc, mnc
}

func tunnelUDPAddr(addr string, port uint16) string {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), strconv.Itoa(int(port)))
}

func tunnelAddressHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

func leftPadTunnel(value string, width int) string {
	value = strings.TrimSpace(value)
	for len(value) < width {
		value = "0" + value
	}
	return value
}

func isDecimalString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ikeKeysUsable(keys ikev2.IKEKeys) bool {
	p := keys.Profile
	return p.RequiredLength() > 0 &&
		len(keys.SKD) >= p.PRFKeyLength &&
		len(keys.SKAi) >= p.IntegrityKeyLength &&
		len(keys.SKAr) >= p.IntegrityKeyLength &&
		len(keys.SKEi) >= p.EncryptionKeyLength &&
		len(keys.SKEr) >= p.EncryptionKeyLength &&
		len(keys.SKPi) >= p.PRFKeyLength &&
		len(keys.SKPr) >= p.PRFKeyLength
}

// comprehensiveIKEProposal 返回包含多个提议的 IKE SA，匹配旧二进制 swu/session.go 的配置。
// 从旧二进制抓包逐字节验证：4 个提议的 transform 必须完全一致，
// 否则 ePDG 可能静默丢弃 IKE_SA_INIT（不回 NO_PROPOSAL_CHOSEN）。
func dhGroupName(g uint16) string {
	switch g {
	case ikev2.DHGroupCurve25519:
		return "Curve25519"
	case ikev2.DHGroup2048BitMODP:
		return "MODP 2048"
	case ikev2.DHGroup1024BitMODP:
		return "MODP 1024"
	default:
		return fmt.Sprintf("DH-%d", g)
	}
}

func espProposalForCarrier(prof carrier.EffectiveCarrierConfig, spi []byte) ikev2.SecurityAssociation {
	switch prof.IKE.ProposalSet {
	case "curve25519-single":
		return ikev2.DefaultESPProposal(spi)
	default:
		return ikev2.ComprehensiveESPProposal(spi)
	}
}

func comprehensiveIKEProposal() ikev2.SecurityAssociation {
	prop := func(num uint8, dhGroup uint16) ikev2.Proposal {
		encr := ikev2.Transform{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC,
			Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}}
		integ := ikev2.Transform{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128}
		prf := ikev2.Transform{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256}
		dh := ikev2.Transform{Type: ikev2.TransformDHRGroup, ID: dhGroup}
		// 顺序必须匹配旧二进制：ENCR → INTEG → PRF → DH
		return ikev2.Proposal{Number: num, ProtocolID: ikev2.ProtocolIKE, Transforms: []ikev2.Transform{encr, integ, prf, dh}}
	}
	// 旧二进制 Proposal 2/3/4 的 DHR 值为 0x0002（MODP 1024, Oakley Group 2），
	// 而不是我们之前用的 Curve25519(31)/ECP256(19)/MODP2048(14)。
	propGroup2 := func(num uint8, sha1 bool) ikev2.Proposal {
		encr := ikev2.Transform{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC,
			Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}}
		integ := ikev2.Transform{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128}
		prf := ikev2.Transform{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256}
		if sha1 {
			integ = ikev2.Transform{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA1_96}
			prf = ikev2.Transform{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA1}
		}
		dh := ikev2.Transform{Type: ikev2.TransformDHRGroup, ID: 2} // MODP 1024 (Group 2)
		return ikev2.Proposal{Number: num, ProtocolID: ikev2.ProtocolIKE, Transforms: []ikev2.Transform{encr, integ, prf, dh}}
	}
	propAES256SHA1Group2 := func(num uint8) ikev2.Proposal {
		encr := ikev2.Transform{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC,
			Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(256)}}
		integ := ikev2.Transform{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA1_96}
		prf := ikev2.Transform{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA1}
		dh := ikev2.Transform{Type: ikev2.TransformDHRGroup, ID: 2} // MODP 1024 (Group 2)
		return ikev2.Proposal{Number: num, ProtocolID: ikev2.ProtocolIKE, Transforms: []ikev2.Transform{encr, integ, prf, dh}}
	}
	return ikev2.SecurityAssociation{Proposals: []ikev2.Proposal{
		prop(1, ikev2.DHGroup2048BitMODP),        // Proposal 1: AES-128+SHA256+MODP 2048 (匹配 KE)
		propGroup2(2, false),                      // Proposal 2: AES-128+SHA256+MODP 1024
		propGroup2(3, true),                       // Proposal 3: AES-128+SHA1+MODP 1024
		propAES256SHA1Group2(4),                   // Proposal 4: AES-256+SHA1+MODP 1024
	}}
}

// defaultLocalIP 返回默认路由接口的 IPv4 地址，用于 IKE 的 NAT 检测载荷。
func defaultLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.To4()
		}
	}
	return nil
}
