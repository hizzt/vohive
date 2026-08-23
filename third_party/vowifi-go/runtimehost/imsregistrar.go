package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/imsipsec"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

type IMSRegisterTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, string, string) voiceclient.SIPRegisterTransport
type IMSVoiceTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding) voiceclient.SIPRequestTransport
type IMSSMSTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.SMSTransport
type IMSUSSDTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.USSDTransport

type WireIMSRegistrar struct {
	Transport        voiceclient.SIPRegisterTransport
	TransportFactory IMSRegisterTransportFactory
	VoiceTransport   voiceclient.SIPRequestTransport
	VoiceFactory     IMSVoiceTransportFactory
	SMSTransport     messaging.SMSTransport
	SMSFactory       IMSSMSTransportFactory
	USSDTransport    messaging.USSDTransport
	USSDFactory      IMSUSSDTransportFactory
	RegistrarURI     string
	ContactURI       string
	ContactHost      string
	ContactPort      int
	Network          string
	ServerAddr       string
	LocalAddr        string
	Resolver         voiceclient.SIPServerResolver
	Timeout          time.Duration
	// SecurityPortC 覆盖 Security-Client 头的 port-c（默认 5062）。
	// 与 SIP 实际监听端口保持一致，>0 时生效。
	SecurityPortC int
	// IPsecTransform 非 nil 时在 AKA 成功回调里 Install IMS ipsec-3gpp ESP
	// 策略（Security-Client/Server 机制对 + CK/IK → port-c↔port-s 选择器）。
	IPsecTransform *imsipsec.Transform
	// SecurityPortS 覆盖 Security-Client 头的 port-s（默认 5063）。Vodafone UK
	// P-CSCF 对 5060 段未保护端口敏感（实测 400 Bad Request），对齐 mdd/1239t
	// 用随机高段（40000-44999）。
	SecurityPortS          int
	Expires               int
	DisableRefresh        bool
	RefreshInterval       time.Duration
	RefreshLead           time.Duration
	RefreshRetryInterval  time.Duration
	DisableKeepalive      bool
	KeepaliveInterval     time.Duration
	UserAgent             string
	CallID                string
	CNonce                string
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int
}

func (r WireIMSRegistrar) RegisterIMS(ctx context.Context, cfg IMSRegistrationConfig) (IMSRegistrationResult, error) {
	profile, err := r.profileFromConfig(cfg)
	if err != nil {
		return IMSRegistrationResult{}, err
	}
	registrarURI := firstRuntimeNonEmpty(r.RegistrarURI, registrarURIForProfile(profile))
	if registrarURI == "" {
		return IMSRegistrationResult{}, errors.New("IMS registrar URI is empty")
	}
	contactURI := firstRuntimeNonEmpty(r.ContactURI, r.contactURIForProfile(profile))
	if contactURI == "" {
		return IMSRegistrationResult{}, errors.New("IMS contact URI is empty")
	}
	transport := r.Transport
	var defaultFlow *voiceclient.WireSIPFlow
	if transport == nil && r.TransportFactory != nil {
		transport = r.TransportFactory(cfg, profile, registrarURI, contactURI)
	}
	if transport == nil {
		defaultFlow = r.defaultSIPFlow(cfg)
		transport = defaultFlow
	}
	expires := r.Expires
	if expires <= 0 {
		expires = 3600
	}
	registerSession := voiceclient.RegisterSession{
		Transport:    transport,
		AKAProvider:  cfg.SIM,
		Profile:      profile,
		RegistrarURI: registrarURI,
		ContactURI:   contactURI,
		// 1239t/v155 Call-ID = 纯 UUID（uuid.NewString）；trace 前缀是私有格式，
		// 部分 S-CSCF 对非常规 Call-ID 直接 403。
		CallID:       firstRuntimeNonEmpty(r.CallID, newSIPCallID(), cfg.TraceID),
		CNonce:       firstRuntimeNonEmpty(r.CNonce, cfg.TraceID, cfg.DeviceID),
		Expires:      expires,
	}
	// Route 头指向 P-CSCF（参考实现 imscore default profile 含 Route <sip:P-CSCF;lr>；
	// v155 反编译同样存在 "<sip:%s:%d;lr>" 模板）。无 ISIM 时 P-CSCF 只按 Route 寻路。
	if serverAddr := strings.TrimSpace(r.ServerAddr); serverAddr != "" {
		registerSession.RouteURI = "sip:" + serverAddr + ";lr"
	}
	// 首个 REGISTER 带 aka_empty 占位 Authorization（imscore default 变体先例）：
	// Vodafone UK P-CSCF 对无 Authorization 的首 REGISTER 回 400。
	registerSession.InitialAuthorization = "aka_empty"
	// Security-Client 的 port-c 与实际 SIP socket 端口保持一致：部分运营商
	// P-CSCF 会把响应发往宣告的保护端口，口径不一致时响应全部落空。
	// port-s 同步覆盖（默认 5063 落在 P-CSCF 敏感段，实测 400）。
	if r.SecurityPortC > 0 {
		agreement := voiceclient.DefaultSecurityClientAgreement(nil)
		agreement.PortClient = r.SecurityPortC
		if r.SecurityPortS > 0 {
			agreement.PortServer = r.SecurityPortS
		}
		registerSession.SecurityClient = agreement
	}
	if r.IPsecTransform != nil {
		// TS 33.203 ipsec-3gpp：AKA 成功后用 CK/IK + Security-Client/Server
		// 机制对在 tun pump 上 Install ESP transform，受保护 REGISTER/后续
		// SIP 走 port-c↔port-s 的二层加密（明文 CSeq3 实测被 P-CSCF 拒 401）。
		transform := r.IPsecTransform
		localIP := net.ParseIP(strings.TrimSpace(profile.LocalIP))
		remoteIP := ipFromHostPort(r.ServerAddr)
		if localIP != nil && remoteIP != nil {
			registerSession.OnSecurityKeys = func(client, server voiceclient.SecurityAgreement, ck, ik []byte) {
				policy, err := imsipsec.NewPolicy(imsipsec.PolicyInput{
					LocalIP:    localIP,
					RemoteIP:   remoteIP,
					ClientMech: securityAgreementMechanism(client),
					ServerMech: securityAgreementMechanism(server),
					CK:         ck,
					IK:         ik,
				})
				if err != nil {
					fmt.Printf("[imsipsec] policy construct failed: %v\n", err)
					return
				}
				// 重注册/重协商时旧 SA 立即作废：先 Clear 再 Install（P-CSCF 每
				// 次安全协商换全套 SPI，残留旧 SA 会吞掉新入向包判 replay）。
				transform.Clear()
				if err := transform.Install(policy); err != nil {
					fmt.Printf("[imsipsec] install failed: %v\n", err)
					return
				}
				fmt.Printf("[imsipsec] ESP installed: local=%s remote=%s port-c=%d port-s=%d spi-c=%d spi-s=%d alg=%s/%s\n",
					localIP, remoteIP, client.PortClient, server.PortServer, client.SPIClient, client.SPIServer,
					server.Algorithm, server.EncryptionAlgorithm)
			}
		}
	}
	result, err := registerSession.Register(ctx)
	if err != nil {
		if defaultFlow != nil {
			_ = defaultFlow.Close()
		}
		return IMSRegistrationResult{
			Registered: result.Registered,
			StatusCode: result.StatusCode,
			Reason:     result.Reason,
			Server:     result.Binding.PublicIdentity,
			Profile:    profile,
			Binding:    result.Binding,
		}, err
	}
	voiceTransport := r.voiceTransport(cfg, profile, result.Binding, defaultFlow)
	smsTransport := r.smsTransport(cfg, profile, result.Binding, voiceTransport)
	ussdTransport := r.ussdTransport(cfg, profile, result.Binding, voiceTransport)
	maintenance := newIMSRegistrationMaintenance(defaultFlow, registerSession, result, r, cfg, profile)
	var closeRegistration func(context.Context) error
	var recoverRegistration func(context.Context) (IMSRegistrationResult, error)
	if maintenance != nil {
		closeRegistration = maintenance.Close
		recoverRegistration = maintenance.Recover
	}
	return IMSRegistrationResult{
		Registered:     result.Registered,
		StatusCode:     result.StatusCode,
		Reason:         firstRuntimeNonEmpty(result.Reason, "ims registered"),
		Server:         firstRuntimeNonEmpty(result.Binding.PublicIdentity, profile.Domain),
		Profile:        profile,
		Binding:        result.Binding,
		VoiceTransport: voiceTransport,
		SMSTransport:   smsTransport,
		USSDTransport:  ussdTransport,
		Close:          closeRegistration,
		Recover:        recoverRegistration,
	}, nil
}

// securityAgreementMechanism 把 voiceclient 的协商结构转成 imsipsec 机制。
func securityAgreementMechanism(a voiceclient.SecurityAgreement) imsipsec.Mechanism {
	return imsipsec.Mechanism{
		Alg:   a.Algorithm,
		EAlg:  a.EncryptionAlgorithm,
		Prot:  a.Prot,
		Mode:  a.Mod,
		SPIc:  a.SPIClient,
		SPIs:  a.SPIServer,
		PortC: a.PortClient,
		PortS: a.PortServer,
	}
}

func ipFromHostPort(hostPort string) net.IP {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	return net.ParseIP(host)
}

func (r WireIMSRegistrar) voiceTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, fallback voiceclient.SIPRequestTransport) voiceclient.SIPRequestTransport {
	if r.VoiceTransport != nil {
		return r.VoiceTransport
	}
	if r.VoiceFactory != nil {
		return r.VoiceFactory(cfg, profile, binding)
	}
	if fallback != nil {
		return fallback
	}
	return voiceclient.WireSIPTransport{
		Network:               r.Network,
		ServerAddr:            r.ServerAddr,
		LocalAddr:             r.LocalAddr,
		Resolver:              r.resolverForConfig(cfg),
		Timeout:               r.Timeout,
		RetransmitInterval:    r.RetransmitInterval,
		MaxRetransmitInterval: r.MaxRetransmitInterval,
		MaxRetransmits:        r.MaxRetransmits,
	}
}

func (r WireIMSRegistrar) defaultSIPFlow(cfg IMSRegistrationConfig) *voiceclient.WireSIPFlow {
	return &voiceclient.WireSIPFlow{
		Network:               r.Network,
		ServerAddr:            r.ServerAddr,
		LocalAddr:             r.LocalAddr,
		Resolver:              r.resolverForConfig(cfg),
		Timeout:               r.Timeout,
		RetransmitInterval:    r.RetransmitInterval,
		MaxRetransmitInterval: r.MaxRetransmitInterval,
		MaxRetransmits:        r.MaxRetransmits,
	}
}

func (r WireIMSRegistrar) resolverForConfig(cfg IMSRegistrationConfig) voiceclient.SIPServerResolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	if len(cfg.Tunnel.DNSServers) == 0 {
		return nil
	}
	return voiceclient.NetSIPResolver{
		DNSServers: append([]string(nil), cfg.Tunnel.DNSServers...),
		Timeout:    r.Timeout,
	}
}

type imsRegistrationMaintenance struct {
	flow          *voiceclient.WireSIPFlow
	session       voiceclient.RegisterSession
	config        WireIMSRegistrar
	runtimeConfig IMSRegistrationConfig
	profile       voiceclient.IMSProfile

	recoverMu      sync.Mutex
	mu             sync.Mutex
	registered     bool
	statusCode     int
	reason         string
	binding        voiceclient.RegistrationBinding
	nextCSeq       int
	authHeader     string
	authHeaderName string
	authState      voiceclient.DigestAuthState
	recoveryCount  int
	cancel         context.CancelFunc
	done           chan struct{}
	wg             sync.WaitGroup
	closed         bool
}

func newIMSRegistrationMaintenance(flow *voiceclient.WireSIPFlow, session voiceclient.RegisterSession, result voiceclient.RegisterResult, config WireIMSRegistrar, runtimeConfig IMSRegistrationConfig, profile voiceclient.IMSProfile) *imsRegistrationMaintenance {
	if flow == nil {
		return nil
	}
	nextCSeq := result.NextCSeq
	if nextCSeq <= 0 {
		nextCSeq = 1
	}
	m := &imsRegistrationMaintenance{
		flow:          flow,
		session:       session,
		config:        config,
		runtimeConfig: runtimeConfig,
		profile:       profile,

		registered:     result.Registered,
		statusCode:     result.StatusCode,
		reason:         result.Reason,
		binding:        result.Binding,
		nextCSeq:       nextCSeq,
		authHeader:     result.AuthHeader,
		authHeaderName: result.AuthHeaderName,
		authState:      result.AuthState,
	}
	if result.Registered && (!config.DisableRefresh || !config.DisableKeepalive) {
		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		m.done = make(chan struct{})
		if !config.DisableRefresh {
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				m.refreshLoop(ctx)
			}()
		}
		if !config.DisableKeepalive {
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				m.keepaliveLoop(ctx)
			}()
		}
		go func() {
			m.wg.Wait()
			close(m.done)
		}()
	}
	return m
}

func (m *imsRegistrationMaintenance) Recover(ctx context.Context) (IMSRegistrationResult, error) {
	if m == nil {
		return IMSRegistrationResult{}, errors.New("IMS registration maintenance unavailable")
	}
	if err := m.recoverRegistration(ctx, errors.New("requested IMS registration recovery")); err != nil {
		return IMSRegistrationResult{}, err
	}
	return m.result("IMS registration recovered"), nil
}

func (m *imsRegistrationMaintenance) result(defaultReason string) IMSRegistrationResult {
	if m == nil {
		return IMSRegistrationResult{}
	}
	m.mu.Lock()
	registered := m.registered
	statusCode := m.statusCode
	reason := m.reason
	binding := m.binding
	m.mu.Unlock()

	if statusCode == 0 && registered {
		statusCode = 200
	}
	voiceTransport := m.config.voiceTransport(m.runtimeConfig, m.profile, binding, m.flow)
	smsTransport := m.config.smsTransport(m.runtimeConfig, m.profile, binding, voiceTransport)
	ussdTransport := m.config.ussdTransport(m.runtimeConfig, m.profile, binding, voiceTransport)
	return IMSRegistrationResult{
		Registered:     registered,
		StatusCode:     statusCode,
		Reason:         firstRuntimeNonEmpty(reason, defaultReason),
		Server:         firstRuntimeNonEmpty(binding.PublicIdentity, m.profile.Domain),
		Profile:        m.profile,
		Binding:        binding,
		VoiceTransport: voiceTransport,
		SMSTransport:   smsTransport,
		USSDTransport:  ussdTransport,
		Close:          m.Close,
		Recover:        m.Recover,
	}
}

func (m *imsRegistrationMaintenance) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.cancel
	done := m.done
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.mu.Lock()
	registered := m.registered
	req := voiceclient.DeregisterRequest{
		Binding:        m.binding,
		CSeq:           m.nextCSeq,
		AuthHeader:     m.authHeader,
		AuthHeaderName: m.authHeaderName,
		AuthState:      m.authState,
	}
	m.registered = false
	m.mu.Unlock()

	var deregisterErr error
	if registered {
		_, deregisterErr = m.session.Deregister(ctx, req)
	}
	return errors.Join(deregisterErr, m.flow.Close())
}

func (m *imsRegistrationMaintenance) refreshLoop(ctx context.Context) {
	for {
		if !m.wait(ctx, m.refreshDelay()) {
			return
		}
		for {
			if err := m.refresh(ctx); err != nil {
				if !m.wait(ctx, m.refreshRetryInterval()) {
					return
				}
				continue
			}
			break
		}
	}
}

func (m *imsRegistrationMaintenance) keepaliveLoop(ctx context.Context) {
	for {
		if !m.wait(ctx, m.keepaliveInterval()) {
			return
		}
		if !m.isRegistered() {
			continue
		}
		if err := m.flow.SendCRLFKeepalive(ctx); err != nil {
			if ctx.Err() != nil || errors.Is(err, voiceclient.ErrSIPFlowClosed) {
				return
			}
			_ = m.recoverRegistration(ctx, err)
		}
	}
}

func (m *imsRegistrationMaintenance) wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *imsRegistrationMaintenance) refresh(ctx context.Context) error {
	m.mu.Lock()
	if !m.registered {
		m.mu.Unlock()
		return nil
	}
	req := voiceclient.RefreshRequest{
		Binding:        m.binding,
		CSeq:           m.nextCSeq,
		AuthHeader:     m.authHeader,
		AuthHeaderName: m.authHeaderName,
		AuthState:      m.authState,
	}
	m.mu.Unlock()

	result, err := m.session.Refresh(ctx, req)
	if err != nil {
		if m.shouldRecoverRegistration(result, err) {
			return m.recoverRegistration(ctx, err)
		}
		return err
	}
	m.mu.Lock()
	if result.Refreshed {
		m.registered = true
		m.statusCode = result.StatusCode
		m.reason = result.Reason
		m.binding = result.Binding
		m.nextCSeq = result.NextCSeq
		m.authHeader = result.AuthHeader
		m.authHeaderName = result.AuthHeaderName
		m.authState = result.AuthState
	}
	m.mu.Unlock()
	return nil
}

func (m *imsRegistrationMaintenance) recoverRegistration(ctx context.Context, cause error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.recoverMu.Lock()
	defer m.recoverMu.Unlock()

	m.mu.Lock()
	if m.closed || !m.registered {
		m.mu.Unlock()
		return nil
	}
	m.recoveryCount++
	session := m.session
	session.CallID = imsRecoveryCallID(session.CallID, m.recoveryCount)
	m.mu.Unlock()

	if err := m.flow.Reset(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("IMS registration recovery reset failed: %w", err)
	}
	result, err := session.Register(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("IMS registration recovery failed after %v: %w", cause, err)
	}
	if !result.Registered {
		m.mu.Lock()
		m.registered = false
		m.statusCode = result.StatusCode
		m.reason = result.Reason
		m.mu.Unlock()
		return fmt.Errorf("IMS registration recovery did not register: %d %s", result.StatusCode, result.Reason)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.session = session
	m.registered = true
	m.statusCode = result.StatusCode
	m.reason = result.Reason
	m.binding = result.Binding
	m.nextCSeq = result.NextCSeq
	m.authHeader = result.AuthHeader
	m.authHeaderName = result.AuthHeaderName
	m.authState = result.AuthState
	m.mu.Unlock()
	return nil
}

func (m *imsRegistrationMaintenance) shouldRecoverRegistration(result voiceclient.RefreshResult, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, voiceclient.ErrSIPFlowClosed) ||
		errors.Is(err, voiceclient.ErrInvalidChallenge) || errors.Is(err, voiceclient.ErrInvalidAuthenticationInfo) {
		return false
	}
	if errors.Is(err, voiceclient.ErrRegistrationRejected) {
		return isRecoverableIMSRegistrationStatus(result.StatusCode)
	}
	return true
}

func isRecoverableIMSRegistrationStatus(code int) bool {
	switch code {
	case 408, 430, 480, 481, 500, 502, 503, 504, 580:
		return true
	default:
		return code >= 500 && code < 600
	}
}

// newSIPCallID 生成 RFC 3261 Call-ID：UUID v4（对齐 1239t registerSession.callID = uuid.NewString()）。
func newSIPCallID() string {
	return voiceclient.NewSIPInstanceURN()
}

func imsRecoveryCallID(base string, n int) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "vowifi-go-register"
	}
	if n <= 0 {
		n = 1
	}
	return base + "-recovery-" + strconv.Itoa(n)
}

func (m *imsRegistrationMaintenance) isRegistered() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registered
}

func (m *imsRegistrationMaintenance) refreshDelay() time.Duration {
	if m.config.RefreshInterval > 0 {
		return m.config.RefreshInterval
	}
	m.mu.Lock()
	expires := m.binding.Expires
	m.mu.Unlock()
	if expires <= 0 {
		expires = m.session.Expires
	}
	if expires <= 0 {
		expires = 3600
	}
	ttl := time.Duration(expires) * time.Second
	lead := m.config.RefreshLead
	if lead <= 0 {
		lead = ttl / 10
		if lead < 5*time.Second {
			lead = 5 * time.Second
		}
		if lead > time.Minute {
			lead = time.Minute
		}
	}
	delay := ttl - lead
	if delay <= 0 {
		delay = ttl / 2
	}
	if delay <= 0 {
		delay = 30 * time.Second
	}
	return delay
}

func (m *imsRegistrationMaintenance) refreshRetryInterval() time.Duration {
	if m.config.RefreshRetryInterval > 0 {
		return m.config.RefreshRetryInterval
	}
	return 30 * time.Second
}

func (m *imsRegistrationMaintenance) keepaliveInterval() time.Duration {
	if m.config.KeepaliveInterval > 0 {
		return m.config.KeepaliveInterval
	}
	return 25 * time.Second
}

func (r WireIMSRegistrar) smsTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, voiceTransport voiceclient.SIPRequestTransport) messaging.SMSTransport {
	if r.SMSTransport != nil {
		return r.SMSTransport
	}
	if r.SMSFactory != nil {
		return r.SMSFactory(cfg, profile, binding, voiceTransport)
	}
	if voiceTransport == nil {
		return nil
	}
	return messaging.IMSSMSTransport{
		Transport:    voiceTransport,
		Profile:      profile,
		Registration: binding,
		Domain:       profile.Domain,
		UserAgent:    firstRuntimeNonEmpty(r.UserAgent, profile.UserAgent),
	}
}

func (r WireIMSRegistrar) ussdTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, voiceTransport voiceclient.SIPRequestTransport) messaging.USSDTransport {
	if r.USSDTransport != nil {
		return r.USSDTransport
	}
	if r.USSDFactory != nil {
		return r.USSDFactory(cfg, profile, binding, voiceTransport)
	}
	if voiceTransport == nil {
		return nil
	}
	return &messaging.IMSUSSDTransport{
		Transport:    voiceTransport,
		Profile:      profile,
		Registration: binding,
		Domain:       profile.Domain,
		UserAgent:    firstRuntimeNonEmpty(r.UserAgent, profile.UserAgent),
	}
}

func (r WireIMSRegistrar) profileFromConfig(cfg IMSRegistrationConfig) (voiceclient.IMSProfile, error) {
	preparedIdentity := identity.IMSIdentityResolution{}
	if cfg.Prepared != nil {
		preparedIdentity = cfg.Prepared.IMSIdentity
	}
	imsi := strings.TrimSpace(cfg.Profile.IMSI)
	if imsi == "" && cfg.Prepared != nil {
		imsi = strings.TrimSpace(cfg.Prepared.Profile.IMSI)
	}
	domain := firstRuntimeNonEmpty(preparedIdentity.Domain, defaultIMSRealm(cfg))
	impi := firstRuntimeNonEmpty(preparedIdentity.IMPI, defaultIMPI(imsi, domain))
	// 预备阶段的 IMPI 无 ISIM 时是裸 IMSI；digest username 需要 RFC 24.229 的完整
	// Private Identity（<user>@<realm>），缺域名时补全。
	if impi != "" && domain != "" && !strings.Contains(impi, "@") {
		impi = impi + "@" + domain
	}
	impu := firstRuntimeNonEmpty(preparedIdentity.IMPU, defaultIMPU(impi, domain))
	// 无 ISIM 时 identity 预备阶段给出的 IMPU 是裸 "sip:IMSI"（不带域名）。
	// Vodafone UK 实测 P-CSCF 对无域名的 To/From 不应答（REGISTER 全超时）；
	// 参考实现（imscore/BuildIMSIdentity）的 IMPU 一律带 home domain。
	if domain != "" && !strings.Contains(impu, "@") {
		impu = impu + "@" + domain
	}
	if impi == "" {
		return voiceclient.IMSProfile{}, errors.New("IMS private identity is empty")
	}
	if impu == "" {
		return voiceclient.IMSProfile{}, errors.New("IMS public identity is empty")
	}
	// EAP root NAI 需要原始 MNC（"15" 两会变 "015"），不能使用 cfgMCCMNC 的去零版本。
	mcc := strings.TrimSpace(cfg.Profile.MCC)
	mnc := strings.TrimSpace(cfg.Profile.MNC)
	if mcc == "" && len(imsi) >= 3 {
		mcc = imsi[:3]
	}
	if mnc == "" && len(imsi) >= 5 {
		mnc = imsi[3:5]
	}
	imei := strings.TrimSpace(cfg.Profile.IMEI)
	if imei == "" && cfg.Prepared != nil {
		imei = strings.TrimSpace(cfg.Prepared.Profile.IMEI)
	}
	return voiceclient.IMSProfile{
		IMPI:      impi,
		IMPU:      impu,
		Domain:    domain,
		LocalIP:   firstRuntimeNonEmpty(r.ContactHost, cfg.Tunnel.LocalInnerIP),
		UserAgent: firstRuntimeNonEmpty(r.UserAgent, "SimAdmin VoWiFi"),
		IMSI:      imsi,
		MCC:       mcc,
		MNC:       mnc,
		IMEI:      imei,
	}, nil
}

func (r WireIMSRegistrar) contactURIForProfile(profile voiceclient.IMSProfile) string {
	host := strings.TrimSpace(r.ContactHost)
	if host == "" {
		host = strings.TrimSpace(profile.LocalIP)
	}
	if host == "" {
		return ""
	}
	port := r.ContactPort
	if port <= 0 {
		port = 5060
	}
	user := sipUser(profile.IMPU)
	if user == "" {
		user = strings.TrimSpace(profile.IMPI)
	}
	if user == "" {
		user = "ue"
	}
	// TCP 模式下 Contact 带 ;transport=tcp（对齐参考 imscore buildHandsetContact）。
	if strings.EqualFold(strings.TrimSpace(r.Network), "tcp") {
		return "sip:" + user + "@" + formatSIPHost(host) + ":" + strconv.Itoa(port) + ";transport=tcp"
	}
	return "sip:" + user + "@" + formatSIPHost(host) + ":" + strconv.Itoa(port)
}

func registrarURIForProfile(profile voiceclient.IMSProfile) string {
	if strings.TrimSpace(profile.Domain) == "" {
		return ""
	}
	return "sip:" + strings.TrimSpace(profile.Domain)
}

func defaultIMSRealm(cfg IMSRegistrationConfig) string {
	mcc, mnc := cfgMCCMNC(cfg)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", leftPadRuntime(mnc, 3), mcc)
}

func cfgMCCMNC(cfg IMSRegistrationConfig) (string, string) {
	mcc := strings.TrimSpace(cfg.Profile.MCC)
	mnc := strings.TrimSpace(cfg.Profile.MNC)
	if cfg.Prepared != nil {
		if mcc == "" {
			mcc = strings.TrimSpace(cfg.Prepared.Profile.MCC)
		}
		if mnc == "" {
			mnc = strings.TrimSpace(cfg.Prepared.Profile.MNC)
		}
	}
	if mcc == "" && len(strings.TrimSpace(cfg.Profile.IMSI)) >= 3 {
		mcc = strings.TrimSpace(cfg.Profile.IMSI)[:3]
	}
	if mnc == "" && len(strings.TrimSpace(cfg.Profile.IMSI)) >= 6 {
		mnc = strings.TrimSpace(cfg.Profile.IMSI)[3:6]
	}
	trimmedMNC := strings.TrimLeft(mnc, "0")
	if trimmedMNC == "" && mnc != "" {
		trimmedMNC = mnc
	}
	return mcc, trimmedMNC
}

func defaultIMPI(imsi, domain string) string {
	imsi = strings.TrimSpace(imsi)
	domain = strings.TrimSpace(domain)
	if imsi == "" {
		return ""
	}
	if domain == "" || strings.Contains(imsi, "@") {
		return imsi
	}
	return imsi + "@" + domain
}

func defaultIMPU(impi, domain string) string {
	impi = strings.TrimSpace(impi)
	domain = strings.TrimSpace(domain)
	if impi == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(impi), "sip:") || strings.HasPrefix(strings.ToLower(impi), "tel:") {
		return impi
	}
	if strings.Contains(impi, "@") {
		return "sip:" + impi
	}
	if domain != "" {
		return "sip:" + impi + "@" + domain
	}
	return "sip:" + impi
}

func sipUser(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = uri[4:]
	}
	if user, _, ok := strings.Cut(uri, "@"); ok {
		return strings.TrimSpace(user)
	}
	return strings.TrimSpace(uri)
}

func leftPadRuntime(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

func formatSIPHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
