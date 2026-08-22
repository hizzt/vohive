package vowifihost

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	swusim "github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu"
	"github.com/iniwex5/vowifi-go/runtimehost"
	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"

	"github.com/iniwex5/vohive/pkg/logger"
)

type runtimeStartFunc func(context.Context, runtimehost.StartRequest) (*runtimehost.Instance, error)

type missingSIMProvider struct{}

func (m missingSIMProvider) GetIMSI() (string, error) {
	return "", fmt.Errorf("missing SIM provider")
}
func (m missingSIMProvider) CalculateAKA(rand, autn []byte) (swusim.AKAResult, error) {
	return swusim.AKAResult{}, fmt.Errorf("missing SIM provider")
}
func (m missingSIMProvider) Close() error { return nil }

// buildVoWiFiSIMAdapter prefers an injected SIM adapter (e.g. MBIM Auth AKA for
// modems without SIM logical-channel APDU); otherwise derives one from the
// modem's APDU path (AT/QMI).
func buildVoWiFiSIMAdapter(override runtimehost.SIMAdapter, modem runtimehost.Modem, imsi string) runtimehost.SIMAdapter {
	if override != nil {
		return override
	}
	// 所有后端的 AKA 现由 vohive 注入；缺失说明编排未设置，属调用错误。
	return runtimehost.NewReaderSIMAdapter(missingSIMProvider{})
}

type RuntimeStartRequest struct {
	DeviceID      string
	TraceID       string
	Epoch         uint64
	Prepared      PreparedStart
	Modem         runtimehost.Modem
	Dataplane     runtimehost.DataplanePolicy
	VoiceGateway  *voicehost.Gateway
	DeliveryStore messaging.DeliveryStore
	Dispatch      eventhost.Dispatcher
	BeforeStart   func(context.Context, runtimehost.SessionConfig) error
}

type RuntimeStartResult struct {
	Instance *runtimehost.Instance
	Stale    bool
}

func (m *Manager) SetRuntimeStartForTest(fn runtimeStartFunc) {
	if m == nil {
		return
	}
	m.runtimeStart = fn
}

// buildVoWiFiIMSRegistrar 按隧道结果构造 IMS 注册器：SIP over UDP 绑
// tun0 内网地址（LocalInnerIP），ServerAddr 直连 ePDG 下发的 P-CSCF。
// P-CSCF 缺失时返回 nil——无 P-CSCF 无法注册（本环境 CFG 常态下发，
// 未下发属异常会话，重建兜底）。
func buildVoWiFiIMSRegistrar(req runtimehost.StartRequest, tunnel swu.TunnelResult) runtimehost.IMSRegistrar {
	innerIP := strings.TrimSpace(tunnel.LocalInnerIP)
	pcscf := strings.TrimSpace(tunnel.PSCFAddress)
	if innerIP == "" || pcscf == "" {
		logger.Warn("IMS 注册器未构造：隧道结果缺内网 IP 或 P-CSCF",
			"device", req.DeviceID,
			"inner_ip", innerIP,
			"pcscf", pcscf)
		return nil
	}
	return runtimehost.WireIMSRegistrar{
		Network:    "udp",
		LocalAddr:  net.JoinHostPort(innerIP, "0"),
		ServerAddr: net.JoinHostPort(pcscf, "5060"),
		// Contact 带 tun0 IP:5060，P-CSCF 据此回寻（路由在 tun0 上）。
		ContactHost: innerIP,
		ContactPort: 5060,
		Timeout:     8 * time.Second,
		Expires:     3600,
	}
}

func (m *Manager) runtimeStarter() runtimeStartFunc {
	if m != nil && m.runtimeStart != nil {
		return m.runtimeStart
	}
	return runtimehost.Start
}

func (m *Manager) StartRuntime(ctx context.Context, req RuntimeStartRequest) (RuntimeStartResult, error) {
	if m == nil {
		return RuntimeStartResult{}, fmt.Errorf("vowifi host manager is nil")
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return RuntimeStartResult{}, fmt.Errorf("vowifi runtime start device_id is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	prepared := req.Prepared.Prepared
	profile := prepared.Profile
	if strings.TrimSpace(profile.IMSI) == "" {
		profile = req.Prepared.Profile
	}
	networkMode := strings.TrimSpace(req.Prepared.StartupState.NetworkMode)
	if networkMode == "" {
		networkMode = strings.TrimSpace(req.Prepared.NetworkMode)
	}

	inst, err := m.runtimeStarter()(ctx, runtimehost.StartRequest{
		Mode:          runtimehost.StartModeMain,
		DeviceID:      deviceID,
		TraceID:       strings.TrimSpace(req.TraceID),
		Profile:       profile,
		Prepared:      &prepared,
		NetworkMode:   networkMode,
		VoiceGateway:  req.VoiceGateway,
		SIM:           buildVoWiFiSIMAdapter(req.Prepared.SIM, req.Modem, prepared.Profile.IMSI),
		Access:        runtimehost.NewModemAccessAdapter(req.Modem),
		Dataplane:     req.Dataplane,
		Proxy:         req.Prepared.Proxy,
		DeliveryStore: req.DeliveryStore,
		Dispatch:      req.Dispatch,
		// IMS 注册接通（2026-08-22 定案）：之前不传 registrar，runtimehost
		// imsReady nil 直通为假象——隧道之上零 SIP 业务流，伦敦代理差时段
		// relay ~7min 回收（v1.5.5 同代理靠周期 SIP 事务存活 35min+）。
		// WireIMSRegistrar 的 REGISTER→401→AKA digest→200 与 refresh/CRLF
		// keepalive 循环现成；SIP socket 绑 tun0 内网 IP（TUN 数据面已把
		// default 路由指到 tun0，P-CSCF 直连无需 DNS）。
		IMSRegistrarFactory: buildVoWiFiIMSRegistrar,
		BeforeStart:   req.BeforeStart,
		ShouldRun: func() bool {
			return ctx.Err() == nil && m.ShouldRun(deviceID, req.Epoch)
		},
	})
	if err != nil {
		return RuntimeStartResult{}, err
	}

	inst.AddObserver(runtimehost.ObserverFunc(func(_ context.Context, ev runtimehost.Event) {
		if !m.IsCurrentInstance(deviceID, inst) {
			m.RecordStartupState(deviceID, ev.State)
			return
		}
		// 数据面 pump 死亡（runtimehost watchTunnelPump 翻 PhaseError）：
		// 移除 instance 让 Active=false，目标态 reconcile 兜底重建。
		// 不移除则 Active 永真，VoWiFi 静默死亡后永不自愈（设备实测）。
		if ev.State.Phase == runtimehost.PhaseError {
			m.RuntimeStore().DeleteInstance(deviceID, inst)
			logger.Warn("VoWiFi 数据面异常退出，已下线实例等待目标态恢复重建",
				"device", deviceID,
				"reason", ev.State.LastReason)
		}
		m.BroadcastState(deviceID)
	}))

	if !m.ClaimStarted(deviceID, req.Epoch, inst) {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = inst.Stop(stopCtx)
		cancel()
		m.ClearStartupStateAndBroadcast(deviceID)
		return RuntimeStartResult{Instance: inst, Stale: true}, nil
	}

	return RuntimeStartResult{Instance: inst}, nil
}
