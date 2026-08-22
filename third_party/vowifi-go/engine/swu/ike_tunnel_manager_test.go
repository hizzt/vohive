package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu/eapaka"
	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

func TestIKEPacketTunnelManagerEstablishesPacketSession(t *testing.T) {
	ikeTransport := ikeTunnelNoopTransport{}
	espTransport := &captureESPPacketTransport{}
	var gotInit ikev2.InitConfig
	var gotAuth ikev2.FullAuthConfig
	var gotIKETransport IKETransportConfig
	var gotESPTransport ESPTransportConfig

	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:          ikeTunnelAKAProvider{},
		EPDGResolver: newEPDGTestResolver("epdg.example", "198.18.0.38"),
		Random:       bytes.NewReader(append([]byte{0xca, 0xfe, 0xba, 0xbe}, bytes.Repeat([]byte{0x55}, 64)...)),
		IKETransportFactory: func(cfg TunnelConfig, transport IKETransportConfig) (ikev2.InitTransport, error) {
			gotIKETransport = transport
			return ikeTransport, nil
		},
		ESPTransportFactory: func(cfg TunnelConfig, transport ESPTransportConfig) (ESPPacketTransport, error) {
			gotESPTransport = transport
			return espTransport, nil
		},
		InitRunner: func(ctx context.Context, cfg ikev2.InitConfig) (ikev2.InitResult, error) {
			gotInit = cfg
			return ikev2.InitResult{MOBIKESupported: true}, nil
		},
		AuthRunner: func(ctx context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			gotAuth = cfg
			child := packetChildSA(true)
			child.LocalSPI = append([]byte(nil), cfg.ChildSPI...)
			child.Configuration = &ikev2.Configuration{
				Type: ikev2.CFGReply,
				Attributes: []ikev2.ConfigurationAttribute{
					{Type: ikev2.ConfigInternalIPv4Address, Value: []byte{10, 0, 0, 2}},
					{Type: ikev2.ConfigInternalIPv4DNS, Value: []byte{10, 0, 0, 1}},
					{Type: ikev2.ConfigInternalIPv6DNS, Value: net.ParseIP("2001:db8::53").To16()},
				},
			}
			return ikev2.FullAuthResult{ChildSA: &child, NextMessageID: 3}, nil
		},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:     "dev-1",
		Mode:         DataplaneModeUserspace,
		EPDGAddress:  "epdg.example",
		OuterLocalIP: "192.0.2.10",
		IMSI:         "310280233641503",
		MCC:          "310",
		MNC:          "280",
		Identity:     IMSIdentity{IMPI: "310280233641503@private.att.net"},
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	result := session.Result()
	if !result.IsReady() || result.EPDGAddress != "epdg.example" || result.LocalInnerIP != "10.0.0.2" {
		t.Fatalf("result=%+v", result)
	}
	if len(result.DNSServers) != 2 || result.DNSServers[0] != "10.0.0.1" || result.DNSServers[1] != "2001:db8::53" {
		t.Fatalf("result DNS=%+v", result.DNSServers)
	}
	result.DNSServers[0] = "198.51.100.53"
	if got := session.Result().DNSServers[0]; got != "10.0.0.1" {
		t.Fatalf("Result() leaked DNS slice, got %q", got)
	}
	if !result.MOBIKESupported || result.ChildSAIdentifier != "cafebabe/22222222" {
		t.Fatalf("result MOBIKE/child id = %+v", result)
	}
	if gotIKETransport.RemoteAddr != "198.18.0.38:500" || gotIKETransport.LocalAddr != "192.0.2.10:500" || gotIKETransport.UseNonESPMarker {
		t.Fatalf("IKE transport=%+v", gotIKETransport)
	}
	if gotESPTransport.RemoteAddr != "198.18.0.38:500" || gotESPTransport.LocalAddr != "192.0.2.10:500" {
		t.Fatalf("ESP transport=%+v", gotESPTransport)
	}
	if gotInit.Transport != ikeTransport || gotInit.RemotePort != 500 {
		t.Fatalf("init config=%+v", gotInit)
	}
	if gotAuth.Transport != ikeTransport || gotAuth.SIM == nil {
		t.Fatalf("auth config transport/SIM not wired: %+v", gotAuth)
	}
	// 新语义（对齐 vowifi_gateway）：EAP 身份永远用 IMSI 永久 NAI，
	// ISIM/IMPI 的 ims./私有域身份不进 IKE/EAP。
	if gotAuth.EAPIdentity != "0310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org" {
		t.Fatalf("EAP identity=%q", gotAuth.EAPIdentity)
	}
	if gotAuth.InitiatorID.Type != ikev2.IDRFC822Addr || string(gotAuth.InitiatorID.Data) != gotAuth.EAPIdentity {
		t.Fatalf("initiator id=%+v", gotAuth.InitiatorID)
	}
	if !bytes.Equal(gotAuth.ChildSPI, []byte{0xca, 0xfe, 0xba, 0xbe}) {
		t.Fatalf("child SPI=%x", gotAuth.ChildSPI)
	}

	packetSession, ok := session.(PacketTunnelSession)
	if !ok {
		t.Fatalf("session type %T does not implement PacketTunnelSession", session)
	}
	if err := packetSession.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	if len(espTransport.packets) != 1 {
		t.Fatalf("ESP packets=%d, want 1", len(espTransport.packets))
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !espTransport.closed {
		t.Fatalf("ESP transport was not closed")
	}
}

func TestIKEPacketTunnelManagerDerivesEPDGAndAKAIdentity(t *testing.T) {
	var gotAuth ikev2.FullAuthConfig
	var gotIKETransport IKETransportConfig
	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:          ikeTunnelAKAProvider{},
		ChildSPI:     []byte{0x11, 0x22, 0x33, 0x44},
		EPDGResolver: newEPDGTestResolver("epdg.epc.mnc028.mcc310.pub.3gppnetwork.org", "192.0.2.99"),
		IKETransportFactory: func(cfg TunnelConfig, transport IKETransportConfig) (ikev2.InitTransport, error) {
			gotIKETransport = transport
			return ikeTunnelNoopTransport{}, nil
		},
		ESPTransport: &captureESPPacketTransport{},
		InitRunner: func(ctx context.Context, cfg ikev2.InitConfig) (ikev2.InitResult, error) {
			return ikev2.InitResult{}, nil
		},
		AuthRunner: func(ctx context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			gotAuth = cfg
			child := packetChildSA(true)
			child.LocalSPI = append([]byte(nil), cfg.ChildSPI...)
			return ikev2.FullAuthResult{ChildSA: &child, NextMessageID: 2}, nil
		},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID: "dev-1",
		Mode:     DataplaneModeUserspace,
		IMSI:     "310280233641503",
		MCC:      "310",
		MNC:      "28",
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	defer session.Close(context.Background())

	wantEPDG := "epdg.epc.mnc028.mcc310.pub.3gppnetwork.org"
	wantIdentity := "0310280233641503@nai.epc.mnc028.mcc310.3gppnetwork.org"
	if gotIKETransport.EPDGAddress != "192.0.2.99" || gotIKETransport.RemoteAddr != "192.0.2.99:500" {
		t.Fatalf("IKE transport=%+v", gotIKETransport)
	}
	if gotAuth.EAPIdentity != wantIdentity || string(gotAuth.InitiatorID.Data) != wantIdentity {
		t.Fatalf("auth identity=%q initiator=%q", gotAuth.EAPIdentity, gotAuth.InitiatorID.Data)
	}
	if session.Result().EPDGAddress != wantEPDG {
		t.Fatalf("result EPDG=%q", session.Result().EPDGAddress)
	}
}

func TestIKEPacketTunnelManagerCarriesReauthenticationState(t *testing.T) {
	initialKeys := eapaka.Keys{
		MK:    bytes.Repeat([]byte{0x01}, 20),
		KEncr: bytes.Repeat([]byte{0x02}, eapaka.KeyLengthKEncr),
		KAut:  bytes.Repeat([]byte{0x03}, eapaka.KeyLengthKAut),
		MSK:   bytes.Repeat([]byte{0x04}, eapaka.KeyLengthMSK),
		EMSK:  bytes.Repeat([]byte{0x05}, eapaka.KeyLengthEMSK),
	}
	nextKeys := initialKeys
	nextKeys.MSK = bytes.Repeat([]byte{0x06}, eapaka.KeyLengthMSK)
	nextKeys.EMSK = bytes.Repeat([]byte{0x07}, eapaka.KeyLengthEMSK)
	var gotAuth ikev2.FullAuthConfig
	var gotState EAPReauthenticationState
	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:          ikeTunnelAKAProvider{},
		ChildSPI:     []byte{0x11, 0x22, 0x33, 0x44},
		Transport:    ikeTunnelNoopTransport{},
		ESPTransport: &captureESPPacketTransport{},
		Reauthentication: EAPReauthenticationState{
			Identity:  "reauth-2",
			Counter:   2,
			CounterOK: true,
			Keys:      initialKeys,
		},
		OnReauthenticationState: func(state EAPReauthenticationState) {
			gotState = state
		},
		InitRunner: func(ctx context.Context, cfg ikev2.InitConfig) (ikev2.InitResult, error) {
			return ikev2.InitResult{}, nil
		},
		AuthRunner: func(ctx context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			gotAuth = cfg
			child := packetChildSA(true)
			child.LocalSPI = append([]byte(nil), cfg.ChildSPI...)
			return ikev2.FullAuthResult{
				ChildSA:            &child,
				EAPKeys:            nextKeys,
				EAPNextReauthID:    "reauth-3",
				EAPNextPseudonym:   "pseudo-3",
				EAPReauthenticated: true,
				EAPReauthCounter:   3,
				NextMessageID:      2,
			}, nil
		},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
		MCC:         "310",
		MNC:         "280",
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	defer session.Close(context.Background())

	if gotAuth.EAPReauthIdentity != "reauth-2" || gotAuth.EAPReauthCounter != 2 || !gotAuth.EAPReauthCounterOK {
		t.Fatalf("auth reauth config identity=%q counter=%d ok=%t", gotAuth.EAPReauthIdentity, gotAuth.EAPReauthCounter, gotAuth.EAPReauthCounterOK)
	}
	if !bytes.Equal(gotAuth.EAPKeys.MSK, initialKeys.MSK) {
		t.Fatalf("auth EAP keys were not carried")
	}
	if gotState.Identity != "reauth-3" || gotState.NextPseudonym != "pseudo-3" || gotState.Counter != 3 || !gotState.CounterOK || !gotState.Reauthenticated {
		t.Fatalf("callback state=%+v", gotState)
	}
	if !bytes.Equal(gotState.Keys.MSK, nextKeys.MSK) || !bytes.Equal(manager.Config.Reauthentication.Keys.EMSK, nextKeys.EMSK) {
		t.Fatalf("updated keys callback=%+v manager=%+v", gotState.Keys, manager.Config.Reauthentication.Keys)
	}
	gotState.Keys.MSK[0] = 0xff
	if manager.Config.Reauthentication.Keys.MSK[0] == 0xff {
		t.Fatal("callback state leaked key slice into manager state")
	}
}

func TestIKEPacketTunnelManagerIgnoresIncompleteReauthenticationState(t *testing.T) {
	initialKeys := eapaka.Keys{
		MK:    bytes.Repeat([]byte{0x01}, 20),
		KEncr: bytes.Repeat([]byte{0x02}, eapaka.KeyLengthKEncr),
		KAut:  bytes.Repeat([]byte{0x03}, eapaka.KeyLengthKAut),
		MSK:   bytes.Repeat([]byte{0x04}, eapaka.KeyLengthMSK),
		EMSK:  bytes.Repeat([]byte{0x05}, eapaka.KeyLengthEMSK),
	}
	var gotAuth ikev2.FullAuthConfig
	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:          ikeTunnelAKAProvider{},
		ChildSPI:     []byte{0x11, 0x22, 0x33, 0x44},
		Transport:    ikeTunnelNoopTransport{},
		ESPTransport: &captureESPPacketTransport{},
		Reauthentication: EAPReauthenticationState{
			Counter:   9,
			CounterOK: true,
			Keys:      initialKeys,
		},
		InitRunner: func(ctx context.Context, cfg ikev2.InitConfig) (ikev2.InitResult, error) {
			return ikev2.InitResult{}, nil
		},
		AuthRunner: func(ctx context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			gotAuth = cfg
			child := packetChildSA(true)
			child.LocalSPI = append([]byte(nil), cfg.ChildSPI...)
			return ikev2.FullAuthResult{
				ChildSA:         &child,
				EAPKeys:         initialKeys,
				EAPNextReauthID: "reauth-1",
				NextMessageID:   2,
			}, nil
		},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
		MCC:         "310",
		MNC:         "280",
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	defer session.Close(context.Background())

	if gotAuth.EAPReauthIdentity != "" || gotAuth.EAPReauthCounter != 0 || gotAuth.EAPReauthCounterOK {
		t.Fatalf("auth reauth config identity=%q counter=%d ok=%t", gotAuth.EAPReauthIdentity, gotAuth.EAPReauthCounter, gotAuth.EAPReauthCounterOK)
	}
	if len(gotAuth.EAPKeys.KAut) != 0 || len(gotAuth.EAPKeys.KEncr) != 0 {
		t.Fatalf("incomplete EAP keys were carried: %+v", gotAuth.EAPKeys)
	}
	if manager.Config.Reauthentication.Identity != "reauth-1" || manager.Config.Reauthentication.Counter != 0 || !manager.Config.Reauthentication.CounterOK {
		t.Fatalf("updated state=%+v", manager.Config.Reauthentication)
	}
}

func TestIKEPacketTunnelManagerResetsReauthenticationCounterAfterFullAuth(t *testing.T) {
	previousKeys := eapaka.Keys{
		MK:    bytes.Repeat([]byte{0x01}, 20),
		KEncr: bytes.Repeat([]byte{0x02}, eapaka.KeyLengthKEncr),
		KAut:  bytes.Repeat([]byte{0x03}, eapaka.KeyLengthKAut),
		MSK:   bytes.Repeat([]byte{0x04}, eapaka.KeyLengthMSK),
		EMSK:  bytes.Repeat([]byte{0x05}, eapaka.KeyLengthEMSK),
	}
	nextKeys := eapaka.Keys{
		MK:    bytes.Repeat([]byte{0x11}, 20),
		KEncr: bytes.Repeat([]byte{0x12}, eapaka.KeyLengthKEncr),
		KAut:  bytes.Repeat([]byte{0x13}, eapaka.KeyLengthKAut),
		MSK:   bytes.Repeat([]byte{0x14}, eapaka.KeyLengthMSK),
		EMSK:  bytes.Repeat([]byte{0x15}, eapaka.KeyLengthEMSK),
	}
	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:          ikeTunnelAKAProvider{},
		ChildSPI:     []byte{0x11, 0x22, 0x33, 0x44},
		Transport:    ikeTunnelNoopTransport{},
		ESPTransport: &captureESPPacketTransport{},
		Reauthentication: EAPReauthenticationState{
			Identity:            "old-reauth",
			Counter:             9,
			CounterOK:           true,
			Keys:                previousKeys,
			LastAcceptedCounter: 9,
			LastRejectedCounter: 4,
		},
		InitRunner: func(ctx context.Context, cfg ikev2.InitConfig) (ikev2.InitResult, error) {
			return ikev2.InitResult{}, nil
		},
		AuthRunner: func(ctx context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			if cfg.EAPReauthIdentity != "old-reauth" || cfg.EAPReauthCounter != 9 || !cfg.EAPReauthCounterOK {
				t.Fatalf("auth reauth config identity=%q counter=%d ok=%t", cfg.EAPReauthIdentity, cfg.EAPReauthCounter, cfg.EAPReauthCounterOK)
			}
			child := packetChildSA(true)
			child.LocalSPI = append([]byte(nil), cfg.ChildSPI...)
			return ikev2.FullAuthResult{
				ChildSA:         &child,
				EAPKeys:         nextKeys,
				EAPNextReauthID: "new-reauth",
				NextMessageID:   2,
			}, nil
		},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
		MCC:         "310",
		MNC:         "280",
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	defer session.Close(context.Background())

	state := manager.Config.Reauthentication
	if state.Identity != "new-reauth" || state.Counter != 0 || !state.CounterOK || state.LastAcceptedCounter != 0 || state.LastRejectedCounter != 0 {
		t.Fatalf("updated state=%+v", state)
	}
	if !bytes.Equal(state.Keys.MSK, nextKeys.MSK) {
		t.Fatalf("updated keys=%+v", state.Keys)
	}
}

func TestIKEPacketTunnelManagerRejectsMissingSIM(t *testing.T) {
	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{})
	_, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
	})
	if !errors.Is(err, ErrInvalidIKETunnelManager) {
		t.Fatalf("EstablishTunnel() err=%v, want ErrInvalidIKETunnelManager", err)
	}
}

func TestIKEPacketTunnelManagerRejectsMissingChildSA(t *testing.T) {
	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:          ikeTunnelAKAProvider{},
		ChildSPI:     []byte{0x11, 0x22, 0x33, 0x44},
		Transport:    ikeTunnelNoopTransport{},
		ESPTransport: &captureESPPacketTransport{},
		InitRunner: func(ctx context.Context, cfg ikev2.InitConfig) (ikev2.InitResult, error) {
			return ikev2.InitResult{}, nil
		},
		AuthRunner: func(ctx context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			return ikev2.FullAuthResult{NextMessageID: 2}, nil
		},
	})
	_, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:    "dev-1",
		Mode:        DataplaneModeUserspace,
		EPDGAddress: "epdg.example",
		IMSI:        "310280233641503",
	})
	if !errors.Is(err, ErrTunnelNotReady) {
		t.Fatalf("EstablishTunnel() err=%v, want ErrTunnelNotReady", err)
	}
}

type ikeTunnelNoopTransport struct{}

func (ikeTunnelNoopTransport) ExchangeIKE(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unexpected IKE exchange")
}

type ikeTunnelAKAProvider struct{}

func (ikeTunnelAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	return sim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04},
		CK:  bytes.Repeat([]byte{0x10}, 16),
		IK:  bytes.Repeat([]byte{0x20}, 16),
	}, nil
}

func TestRunIKEInitWithDHFallbackDegradesOnInvalidKEPayload(t *testing.T) {
	var sawGroups []uint16

	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{})
	transport := ikeTunnelNoopTransport{}
	cfg := IKETransportConfig{
		LocalIP:    net.ParseIP("192.0.2.10"),
		LocalPort:  500,
		RemoteIP:   net.ParseIP("198.51.100.1"),
		RemotePort: 500,
	}
	random := bytes.NewReader(bytes.Repeat([]byte{0x55}, 64))

	runner := func(ctx context.Context, ikeCfg ikev2.InitConfig) (ikev2.InitResult, error) {
		sawGroups = append(sawGroups, ikeCfg.DHGroup)
		if len(sawGroups) == 1 || ikeCfg.DHGroup == ikev2.DHGroup2048BitMODP {
			return ikev2.InitResult{}, ikev2.ErrInvalidKEPayload
		}
		return ikev2.InitResult{
			InitiatorSPI: 0x1122334455667788,
			NonceI:       []byte{0xab, 0xcd},
		}, nil
	}

	result, err := manager.runIKEInitWithDHFallback(context.Background(), runner, transport, cfg, random, comprehensiveIKEProposal())
	if err != nil {
		t.Fatalf("runIKEInitWithDHFallback() err=%v", err)
	}
	if len(sawGroups) != 2 {
		t.Fatalf("initRunner calls=%d, want 2 (MODP2048 then MODP1024)", len(sawGroups))
	}
	if sawGroups[0] != ikev2.DHGroup2048BitMODP || sawGroups[1] != ikev2.DHGroup1024BitMODP {
		t.Fatalf("DH groups=%v, want [14 2]", sawGroups)
	}
	if result.NonceI == nil || result.NonceI[0] != 0xab {
		t.Fatalf("result from fallback attempt lost: %+v", result)
	}
}

func TestRunIKEInitWithDHFallbackReturnsOtherErrors(t *testing.T) {
	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{})
	transport := ikeTunnelNoopTransport{}
	cfg := IKETransportConfig{
		LocalIP:   net.ParseIP("192.0.2.10"),
		LocalPort: 500,
	}
	random := bytes.NewReader(bytes.Repeat([]byte{0x55}, 64))

	sentinel := errors.New("boom")
	calls := 0
	runner := func(ctx context.Context, ikeCfg ikev2.InitConfig) (ikev2.InitResult, error) {
		calls++
		return ikev2.InitResult{}, sentinel
	}

	_, err := manager.runIKEInitWithDHFallback(context.Background(), runner, transport, cfg, random, comprehensiveIKEProposal())
	if err == nil || err.Error() != "boom" {
		t.Fatalf("err=%v, want sentinel propagated", err)
	}
	if calls != 1 {
		t.Fatalf("initRunner calls=%d, want 1 (non-KE error aborts fallback)", calls)
	}
}

func TestFilterProposalsByDHGroup(t *testing.T) {
	sa := comprehensiveIKEProposal() // 4 proposals: MODP2048 x1, MODP1024 x3
	if len(sa.Proposals) != 4 {
		t.Fatalf("comprehensive proposal count=%d, want 4", len(sa.Proposals))
	}

	g14 := filterProposalsByDHGroup(sa, ikev2.DHGroup2048BitMODP)
	if len(g14.Proposals) != 1 {
		t.Fatalf("MODP2048 filtered count=%d, want 1", len(g14.Proposals))
	}
	g2 := filterProposalsByDHGroup(sa, ikev2.DHGroup1024BitMODP)
	if len(g2.Proposals) != 3 {
		t.Fatalf("MODP1024 filtered count=%d, want 3", len(g2.Proposals))
	}
	// RFC 7296 §3.3：提案编号必须从 1 连续——过滤后重编号，不能保留原始 2,3,4。
	for i, p := range g2.Proposals {
		if p.Number != uint8(i+1) {
			t.Fatalf("MODP1024 proposal[%d].Number=%d want %d", i, p.Number, i+1)
		}
	}
	for i, p := range g14.Proposals {
		if p.Number != uint8(i+1) {
			t.Fatalf("MODP2048 proposal[%d].Number=%d want %d", i, p.Number, i+1)
		}
	}
}
