package swu

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

// responderFixture 构造标准 IKE 密钥材料的应答方测试夹具（与 ikev2 包
// informationalFixture 同款：SplitIKEKeys 均匀材料）。
func responderFixture(t *testing.T) (ikev2.InitResult, ikev2.IKEKeys) {
	t.Helper()
	profile, err := ikev2.KeyMaterialProfileFromSA(ikev2.DefaultIKEProposal())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys, err := ikev2.SplitIKEKeys(profile, incrementalBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	return ikev2.InitResult{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Keys:         keys,
	}, keys
}

func incrementalBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

// buildPeerRequest 构造 ePDG（发起方）发来的加密 INFORMATIONAL 请求。
func buildPeerRequest(t *testing.T, init ikev2.InitResult, keys ikev2.IKEKeys, messageID uint32, inner []ikev2.Payload, response bool) []byte {
	t.Helper()
	headerFlags := ikev2.FlagInitiator
	if response {
		headerFlags |= ikev2.FlagResponse
	}
	// 发起方请求：BuildInformationalRequestFrom(init, msgid, fromInitiator=true)
	_, raw, err := ikev2.BuildInformationalRequestFrom(init, keys, messageID, true, inner, nil)
	if err != nil {
		t.Fatalf("BuildInformationalRequestFrom() error = %v", err)
	}
	if response {
		// 响应报文：用 ResponseFrom 重构造后改 flags 不现实——直接在原始字节上
		// 置位 R（加密体不受 Flags 影响，Flags 仅在明文头）
		raw[19] |= 0x20
	}
	_ = headerFlags
	return raw
}

func TestIKEResponderAnswersDPDProbe(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	r := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	req := buildPeerRequest(t, init, keys, 77, nil, false)
	if !r.HandleInbound(context.Background(), req) {
		t.Fatalf("HandleInbound() = false, want consumed")
	}
	if len(sent) != 1 {
		t.Fatalf("sent=%d responses, want 1", len(sent))
	}
	// 响应必须能被本方按"对端响应"解密（fromInitiator=false → SK_AR 方向密钥）
	msg, inner, err := ikev2.UnprotectMessage(sent[0], keys, false)
	if err != nil {
		t.Fatalf("UnprotectMessage(response) error = %v", err)
	}
	if len(inner) != 0 {
		t.Fatalf("inner payloads=%d, want empty DPD ack", len(inner))
	}
	h := msg.Header
	if h.InitiatorSPI != init.InitiatorSPI || h.ResponderSPI != init.ResponderSPI {
		t.Fatalf("SPI mismatch: %x/%x", h.InitiatorSPI, h.ResponderSPI)
	}
	if h.MessageID != 77 {
		t.Fatalf("MessageID=%d, want 77 (echo)", h.MessageID)
	}
	if h.Flags&ikev2.FlagResponse == 0 {
		t.Fatalf("Flags=%#x missing Response bit", h.Flags)
	}
	if h.Flags&ikev2.FlagInitiator != 0 {
		t.Fatalf("Flags=%#x Initiator bit must be clear on response", h.Flags)
	}
}

func TestIKEResponderAnswersDeviceIdentity(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	r := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	// 构造带 DEVICE_IDENTITY 请求通知的 INFORMATIONAL（空体通知数据）
	np, err := ikev2.DeviceIdentityNotify(ikev2.DeviceIdentity{
		IdentityType: ikev2.DeviceIdentityTypeIMEI,
		Value:        "123456789012345",
	})
	if err != nil {
		t.Fatalf("DeviceIdentityNotify() error = %v", err)
	}
	req := buildPeerRequest(t, init, keys, 5, []ikev2.Payload{np}, false)
	if !r.HandleInbound(context.Background(), req) {
		t.Fatalf("HandleInbound() = false, want consumed")
	}
	if len(sent) != 1 {
		t.Fatalf("sent=%d responses, want 1", len(sent))
	}
	_, inner, err := ikev2.UnprotectMessage(sent[0], keys, false)
	if err != nil {
		t.Fatalf("UnprotectMessage(response) error = %v", err)
	}
	found := false
	for _, p := range inner {
		if p.Type != ikev2.PayloadNotify {
			continue
		}
		n, err := ikev2.ParseNotify(p.Body)
		if err != nil {
			t.Fatalf("ParseNotify() error = %v", err)
		}
		if n.NotifyType == ikev2.NotifyDeviceIdentity {
			found = true
			// 通知数据 = [2B 总长][1B 类型 0x01=IMEI][BCD 低半字节在偶数位]
			want := append([]byte{0x00, 0x0b, 0x01}, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf5)
			if !bytes.Equal(n.NotificationData, want) {
				t.Fatalf("device identity data=%x, want %x", n.NotificationData, want)
			}
		}
	}
	if !found {
		t.Fatalf("response missing DEVICE_IDENTITY notify")
	}
}

func TestIKEResponderDeleteTriggersCallback(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	deleted := make(chan struct{}, 1)
	r := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	r.SetOnDelete(func() { deleted <- struct{}{} })
	// ePDG 发 ESP DELETE（拆 CHILD SA）
	delPayload, err := ikev2.ESPDeletePayload([]byte{0x22, 0x33, 0x44, 0x55})
	if err != nil {
		t.Fatalf("ESPDeletePayload() error = %v", err)
	}
	req := buildPeerRequest(t, init, keys, 9, []ikev2.Payload{delPayload}, false)
	if !r.HandleInbound(context.Background(), req) {
		t.Fatalf("HandleInbound() = false, want consumed")
	}
	if len(sent) != 1 {
		t.Fatalf("sent=%d responses, want 1 (delete ack)", len(sent))
	}
	select {
	case <-deleted:
	case <-time.After(2 * time.Second):
		t.Fatalf("onDelete callback not fired")
	}
}

func TestIKEResponderDropsLateResponse(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	r := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	// 迟到的本方请求响应（R=1）：消费但不发送任何应答
	resp := buildPeerRequest(t, init, keys, 3, nil, true)
	if !r.HandleInbound(context.Background(), resp) {
		t.Fatalf("HandleInbound() = false, want consumed (late response)")
	}
	if len(sent) != 0 {
		t.Fatalf("sent=%d responses, want 0 for late response", len(sent))
	}
}

func TestIKEResponderIgnoresForeignSPI(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	r := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	// 旧 SA 残留：SPIi 对不上
	foreign := buildPeerRequest(t, init, keys, 1, nil, false)
	foreign[0] ^= 0xff // 破坏 InitiatorSPI 首字节
	if r.HandleInbound(context.Background(), foreign) {
		t.Fatalf("HandleInbound() = true for foreign SPI, want untouched")
	}
	if len(sent) != 0 {
		t.Fatalf("sent=%d, want 0", len(sent))
	}
	// 关闭后不再应答
	r.Close()
	req := buildPeerRequest(t, init, keys, 2, nil, false)
	if r.HandleInbound(context.Background(), req) {
		t.Fatalf("HandleInbound() = true after Close(), want untouched")
	}
}

// TestPacketSessionDispatchesIKEToResponder 验证 ReadInnerPacket 路径：
// 入站 IKE 请求被应答方消费（应答回调收到报文），ESP 包正常走解密。
func TestPacketSessionDispatchesIKEToResponder(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	responder := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	wire := &queueESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:      packetChildSA(true),
		Transport:    wire,
		IKEResponder: responder,
		Result:       TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	// 先投递 ePDG DPD 请求，再投递真实 ESP 包
	dpdReq := buildPeerRequest(t, init, keys, 30, nil, false)
	wire.push(dpdReq)
	wire.push(peerOutbox(t))

	pkt, err := session.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket() error = %v", err)
	}
	if pkt.NextHeader == 0 || len(pkt.Payload) == 0 {
		t.Fatalf("unexpected inner packet %+v", pkt)
	}
	if len(sent) != 1 {
		t.Fatalf("responder sent=%d responses, want 1 (DPD answered)", len(sent))
	}
}

// queueESPPacketTransport 按投递顺序回放的读侧 transport。
type queueESPPacketTransport struct {
	mu      chan struct{}
	packets [][]byte
}

func (t *queueESPPacketTransport) push(p []byte) {
	t.packets = append(t.packets, append([]byte(nil), p...))
}

func (t *queueESPPacketTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	return nil
}

func (t *queueESPPacketTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if len(t.packets) == 0 {
		return nil, errors.New("no packets")
	}
	packet := t.packets[0]
	t.packets = t.packets[1:]
	return packet, nil
}

// peerOutbox 构造一个 b→a 方向会话，返回它加密出的首个 ESP 包。
func peerOutbox(t *testing.T) []byte {
	t.Helper()
	capture := &captureESPPacketTransport{}
	peerSession, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(false),
		Transport: capture,
	})
	if err != nil {
		t.Fatalf("NewPacketSession(peerSession) error = %v", err)
	}
	if err := peerSession.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad}); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	if len(capture.packets) == 0 {
		t.Fatalf("peer produced no ESP packet")
	}
	return capture.packets[0]
}

// TestIKEResponderAnswersPSCFRestoration 验证 P-CSCF restoration 应答：
// CFG_REQUEST(带 P_CSCF v4 地址) → CFG_REPLY 回显属性类型且 length 0 + 回调触发。
func TestIKEResponderAnswersPSCFRestoration(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	restored := make(chan string, 1)
	r := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	r.SetOnPSCFRestore(func(addr string) { restored <- addr })

	cfgPayload, err := ikev2.ConfigurationPayload(ikev2.Configuration{
		Type: ikev2.CFGRequest,
		Attributes: []ikev2.ConfigurationAttribute{
			{Type: ikev2.ConfigInternalIPv4Pcscf, Value: []byte{10, 11, 12, 13}},
		},
	})
	if err != nil {
		t.Fatalf("ConfigurationPayload() error = %v", err)
	}
	req := buildPeerRequest(t, init, keys, 21, []ikev2.Payload{cfgPayload}, false)
	if !r.HandleInbound(context.Background(), req) {
		t.Fatalf("HandleInbound() = false, want consumed")
	}
	if len(sent) != 1 {
		t.Fatalf("sent=%d responses, want 1", len(sent))
	}
	_, inner, err := ikev2.UnprotectMessage(sent[0], keys, false)
	if err != nil {
		t.Fatalf("UnprotectMessage() error = %v", err)
	}
	found := false
	for _, p := range inner {
		if p.Type != ikev2.PayloadCP {
			continue
		}
		cfg, err := ikev2.ParseConfiguration(p.Body)
		if err != nil {
			t.Fatalf("ParseConfiguration() error = %v", err)
		}
		if cfg.Type != ikev2.CFGReply {
			t.Fatalf("cfg.Type=%d, want CFGReply", cfg.Type)
		}
		if len(cfg.Attributes) != 1 || cfg.Attributes[0].Type != ikev2.ConfigInternalIPv4Pcscf {
			t.Fatalf("attrs=%+v, want echoed P-CSCF type", cfg.Attributes)
		}
		if len(cfg.Attributes[0].Value) != 0 {
			t.Fatalf("attr value len=%d, want 0 (len-0 echo)", len(cfg.Attributes[0].Value))
		}
		found = true
	}
	if !found {
		t.Fatalf("response missing CFG_REPLY")
	}
	select {
	case addr := <-restored:
		if addr != "10.11.12.13" {
			t.Fatalf("restored addr=%q, want 10.11.12.13", addr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("onPSCFRestore callback not fired")
	}
}

// TestIKEResponderAnswersIMEISVRequest 验证 DEVICE_IDENTITY 请求按类型区分：
// ePDG 要 IMEISV(0x02) 时回 16 位 IMEISV（IMEI+SV 兜底推导），而非 15 位 IMEI。
func TestIKEResponderAnswersIMEISVRequest(t *testing.T) {
	init, keys := responderFixture(t)
	var sent [][]byte
	r := NewIKEResponder(init, keys, "123456789012345", func(raw []byte) error {
		sent = append(sent, append([]byte(nil), raw...))
		return nil
	})
	// 构造 IMEISV 请求通知：数据 = [len(2)][type(1)=0x02]
	reqPayload, err := ikev2.NotifyPayload(ikev2.Notify{
		ProtocolID:       ikev2.ProtocolIKE,
		NotifyType:       ikev2.NotifyDeviceIdentity,
		NotificationData: []byte{0x00, 0x03, 0x02},
	})
	if err != nil {
		t.Fatalf("NotifyPayload() error = %v", err)
	}
	req := buildPeerRequest(t, init, keys, 31, []ikev2.Payload{reqPayload}, false)
	if !r.HandleInbound(context.Background(), req) {
		t.Fatalf("HandleInbound() = false, want consumed")
	}
	if len(sent) != 1 {
		t.Fatalf("sent=%d, want 1", len(sent))
	}
	_, inner, err := ikev2.UnprotectMessage(sent[0], keys, false)
	if err != nil {
		t.Fatalf("UnprotectMessage() error = %v", err)
	}
	for _, p := range inner {
		if p.Type != ikev2.PayloadNotify {
			continue
		}
		n, err := ikev2.ParseNotify(p.Body)
		if err != nil || n.NotifyType != ikev2.NotifyDeviceIdentity {
			continue
		}
		// 数据布局 [len(2)][type(1)][BCD(8)]，type 必须是 0x02 且 BCD 是 16 位
		if len(n.NotificationData) < 3 {
			t.Fatalf("device identity data too short: %x", n.NotificationData)
		}
		if got := n.NotificationData[2]; got != ikev2.DeviceIdentityTypeIMEISV {
			t.Fatalf("identity type=%#x, want IMEISV(0x02)", got)
		}
		bcd := n.NotificationData[3:]
		if len(bcd) != 8 {
			t.Fatalf("bcd len=%d, want 8 (16 digits)", len(bcd))
		}
		return
	}
	t.Fatalf("response missing DEVICE_IDENTITY notify")
}
