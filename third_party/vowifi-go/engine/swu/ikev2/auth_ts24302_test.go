package ikev2

import (
	"bytes"
	"testing"
)

func TestEncodeDeviceIdentityBCD(t *testing.T) {
	// 与 vowifi_gateway encode_device_identity_notification_data 逐字节对齐：
	// 偶数索引数字在低半字节；IMEI 补 F 凑 16 位后，末字节为 0xF7。
	got := encodeDeviceIdentityBCD("123456789012347")
	want := []byte{0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf7}
	if !bytes.Equal(got, want) {
		t.Fatalf("BCD=%x want=%x", got, want)
	}
}

func TestDeviceIdentityMarshal(t *testing.T) {
	// vowifi_gateway swu_ike.py L2123-2147 格式：[2B 总长][类型][BCD]。
	d := DeviceIdentity{IdentityType: DeviceIdentityTypeIMEI, Value: "123456789012347"}
	raw, err := d.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if len(raw) != 11 {
		t.Fatalf("length=%d want 11 (2+1+8)", len(raw))
	}
	if raw[0] != 0 || raw[1] != 11 || raw[2] != 0x01 {
		t.Fatalf("header=%x", raw[:3])
	}
	if !bytes.Equal(raw[3:], []byte{0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf7}) {
		t.Fatalf("bcd=%x", raw[3:])
	}
	if _, err := (DeviceIdentity{IdentityType: DeviceIdentityTypeIMEI, Value: "12345"}).MarshalBinary(); err == nil {
		t.Fatal("short IMEI should fail")
	}
	if _, err := (DeviceIdentity{IdentityType: 0x99, Value: "123456789012345"}).MarshalBinary(); err == nil {
		t.Fatal("unknown type should fail")
	}
}

func TestDeviceIdentityNotifyRoundtrip(t *testing.T) {
	payload, err := DeviceIdentityNotify(DeviceIdentity{IdentityType: DeviceIdentityTypeIMEI, Value: "123456789012347"})
	if err != nil {
		t.Fatalf("DeviceIdentityNotify() error = %v", err)
	}
	notify, err := ParseNotify(payload.Body)
	if err != nil {
		t.Fatalf("ParseNotify() error = %v", err)
	}
	if notify.NotifyType != NotifyDeviceIdentity {
		t.Fatalf("notify type=%d", notify.NotifyType)
	}
	if len(notify.NotificationData) != 11 || notify.NotificationData[2] != 0x01 {
		t.Fatalf("data=%x", notify.NotificationData)
	}
}

func TestSWuConfigurationRequestForCPMode(t *testing.T) {
	v4 := SWuConfigurationRequestForCPMode("v4")
	if v4.Type != CFGRequest || len(v4.Attributes) != 3 {
		t.Fatalf("v4=%+v", v4)
	}
	for i, want := range []uint16{ConfigInternalIPv4Address, ConfigInternalIPv4DNS, ConfigInternalIPv4Pcscf} {
		if v4.Attributes[i].Type != want {
			t.Fatalf("v4 attr[%d]=%d want %d", i, v4.Attributes[i].Type, want)
		}
	}
	v6 := SWuConfigurationRequestForCPMode("v6")
	for i, want := range []uint16{ConfigInternalIPv6Address, ConfigInternalIPv6DNS, ConfigInternalIPv6Pcscf} {
		if v6.Attributes[i].Type != want {
			t.Fatalf("v6 attr[%d]=%d want %d", i, v6.Attributes[i].Type, want)
		}
	}
	dual := SWuConfigurationRequestForCPMode("dual")
	if len(dual.Attributes) != 6 || dual.Attributes[0].Type != ConfigInternalIPv4Address || dual.Attributes[2].Type != ConfigInternalIPv4Pcscf {
		t.Fatalf("dual=%+v", dual)
	}
}

func TestNotify3GGPNames(t *testing.T) {
	cases := map[uint16]string{
		9000:  "3GPP_GENERIC_ATTACH_REJECTION",
		9001:  "3GPP_ILLEGAL_UE",
		16375: "3GPP_PRIVATE_16375 (Vodafone UK IPv4-only IMS hint)",
	}
	for typ, want := range cases {
		if got := NotifyTypeName(typ); got != want {
			t.Fatalf("NotifyTypeName(%d)=%q want %q", typ, got, want)
		}
	}
	if !Is3GGPAttachRejectNotify(9000) || !Is3GGPAttachRejectNotify(16375) || Is3GGPAttachRejectNotify(16384) {
		t.Fatal("Is3GGPAttachRejectNotify misclassifies")
	}
}

func TestAuthNotifyErrorSurfacesReject(t *testing.T) {
	// FAILED_CP_REQUIRED 的 NOTIFY 必须被识别为错误。
	n, _ := (Notify{NotifyType: NotifyFailedCPRequired}).MarshalBinary()
	inner := []Payload{{Type: PayloadNotify, Body: n}}
	if err := authNotifyError(inner); err == nil {
		t.Fatal("authNotifyError should surface FAILED_CP_REQUIRED")
	}
	// INITIAL_CONTACT 等状态通知不应报错。
	ok, _ := (Notify{NotifyType: NotifyInitialContact}).MarshalBinary()
	if err := authNotifyError([]Payload{{Type: PayloadNotify, Body: ok}}); err != nil {
		t.Fatalf("status notify should not error: %v", err)
	}
}

func TestComputeInitiatorAUTHShape(t *testing.T) {
	init, keys := fakeInitAuthMaterial(t)
	id := Identity{Type: IDRFC822Addr, Data: []byte("0234159876543210@nai.epc.mnc015.mcc234.3gppnetwork.org")}
	payload, err := computeInitiatorAUTH(init, keys, id, bytes.Repeat([]byte{0x5a}, 64))
	if err != nil {
		t.Fatalf("computeInitiatorAUTH() error = %v", err)
	}
	if payload.Type != PayloadAUTH {
		t.Fatalf("payload type=%d", payload.Type)
	}
	if len(payload.Body) < 4+keys.Profile.PRF.Size() {
		t.Fatalf("auth body length=%d", len(payload.Body))
	}
	if payload.Body[0] != 2 {
		t.Fatalf("method=%d want 2 (SHARED_KEY_MESSAGE_INTEGRITY_CODE)", payload.Body[0])
	}
	// AUTH 对 MSK 敏感：换 MSK 必须变。
	payload2, err := computeInitiatorAUTH(init, keys, id, bytes.Repeat([]byte{0x5b}, 64))
	if err != nil {
		t.Fatalf("computeInitiatorAUTH() error = %v", err)
	}
	if bytes.Equal(payload.Body, payload2.Body) {
		t.Fatal("AUTH should depend on MSK")
	}
}

func fakeInitAuthMaterial(t *testing.T) (InitResult, IKEKeys) {
	t.Helper()
	sa := DefaultIKEProposal()
	profile, err := KeyMaterialProfileFromSA(sa)
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys := IKEKeys{
		Profile: profile,
		SKD:     bytes.Repeat([]byte{0x01}, profile.PRFKeyLength),
		SKAi:    bytes.Repeat([]byte{0x02}, profile.IntegrityKeyLength),
		SKAr:    bytes.Repeat([]byte{0x03}, profile.IntegrityKeyLength),
		SKEi:    bytes.Repeat([]byte{0x04}, profile.EncryptionKeyLength),
		SKEr:    bytes.Repeat([]byte{0x05}, profile.EncryptionKeyLength),
		SKPi:    bytes.Repeat([]byte{0x06}, profile.PRFKeyLength),
		SKPr:    bytes.Repeat([]byte{0x07}, profile.PRFKeyLength),
	}
	init := InitResult{
		InitiatorSPI: 0x1122334455667788,
		ResponderSPI: 0x8877665544332211,
		NonceI:       bytes.Repeat([]byte{0xa1}, 32),
		NonceR:       bytes.Repeat([]byte{0xb2}, 32),
		RequestBytes: bytes.Repeat([]byte{0xc3}, 100),
	}
	return init, keys
}

func TestDeviceIdentityNotifyIs41101(t *testing.T) {
	// TS 24.302 Table 8.1.2.3-1: DEVICE_IDENTITY = 41101（私有状态区间）。
	// 之前误用 12345 落在错误通知区间（<16384），会被 ePDG 当错误通知处理。
	if NotifyDeviceIdentity != 41101 {
		t.Fatalf("NotifyDeviceIdentity=%d want 41101", NotifyDeviceIdentity)
	}
	payload, err := DeviceIdentityNotify(DeviceIdentity{IdentityType: DeviceIdentityTypeIMEI, Value: "123456789012347"})
	if err != nil {
		t.Fatalf("DeviceIdentityNotify() error = %v", err)
	}
	notify, err := ParseNotify(payload.Body)
	if err != nil {
		t.Fatalf("ParseNotify() error = %v", err)
	}
	if notify.NotifyType != 41101 {
		t.Fatalf("wire notify type=%d want 41101", notify.NotifyType)
	}
	// 状态通知（>=16384 或 3GPP 私有状态区间）不得被归类为错误。
	if err := notifyErrorClass(41101); err != nil {
		t.Fatalf("41101 misclassified as error: %v", err)
	}
}

func TestAnswerDeviceIdentityRequest(t *testing.T) {
	dev := &DeviceIdentity{IdentityType: DeviceIdentityTypeIMEI, Value: "123456789012347"}

	// ePDG 未请求 → nil
	noReq := []Payload{EAPNotifyPayloadForTest(t, 16384)}
	if got := answerDeviceIdentityRequest(noReq, dev); got != nil {
		t.Fatalf("unrequested answer=%v", got)
	}

	// ePDG 请求（空数据 notify，类型默认 IMEI）→ 应答
	req := []Payload{EAPNotifyPayloadForTest(t, NotifyDeviceIdentity)}
	got := answerDeviceIdentityRequest(req, dev)
	if got == nil {
		t.Fatal("requested but no answer")
	}
	notify, err := ParseNotify(got.Body)
	if err != nil {
		t.Fatalf("ParseNotify() error = %v", err)
	}
	if notify.NotifyType != 41101 || len(notify.NotificationData) == 0 || notify.NotificationData[2] != 0x01 {
		t.Fatalf("answer notify=%+v data=%x", notify, notify.NotificationData)
	}

	// 本地无 IMEI → nil
	if got := answerDeviceIdentityRequest(req, nil); got != nil {
		t.Fatalf("nil identity answer=%v", got)
	}
}

func EAPNotifyPayloadForTest(t *testing.T, notifyType uint16) Payload {
	t.Helper()
	body, err := (Notify{NotifyType: notifyType}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return Payload{Type: PayloadNotify, Body: body}
}
