package imsipsec

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/swu/esp"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	ck := make([]byte, 16)
	ik := make([]byte, 16)
	for i := range ck {
		ck[i] = byte(i + 1)
		ik[i] = byte(i + 0x41)
	}
	client := Mechanism{
		Alg: "hmac-sha-1-96", EAlg: "aes-cbc",
		SPIc: 0x11223344, SPIs: 0x55667788,
		PortC: 50601, PortS: 50600,
	}
	server := Mechanism{
		Alg: "hmac-sha-1-96", EAlg: "aes-cbc",
		SPIc: 0x99aabbcc, SPIs: 0xddeeff00,
		PortC: 50601, PortS: 50600,
	}
	policy, err := NewPolicy(PolicyInput{
		LocalIP:    net.ParseIP("192.168.156.2"),
		RemoteIP:   net.ParseIP("10.128.120.67"),
		ClientMech: client,
		ServerMech: server,
		CK:         ck,
		IK:         ik,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return policy
}

// buildTCPv4Packet 构造 UE port-c → P-CSCF port-s 的 IPv4 TCP 包。
func buildTCPv4Packet(t *testing.T, src net.IP, dst net.IP, srcPort, dstPort int, payloadLen int) []byte {
	t.Helper()
	tcp := make([]byte, 20+payloadLen)
	binary.BigEndian.PutUint16(tcp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	for i := range tcp[20:] {
		tcp[20+i] = byte(i)
	}
	packet := make([]byte, 20+len(tcp))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6 // TCP
	copy(packet[12:16], src.To4())
	copy(packet[16:20], dst.To4())
	copy(packet[20:], tcp)
	totalLen := uint16(len(packet))
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen)
	binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))
	return packet
}

func TestParseMechanismFromWireHeader(t *testing.T) {
	// 2026-08-22 112 实测 Vodafone UK Security-Server 头。
	mech, err := ParseMechanism("ipsec-3gpp;q=0.5;alg=hmac-sha-1-96;prot=esp;mod=trans;ealg=aes-cbc;spi-c=3303352042;spi-s=2316000876;port-c=50601;port-s=50600")
	if err != nil {
		t.Fatalf("ParseMechanism: %v", err)
	}
	if mech.Alg != "hmac-sha-1-96" || mech.EAlg != "aes-cbc" {
		t.Fatalf("alg=%q ealg=%q", mech.Alg, mech.EAlg)
	}
	if mech.SPIc != 3303352042 || mech.SPIs != 2316000876 {
		t.Fatalf("spi-c=%d spi-s=%d", mech.SPIc, mech.SPIs)
	}
	if mech.PortC != 50601 || mech.PortS != 50600 {
		t.Fatalf("port-c=%d port-s=%d", mech.PortC, mech.PortS)
	}
}

func TestNewPolicyFlowSemantics(t *testing.T) {
	policy := testPolicy(t)
	// FlowC（UE port-c→P-CSCF port-s）：出向 SPI=P-CSCF spi-s，入向落 UE spi-c。
	if policy.FlowC.OutboundSPI != 0xddeeff00 {
		t.Fatalf("FlowC.OutboundSPI=%08x want server spi-s", policy.FlowC.OutboundSPI)
	}
	if policy.FlowC.InboundSPI != 0x11223344 {
		t.Fatalf("FlowC.InboundSPI=%08x want client spi-c", policy.FlowC.InboundSPI)
	}
	if policy.FlowC.LocalPort != 50601 || policy.FlowC.RemotePort != 50600 {
		t.Fatalf("FlowC ports %d->%d", policy.FlowC.LocalPort, policy.FlowC.RemotePort)
	}
}

func TestTransformRoundTripFlowC(t *testing.T) {
	transform := NewTransform()
	// Install 前透传。
	plain := buildTCPv4Packet(t, net.ParseIP("192.168.156.2"), net.ParseIP("10.128.120.67"), 50601, 50600, 100)
	if out, err := transform.TransformOutbound(plain); err != nil || &out[0] != &plain[0] {
		t.Fatalf("pre-install outbound should pass through, err=%v", err)
	}
	if err := transform.Install(testPolicy(t)); err != nil {
		t.Fatalf("Install: %v", err)
	}

	out, err := transform.TransformOutbound(plain)
	if err != nil {
		t.Fatalf("TransformOutbound: %v", err)
	}
	if len(out) <= len(plain) {
		t.Fatalf("ESP packet should be larger than plaintext (%d <= %d)", len(out), len(plain))
	}
	if out[9] != ipProtoESP {
		t.Fatalf("next header=%d want ESP", out[9])
	}
	if binary.BigEndian.Uint32(out[20:24]) != 0xddeeff00 {
		t.Fatalf("outbound SPI=%08x want server spi-s", binary.BigEndian.Uint32(out[20:24]))
	}
	if err := verifyIPv4Checksum(out); err != nil {
		t.Fatalf("outbound checksum: %v", err)
	}

	// 远端视角：P-CSCF 以 SPI=UE spi-c、同套 CK/IK 密钥封装回程
	// （src=P-CSCF port-s → dst=UE port-c）。TransformInbound 按 SPI 解封。
	policy := testPolicy(t)
	peerEnc, peerAuth, err := DeriveSecureChannelKeys(policy.FlowC)
	if err != nil {
		t.Fatalf("peer derive: %v", err)
	}
	peerSA, err := esp.NewSA(esp.SA{
		SPI:           policy.FlowC.InboundSPI, // UE 宣告的 spi-c
		EncryptionKey: peerEnc,
		IntegrityKey:  peerAuth,
		Integrity:     esp.IntegrityHMACSHA1_96,
		ICVLength:     12,
		BlockSize:     16,
	})
	if err != nil {
		t.Fatalf("peer SA: %v", err)
	}
	peerESP, err := peerSA.Seal(ipProtoTCP, plain[20:], esp.SealOptions{})
	if err != nil {
		t.Fatalf("peer seal: %v", err)
	}
	// 对端包 = 仅 IP 头（swap 后 src=P-CSCF/dst=UE）+ ESP，协议改 ESP。
	peerHdr := swapAddresses(plain[:20])
	peerHdr[9] = ipProtoESP
	inbound := append(peerHdr, peerESP...)
	binary.BigEndian.PutUint16(inbound[2:4], uint16(len(inbound)))
	binary.BigEndian.PutUint16(inbound[10:12], 0)
	binary.BigEndian.PutUint16(inbound[10:12], ipv4HeaderChecksum(inbound[:20]))
	dec, err := transform.TransformInbound(inbound)
	if err != nil {
		t.Fatalf("TransformInbound: %v", err)
	}
	if dec[9] != ipProtoTCP {
		t.Fatalf("decapsulated next header=%d want TCP", dec[9])
	}
	if len(dec) != len(plain) {
		t.Fatalf("decapsulated len=%d want %d", len(dec), len(plain))
	}
	if string(dec[20:]) != string(plain[20:]) {
		t.Fatalf("TCP payload mismatch after round trip")
	}
	if err := verifyIPv4Checksum(dec); err != nil {
		t.Fatalf("inbound checksum: %v", err)
	}
}

func TestTransformPassthroughUnmatched(t *testing.T) {
	transform := NewTransform()
	if err := transform.Install(testPolicy(t)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// 非 port-c/port-s 的 TCP 流量透传。
	other := buildTCPv4Packet(t, net.ParseIP("192.168.156.2"), net.ParseIP("10.128.120.67"), 40000, 80, 50)
	out, err := transform.TransformOutbound(other)
	if err != nil {
		t.Fatalf("TransformOutbound: %v", err)
	}
	if string(out) != string(other) {
		t.Fatalf("unmatched TCP flow must pass through unchanged")
	}
	// 其他目的 IP 透传。
	far := buildTCPv4Packet(t, net.ParseIP("192.168.156.2"), net.ParseIP("8.8.8.8"), 50601, 50600, 50)
	if out, err := transform.TransformOutbound(far); err != nil || string(out) != string(far) {
		t.Fatalf("traffic to other IP must pass through, err=%v", err)
	}
	// UDP 非选择器端口（如 DNS）透传。
	udp := buildTCPv4Packet(t, net.ParseIP("192.168.156.2"), net.ParseIP("10.128.120.67"), 40000, 53, 50)
	udp[9] = ipProtoUDP
	if out, err := transform.TransformOutbound(udp); err != nil || string(out) != string(udp) {
		t.Fatalf("UDP outside selector ports must pass through, err=%v", err)
	}
	// UDP 命中选择器端口（UDP SIP 模式）也封装为 ESP。
	udpSIP := buildTCPv4Packet(t, net.ParseIP("192.168.156.2"), net.ParseIP("10.128.120.67"), 50601, 50600, 50)
	udpSIP[9] = ipProtoUDP
	enc, err := transform.TransformOutbound(udpSIP)
	if err != nil {
		t.Fatalf("UDP in selector ports must be encapsulated, err=%v", err)
	}
	if enc[9] != ipProtoESP {
		t.Fatalf("UDP SIP next header=%d want ESP", enc[9])
	}
	// 非 ESP 入向透传。
	plain := buildTCPv4Packet(t, net.ParseIP("10.128.120.67"), net.ParseIP("192.168.156.2"), 50600, 50601, 40)
	if out, err := transform.TransformInbound(plain); err != nil || string(out) != string(plain) {
		t.Fatalf("non-ESP inbound must pass through, err=%v", err)
	}
}

func TestInstallTwiceRejectedAndClear(t *testing.T) {
	transform := NewTransform()
	if err := transform.Install(testPolicy(t)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := transform.Install(testPolicy(t)); err == nil {
		t.Fatalf("double Install must be rejected")
	}
	transform.Clear()
	if transform.Installed() {
		t.Fatalf("Installed after Clear")
	}
	if err := transform.Install(testPolicy(t)); err != nil {
		t.Fatalf("Install after Clear: %v", err)
	}
}

func swapAddresses(packet []byte) []byte {
	out := append([]byte(nil), packet...)
	src := append([]byte(nil), out[12:16]...)
	dst := append([]byte(nil), out[16:20]...)
	copy(out[12:16], dst)
	copy(out[16:20], src)
	// 头变化后重算校验和（TransformInbound 校验前不检查校验和，但保持正确）。
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], ipv4HeaderChecksum(out[:20]))
	return out
}

// fixESPHeaderAfterSPIRewrite 在测试改写 SPI 后重算 IP 头校验和
// （SPI 位于 payload 内，头字段未变，仅源/目的已在 swap 时重算）。
func fixESPHeaderAfterSPIRewrite(packet []byte) []byte {
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))
	return packet
}

func verifyIPv4Checksum(packet []byte) error {
	if len(packet) < 20 {
		return errString("short header")
	}
	if binary.BigEndian.Uint16(packet[10:12]) != ipv4HeaderChecksum(packet[:20]) {
		// ipv4HeaderChecksum 计算含校验和字段为已置零值；直接重算对比需先清零副本。
		hdr := append([]byte(nil), packet[:20]...)
		hdr[10], hdr[11] = 0, 0
		if binary.BigEndian.Uint16(packet[10:12]) != ipv4HeaderChecksum(hdr) {
			return errString("checksum mismatch")
		}
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

var _ = strings.TrimSpace

// testPolicyWithAlgs 按指定算法组合构造策略（算法矩阵测试用）。
func testPolicyWithAlgs(t *testing.T, alg, ealg string) Policy {
	t.Helper()
	ck := make([]byte, 16)
	ik := make([]byte, 16)
	for i := range ck {
		ck[i] = byte(i + 1)
		ik[i] = byte(i + 0x41)
	}
	client := Mechanism{
		Alg: alg, EAlg: ealg,
		SPIc: 0x11223344, SPIs: 0x55667788,
		PortC: 50601, PortS: 50600,
	}
	server := Mechanism{
		Alg: alg, EAlg: ealg,
		SPIc: 0x99aabbcc, SPIs: 0xddeeff00,
		PortC: 50601, PortS: 50600,
	}
	policy, err := NewPolicy(PolicyInput{
		LocalIP:    net.ParseIP("192.168.156.2"),
		RemoteIP:   net.ParseIP("10.128.120.67"),
		ClientMech: client,
		ServerMech: server,
		CK:         ck,
		IK:         ik,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return policy
}

// TestTransformRoundTripAlgorithmMatrix 换运营商硬前提：TS 33.203 全部
// 协商组合的二层 ESP 往返（出向封装 + 对端视角入向解封）。
func TestTransformRoundTripAlgorithmMatrix(t *testing.T) {
	cases := []struct {
		name string
		alg  string
		ealg string
	}{
		{"sha1-96+aes-cbc", "hmac-sha-1-96", "aes-cbc"},   // Vodafone UK 现役
		{"md5-96+aes-cbc", "hmac-md5-96", "aes-cbc"},     //
		{"sha1-96+3des", "hmac-sha-1-96", "des-ede3-cbc"}, //
		{"md5-96+3des", "hmac-md5-96", "des-ede3-cbc"},    //
		{"sha1-96+null", "hmac-sha-1-96", "null"},         //
		{"md5-96+null", "hmac-md5-96", "null"},            //
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := testPolicyWithAlgs(t, tc.alg, tc.ealg)
			transform := NewTransform()
			if err := transform.Install(policy); err != nil {
				t.Fatalf("Install: %v", err)
			}
			plain := buildTCPv4Packet(t, net.ParseIP("192.168.156.2"), net.ParseIP("10.128.120.67"), 50601, 50600, 100)
			out, err := transform.TransformOutbound(plain)
			if err != nil {
				t.Fatalf("TransformOutbound: %v", err)
			}
			if out[9] != ipProtoESP {
				t.Fatalf("next header=%d want ESP", out[9])
			}
			if binary.BigEndian.Uint32(out[20:24]) != policy.FlowC.OutboundSPI {
				t.Fatalf("outbound SPI=%08x want %08x", binary.BigEndian.Uint32(out[20:24]), policy.FlowC.OutboundSPI)
			}
			// 对端视角：P-CSCF 用 UE 宣告的 spi-c + 同套密钥封装回程。
			peerEnc, peerAuth, err := DeriveSecureChannelKeys(policy.FlowC)
			if err != nil {
				t.Fatalf("peer derive: %v", err)
			}
			cipher, blockSize := espCipher(tc.ealg)
			peerSA, err := esp.NewSA(esp.SA{
				SPI:           policy.FlowC.InboundSPI,
				EncryptionKey: peerEnc,
				IntegrityKey:  peerAuth,
				Integrity:     espIntegrity(tc.alg),
				Cipher:        cipher,
				ICVLength:     12,
				BlockSize:     blockSize,
			})
			if err != nil {
				t.Fatalf("peer SA: %v", err)
			}
			peerESP, err := peerSA.Seal(ipProtoTCP, plain[20:], esp.SealOptions{})
			if err != nil {
				t.Fatalf("peer seal: %v", err)
			}
			peerHdr := swapAddresses(plain[:20])
			peerHdr[9] = ipProtoESP
			inbound := append(peerHdr, peerESP...)
			binary.BigEndian.PutUint16(inbound[2:4], uint16(len(inbound)))
			binary.BigEndian.PutUint16(inbound[10:12], 0)
			binary.BigEndian.PutUint16(inbound[10:12], ipv4HeaderChecksum(inbound[:20]))
			dec, err := transform.TransformInbound(inbound)
			if err != nil {
				t.Fatalf("TransformInbound: %v", err)
			}
			if dec[9] != ipProtoTCP || len(dec) != len(plain) || string(dec[20:]) != string(plain[20:]) {
				t.Fatalf("round trip mismatch: nextHeader=%d len=%d", dec[9], len(dec))
			}
		})
	}
}

// TestTransformRoundTripFlowS 验证 FlowS 方向（P-CSCF 主动发起的请求通道）：
// UE port-s → P-CSCF port-c 出向封装（SPI=P-CSCF spi-c），P-CSCF → UE port-s
// 回程解封（SPI=UE spi-s）。来话 INVITE 的通道前提（业务处理在 V4 语音阶段）。
func TestTransformRoundTripFlowS(t *testing.T) {
	policy := testPolicy(t)
	transform := NewTransform()
	if err := transform.Install(policy); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// UE port-s → P-CSCF port-c。
	plain := buildTCPv4Packet(t, net.ParseIP("192.168.156.2"), net.ParseIP("10.128.120.67"), 50600, 50601, 80)
	out, err := transform.TransformOutbound(plain)
	if err != nil {
		t.Fatalf("TransformOutbound: %v", err)
	}
	if out[9] != ipProtoESP {
		t.Fatalf("next header=%d want ESP", out[9])
	}
	if binary.BigEndian.Uint32(out[20:24]) != policy.FlowS.OutboundSPI {
		t.Fatalf("outbound SPI=%08x want server spi-c %08x", binary.BigEndian.Uint32(out[20:24]), policy.FlowS.OutboundSPI)
	}
	if err := verifyIPv4Checksum(out); err != nil {
		t.Fatalf("outbound checksum: %v", err)
	}

	// 对端视角：P-CSCF 用 UE 宣告的 spi-s + 同套密钥封装 port-c → port-s 回程。
	peerEnc, peerAuth, err := DeriveSecureChannelKeys(policy.FlowS)
	if err != nil {
		t.Fatalf("peer derive: %v", err)
	}
	peerSA, err := esp.NewSA(esp.SA{
		SPI:           policy.FlowS.InboundSPI, // UE 宣告的 spi-s
		EncryptionKey: peerEnc,
		IntegrityKey:  peerAuth,
		Integrity:     esp.IntegrityHMACSHA1_96,
		Cipher:        esp.CipherAES128CBC,
		ICVLength:     12,
		BlockSize:     16,
	})
	if err != nil {
		t.Fatalf("peer SA: %v", err)
	}
	peerESP, err := peerSA.Seal(ipProtoTCP, plain[20:], esp.SealOptions{})
	if err != nil {
		t.Fatalf("peer seal: %v", err)
	}
	peerHdr := swapAddresses(plain[:20])
	peerHdr[9] = ipProtoESP
	inbound := append(peerHdr, peerESP...)
	binary.BigEndian.PutUint16(inbound[2:4], uint16(len(inbound)))
	binary.BigEndian.PutUint16(inbound[10:12], 0)
	binary.BigEndian.PutUint16(inbound[10:12], ipv4HeaderChecksum(inbound[:20]))
	dec, err := transform.TransformInbound(inbound)
	if err != nil {
		t.Fatalf("TransformInbound: %v", err)
	}
	if dec[9] != ipProtoTCP || len(dec) != len(plain) || string(dec[20:]) != string(plain[20:]) {
		t.Fatalf("round trip mismatch: nextHeader=%d len=%d", dec[9], len(dec))
	}
}
