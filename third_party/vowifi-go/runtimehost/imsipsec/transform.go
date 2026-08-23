package imsipsec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/iniwex5/vowifi-go/engine/swu/esp"
)

func debugEnabled() bool { return os.Getenv("SWU_DEBUG_IMSIPSEC") != "" }

// debugTraceNoMatch 排查选择器未命中：打印包五元组与策略期望值。
func debugTraceNoMatch(dir string, p parsedIP, policy *Policy) {
	if !debugEnabled() {
		return
	}
	fmt.Fprintf(os.Stderr, "[imsipsec] %s NO-MATCH %s:%d -> %s:%d (want %s:%d -> %s:%d | %s:%d -> %s:%d)\n",
		dir, p.src, p.srcPort, p.dst, p.dstPort,
		policy.LocalIP, policy.FlowC.LocalPort, policy.RemoteIP, policy.FlowC.RemotePort,
		policy.LocalIP, policy.FlowS.LocalPort, policy.RemoteIP, policy.FlowS.RemotePort)
}

const (
	ipProtoTCP uint8 = 6
	ipProtoESP uint8 = 50
)

// Transform 对完整 IP 包做 ESP transport-mode 加解密（IMS ipsec-3gpp 数据面）。
// Install 之前完全透传；Install 后仅命中 port-c/port-s 选择器的 TCP 包被封装，
// 其余流量（DNS、IKE 探测、其他连接）不受影响。
//
// 并发模型：transform 由 swu PacketPump 双向两个 goroutine 调用，
// Install/Clear 由 IMS 注册协程触发——用 RWMutex 做原子换装。
type Transform struct {
	mu      sync.RWMutex
	policy  *Policy
	outC    *esp.SA
	outS    *esp.SA
	inC     *esp.SA
	inS     *esp.SA
	inbound map[uint32]*esp.SA
}

// NewTransform 创建空 Transform（纯透传），随后 Install 启用协商出的策略。
func NewTransform() *Transform {
	return &Transform{}
}

// Installed 报告当前是否已安装策略。
func (t *Transform) Installed() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.policy != nil
}

// Install 原子启用一条策略（重复 Install 直接拒绝——TS 33.203 一套 SA 生命周期内不换）。
func (t *Transform) Install(policy Policy) error {
	outC, err := flowOutboundSA(policy.FlowC)
	if err != nil {
		return fmt.Errorf("flow-c outbound: %w", err)
	}
	outS, err := flowOutboundSA(policy.FlowS)
	if err != nil {
		return fmt.Errorf("flow-s outbound: %w", err)
	}
	inC, err := flowInboundSA(policy.FlowC)
	if err != nil {
		return fmt.Errorf("flow-c inbound: %w", err)
	}
	inS, err := flowInboundSA(policy.FlowS)
	if err != nil {
		return fmt.Errorf("flow-s inbound: %w", err)
	}
	// 入向 SPI 兼容两类 P-CSCF 实现（112 设备实测 Vodafone UK 用后者）：
	// a) 标准 TS 33.203：P-CSCF 回程落 UE 宣告的 spi-c/spi-s；
	// b) 对称单 SA：P-CSCF 直接用自己宣告的 spi-s/spi-c 封装回程（与 UE 出向
	//    同 SPI 同密钥，seq 空间独立——须各自独立 SA 实例防重放窗口串扰）。
	inbound := map[uint32]*esp.SA{
		policy.FlowC.InboundSPI: inC,
		policy.FlowS.InboundSPI: inS,
	}
	if _, exists := inbound[policy.FlowC.OutboundSPI]; !exists {
		inbound[policy.FlowC.OutboundSPI], err = flowInboundSA(policy.FlowC)
		if err != nil {
			return fmt.Errorf("flow-c inbound (sym): %w", err)
		}
	}
	if _, exists := inbound[policy.FlowS.OutboundSPI]; !exists {
		inbound[policy.FlowS.OutboundSPI], err = flowInboundSA(policy.FlowS)
		if err != nil {
			return fmt.Errorf("flow-s inbound (sym): %w", err)
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.policy != nil {
		return errors.New("imsipsec: policy already installed")
	}
	t.policy = &policy
	t.outC = outC
	t.outS = outS
	t.inC = inC
	t.inS = inS
	t.inbound = inbound
	return nil
}

// Clear 摘除策略回到透传（REGISTER 会话终止/重协商时）。
func (t *Transform) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.policy = nil
	t.outC, t.outS, t.inC, t.inS = nil, nil, nil, nil
	t.inbound = nil
}

func flowOutboundSA(flow Flow) (*esp.SA, error) {
	encKey, authKey, err := DeriveSecureChannelKeys(flow)
	if err != nil {
		return nil, err
	}
	return esp.NewSA(esp.SA{
		SPI:              flow.OutboundSPI,
		EncryptionKey:    encKey,
		IntegrityKey:     authKey,
		Integrity:        espIntegrity(flow.AuthAlg),
		ICVLength:        12,
		BlockSize:        16,
		ReplayWindowSize: 0, // UE→P-CSCF 出向无需防重放窗口
	})
}

func flowInboundSA(flow Flow) (*esp.SA, error) {
	encKey, authKey, err := DeriveSecureChannelKeys(flow)
	if err != nil {
		return nil, err
	}
	return esp.NewSA(esp.SA{
		SPI:              flow.InboundSPI,
		EncryptionKey:    encKey,
		IntegrityKey:     authKey,
		Integrity:        espIntegrity(flow.AuthAlg),
		ICVLength:        12,
		BlockSize:        16,
		ReplayWindowSize: 64,
	})
}

// DeriveSecureChannelKeys 从 CK/IK 派生 ESP 密钥（TS 33.203：CK→加密、IK→完整性）。
func DeriveSecureChannelKeys(flow Flow) (encKey, authKey []byte, err error) {
	switch canonicalEAlg(flow.EncAlg) {
	case "aes-cbc":
		if len(flow.CK) < 16 {
			return nil, nil, errors.New("CK too short for AES-CBC")
		}
		encKey = append([]byte(nil), flow.CK[:16]...)
	case "des-ede3-cbc":
		if len(flow.CK) < 16 {
			return nil, nil, errors.New("CK too short for 3DES")
		}
		key := make([]byte, 24)
		copy(key[0:8], flow.CK[0:8])
		copy(key[8:16], flow.CK[8:16])
		copy(key[16:24], flow.CK[0:8])
		for i := range key {
			key[i] = setDESOddParityByte(key[i])
		}
		encKey = key
	default:
		return nil, nil, fmt.Errorf("unsupported enc alg %q", flow.EncAlg)
	}
	switch canonicalAlg(flow.AuthAlg) {
	case "hmac-sha-1-96":
		if len(flow.IK) < 16 {
			return nil, nil, errors.New("IK too short for HMAC-SHA-1-96")
		}
		key := make([]byte, 20)
		copy(key, flow.IK[:16])
		authKey = key
	case "hmac-md5-96":
		if len(flow.IK) < 16 {
			return nil, nil, errors.New("IK too short for HMAC-MD5-96")
		}
		authKey = append([]byte(nil), flow.IK[:16]...)
	default:
		return nil, nil, fmt.Errorf("unsupported auth alg %q", flow.AuthAlg)
	}
	return encKey, authKey, nil
}

func setDESOddParityByte(b byte) byte {
	parity := byte(0)
	for i := 0; i < 7; i++ {
		if b&(1<<uint(i)) != 0 {
			parity ^= 1
		}
	}
	if parity == 0 {
		b |= 1 << 7
	} else {
		b &^= 1 << 7
	}
	return b
}

func espIntegrity(alg string) esp.IntegrityAlgorithm {
	// engine/swu/esp 只实现 SHA1-96/SHA2-256-128。Vodafone UK 实测协商
	// hmac-sha-1-96（设备日志 Security-Server 实证），MD5-96 分支按 SHA1 处理
	// 不可达；若他网协商 MD5 需先给 esp 包补 HMAC-MD5-96。
	return esp.IntegrityHMACSHA1_96
}

// TransformOutbound 对出向 IP 包（UE→P-CSCF）做 ESP transport 封装；未命中透传。
func (t *Transform) TransformOutbound(packet []byte) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.policy == nil {
		return packet, nil
	}
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.nextHeader != ipProtoTCP {
		return packet, nil
	}
	var sa *esp.SA
	switch {
	case matchFlow(parsed, t.policy.LocalIP, t.policy.RemoteIP, t.policy.FlowC.LocalPort, t.policy.FlowC.RemotePort):
		sa = t.outC
	case matchFlow(parsed, t.policy.LocalIP, t.policy.RemoteIP, t.policy.FlowS.LocalPort, t.policy.FlowS.RemotePort):
		sa = t.outS
	default:
		debugTraceNoMatch("out", parsed, t.policy)
		return packet, nil
	}
	espPacket, err := sa.Seal(ipProtoTCP, parsed.transport, esp.SealOptions{})
	if err != nil {
		return nil, fmt.Errorf("imsipsec: seal spi 0x%08x: %w", sa.SPI, err)
	}
	out := replaceIPPayload(parsed, espPacket, ipProtoESP)
	if debugEnabled() {
		fmt.Fprintf(os.Stderr, "[imsipsec] out matched %s:%d -> %s:%d spi=%08x plain=%dB esp=%dB\n",
			parsed.src, parsed.srcPort, parsed.dst, parsed.dstPort, sa.SPI, len(parsed.transport), len(out))
	}
	return out, nil
}

// TransformInbound 对入向 IP 包做 ESP transport 解封装；非 ESP 或 SPI 未知透传。
func (t *Transform) TransformInbound(packet []byte) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.policy == nil {
		return packet, nil
	}
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.nextHeader != ipProtoESP {
		return packet, nil
	}
	if len(parsed.transport) < 8 {
		return packet, nil
	}
	spi := binary.BigEndian.Uint32(parsed.transport[:4])
	sa, ok := t.inbound[spi]
	if !ok {
		if debugEnabled() {
			fmt.Fprintf(os.Stderr, "[imsipsec] in NO-MATCH %s -> %s spi=%08x len=%dB\n",
				parsed.src, parsed.dst, spi, len(parsed.transport))
		}
		return packet, nil
	}
	open, err := sa.Open(parsed.transport)
	if err != nil {
		return nil, fmt.Errorf("imsipsec: open spi 0x%08x: %w", spi, err)
	}
	if open.NextHeader != ipProtoTCP {
		return packet, nil
	}
	if debugEnabled() {
		fmt.Fprintf(os.Stderr, "[imsipsec] in matched %s -> %s spi=%08x plain=%dB\n",
			parsed.src, parsed.dst, spi, len(open.Payload))
	}
	return replaceIPPayload(parsed, open.Payload, ipProtoTCP), nil
}

type parsedIP struct {
	header     []byte
	transport  []byte
	src        net.IP
	dst        net.IP
	srcPort    int
	dstPort    int
	nextHeader uint8
}

func parseIPPacket(packet []byte) (parsedIP, bool) {
	if len(packet) < 20 {
		return parsedIP{}, false
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return parsedIP{}, false
		}
		out := parsedIP{
			header:     packet[:ihl],
			transport:  packet[ihl:],
			src:        net.IP(append(net.IP(nil), packet[12:16]...)),
			dst:        net.IP(append(net.IP(nil), packet[16:20]...)),
			nextHeader: packet[9],
		}
		if out.nextHeader == ipProtoTCP && len(out.transport) >= 4 {
			out.srcPort = int(binary.BigEndian.Uint16(out.transport[:2]))
			out.dstPort = int(binary.BigEndian.Uint16(out.transport[2:4]))
		}
		return out, true
	case 6:
		if len(packet) < 40 {
			return parsedIP{}, false
		}
		out := parsedIP{
			header:     packet[:40],
			transport:  packet[40:],
			src:        net.IP(append(net.IP(nil), packet[8:24]...)),
			dst:        net.IP(append(net.IP(nil), packet[24:40]...)),
			nextHeader: packet[6],
		}
		if out.nextHeader == ipProtoTCP && len(out.transport) >= 4 {
			out.srcPort = int(binary.BigEndian.Uint16(out.transport[:2]))
			out.dstPort = int(binary.BigEndian.Uint16(out.transport[2:4]))
		}
		return out, true
	}
	return parsedIP{}, false
}

func matchFlow(p parsedIP, localIP, remoteIP net.IP, localPort, remotePort int) bool {
	return p.src.Equal(localIP) && p.dst.Equal(remoteIP) &&
		p.srcPort == localPort && p.dstPort == remotePort
}

// replaceIPPayload 重建 IP 包（原头 + 新 payload），重写协议/长度字段并重算校验和。
func replaceIPPayload(p parsedIP, payload []byte, nextHeader uint8) []byte {
	out := make([]byte, 0, len(p.header)+len(payload))
	out = append(out, p.header...)
	out = append(out, payload...)
	switch len(p.header) {
	case 20:
		out[9] = nextHeader
		totalLen := uint16(20 + len(payload))
		out[2] = byte(totalLen >> 8)
		out[3] = byte(totalLen)
		// tun 设备对写入包做首部校验和校验，置零后重算。
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], ipv4HeaderChecksum(out[:20]))
	case 40:
		out[6] = nextHeader
		payloadLen := uint16(len(payload))
		out[4] = byte(payloadLen >> 8)
		out[5] = byte(payloadLen)
	}
	return out
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
