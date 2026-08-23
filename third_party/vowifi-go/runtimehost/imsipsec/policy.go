// Package imsipsec 实现 3GPP TS 33.203 ipsec-3gpp 安全协商的数据面：
// 在 SWu 内层 IP 包收发路径上对 UE port-c↔P-CSCF port-s（及 port-s↔port-c）
// 的 TCP 流量做 userspace ESP transport-mode 加解密。
//
// 结构参照 1239t/v155 的 internal/vowifi/ipsec3gpp（SecuredDataplane/Transport/
// Policy 三层），加解密原语复用本仓库 engine/swu/esp 的 SA（AES-CBC + HMAC-SHA-1-96）。
package imsipsec

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Mechanism 是 Security-Client/Server/Verify 头里的一个 ipsec-3gpp 机制。
type Mechanism struct {
	Alg   string
	EAlg  string
	Prot  string
	Mode  string
	SPIc  uint32
	SPIs  uint32
	PortC int
	PortS int
}

// ParseMechanism 解析单个机制串（分号参数表）。
func ParseMechanism(raw string) (Mechanism, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Mechanism{}, errors.New("imsipsec: empty mechanism")
	}
	scheme, params, _ := strings.Cut(raw, ";")
	if !strings.EqualFold(strings.TrimSpace(scheme), "ipsec-3gpp") {
		return Mechanism{}, fmt.Errorf("imsipsec: unsupported scheme %q", scheme)
	}
	mech := Mechanism{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Prot: "esp", Mode: "trans"}
	for _, param := range strings.Split(params, ";") {
		key, value, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "alg":
			mech.Alg = canonicalAlg(value)
		case "ealg":
			mech.EAlg = canonicalEAlg(value)
		case "prot":
			mech.Prot = value
		case "mod", "mode":
			mech.Mode = value
		case "spi-c", "spi_c":
			v, err := parseUint32(value)
			if err != nil {
				return Mechanism{}, fmt.Errorf("imsipsec: invalid spi-c: %w", err)
			}
			mech.SPIc = v
		case "spi-s", "spi_s":
			v, err := parseUint32(value)
			if err != nil {
				return Mechanism{}, fmt.Errorf("imsipsec: invalid spi-s: %w", err)
			}
			mech.SPIs = v
		case "port-c", "port_c":
			v, err := strconv.Atoi(value)
			if err == nil {
				mech.PortC = v
			}
		case "port-s", "port_s":
			v, err := strconv.Atoi(value)
			if err == nil {
				mech.PortS = v
			}
		}
	}
	return mech, nil
}

// Flow 描述一个方向的 SA 参数（TS 33.203）。
type Flow struct {
	OutboundSPI uint32
	InboundSPI  uint32
	LocalPort   int
	RemotePort  int
	AuthAlg     string
	EncAlg      string
	CK          []byte
	IK          []byte
}

// Policy 是协商出的完整保护策略：两条 Flow（client 侧 port-c↔port-s、
// server 侧 port-s↔port-c）。
type Policy struct {
	LocalIP  net.IP
	RemoteIP net.IP
	FlowC    Flow
	FlowS    Flow
}

// PolicyInput 由安全协商结果（Security-Client/Server 机制对 + AKA CK/IK）构造。
type PolicyInput struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	ClientMech Mechanism
	ServerMech Mechanism
	CK         []byte
	IK         []byte
}

// NewPolicy 构造 Policy。方向语义（TS 33.203 primary flow）：
// UE port-c → P-CSCF port-s 用 P-CSCF 的 spi-s；回程落在 UE 宣告的 spi-c 上。
func NewPolicy(in PolicyInput) (Policy, error) {
	if len(in.CK) == 0 || len(in.IK) == 0 {
		return Policy{}, errors.New("imsipsec: CK and IK are required")
	}
	client, server := in.ClientMech, in.ServerMech
	if client.SPIc == 0 || client.SPIs == 0 || client.PortC == 0 || client.PortS == 0 {
		return Policy{}, errors.New("imsipsec: client spi/port incomplete")
	}
	if server.SPIc == 0 || server.SPIs == 0 || server.PortC == 0 || server.PortS == 0 {
		return Policy{}, errors.New("imsipsec: server spi/port incomplete")
	}
	authAlg := canonicalAlg(firstNonEmpty(server.Alg, client.Alg))
	encAlg := canonicalEAlg(firstNonEmpty(server.EAlg, client.EAlg))
	if authAlg == "" || encAlg == "" {
		return Policy{}, errors.New("imsipsec: algorithms required")
	}
	if in.LocalIP == nil || in.RemoteIP == nil {
		return Policy{}, errors.New("imsipsec: local/remote IP required")
	}
	ck := append([]byte(nil), in.CK...)
	ik := append([]byte(nil), in.IK...)
	return Policy{
		LocalIP:  append(net.IP(nil), in.LocalIP...),
		RemoteIP: append(net.IP(nil), in.RemoteIP...),
		FlowC: Flow{
			// UE port-c → P-CSCF port-s 使用 P-CSCF spi-s；P-CSCF → UE port-c 落在 UE spi-c。
			OutboundSPI: server.SPIs,
			InboundSPI:  client.SPIc,
			LocalPort:   client.PortC,
			RemotePort:  server.PortS,
			AuthAlg:     authAlg,
			EncAlg:      encAlg,
			CK:          ck,
			IK:          ik,
		},
		FlowS: Flow{
			// UE port-s → P-CSCF port-c（P-CSCF 主动发起的请求）使用 P-CSCF spi-c；
			// 回程落在 UE spi-s。
			OutboundSPI: server.SPIc,
			InboundSPI:  client.SPIs,
			LocalPort:   client.PortS,
			RemotePort:  server.PortC,
			AuthAlg:     authAlg,
			EncAlg:      encAlg,
			CK:          ck,
			IK:          ik,
		},
	}, nil
}

func parseUint32(value string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func canonicalAlg(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "hmac-sha-1-96", "hmac-sha1-96", "sha1":
		return "hmac-sha-1-96"
	case "hmac-md5-96", "hmac-md5", "md5":
		return "hmac-md5-96"
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalEAlg(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "aes-cbc", "aes128-cbc", "aes":
		return "aes-cbc"
	case "des-ede3-cbc", "3des":
		return "des-ede3-cbc"
	case "null":
		return "null"
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
