package voiceclient

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	DefaultSecurityProtocol  = "ipsec-3gpp"
	DefaultSecurityAlgorithm = "hmac-sha-1-96"
	// ealg=aes-cbc（对齐 v155/参考实现 offer）：Vodafone UK P-CSCF 协商选择
	// ealg=aes-cbc，offer ealg=null 的首个 REGISTER 被实测静默丢弃（零响应）。
	DefaultSecurityEAlg      = "aes-cbc"
	DefaultSecurityProt      = "esp"
	DefaultSecurityMod       = "trans"
	DefaultSecurityPortC     = 5062
	DefaultSecurityPortS     = 5063
)

type SecurityAgreement struct {
	Protocol            string
	Algorithm           string
	EncryptionAlgorithm string
	Prot                string
	Mod                 string
	SPIClient           uint32
	SPIServer           uint32
	PortClient          int
	PortServer          int
	Parameters          map[string]string
	Raw                 string
}

func DefaultSecurityClientAgreement(random io.Reader) SecurityAgreement {
	if random == nil {
		random = cryptorand.Reader
	}
	return SecurityAgreement{
		Protocol:            DefaultSecurityProtocol,
		Algorithm:           DefaultSecurityAlgorithm,
		EncryptionAlgorithm: DefaultSecurityEAlg,
		SPIClient:           randomSecuritySPI(random),
		SPIServer:           randomSecuritySPI(random),
		PortClient:          DefaultSecurityPortC,
		PortServer:          DefaultSecurityPortS,
	}
}

// BuildSecurityClientMultiMechanismHeader 渲染 1239t default 的 6 机制逗号列表
// （DefaultSecurityClientMechanisms：md5/des、md5/aes、md5/null、sha1/des、sha1/aes、sha1/null），
// 共用同一对 spi/port。P-CSCF 从中协商选择（Vodafone UK 实测选 sha1+aes-cbc）。
func BuildSecurityClientMultiMechanismHeader(agreement SecurityAgreement) string {
	agreement = completeSecurityAgreement(agreement)
	mechs := [][2]string{
		{"hmac-md5-96", "des-ede3-cbc"},
		{"hmac-md5-96", "aes-cbc"},
		{"hmac-md5-96", "null"},
		{"hmac-sha-1-96", "des-ede3-cbc"},
		{"hmac-sha-1-96", "aes-cbc"},
		{"hmac-sha-1-96", "null"},
	}
	parts := make([]string, 0, len(mechs))
	for _, m := range mechs {
		parts = append(parts, fmt.Sprintf(
			"ipsec-3gpp; alg=%s; ealg=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
			m[0], m[1],
			agreement.SPIClient, agreement.SPIServer,
			agreement.PortClient, agreement.PortServer,
		))
	}
	return strings.Join(parts, ",")
}

func BuildSecurityClientHeader(agreement SecurityAgreement) string {
	agreement = completeSecurityAgreement(agreement)
	return agreement.HeaderValue()
}

func ParseSecurityAgreements(values []string) []SecurityAgreement {
	var out []SecurityAgreement
	for _, value := range values {
		for _, item := range splitSIPHeaderValues(value) {
			agreement, ok := parseSecurityAgreement(item)
			if ok {
				out = append(out, agreement)
			}
		}
	}
	return out
}

func SelectSecurityAgreement(values []string, client SecurityAgreement) (SecurityAgreement, bool) {
	offers := ParseSecurityAgreements(values)
	if len(offers) == 0 {
		return SecurityAgreement{}, false
	}
	client = completeSecurityAgreement(client)
	bestIndex := -1
	bestScore := -1
	var best SecurityAgreement
	for i, offer := range offers {
		offer = completeSecurityAgreement(offer)
		if !securityAgreementCompatible(offer, client) {
			continue
		}
		score := securityAgreementScore(offer, client)
		if score > bestScore {
			bestIndex = i
			bestScore = score
			best = offer
		}
	}
	if bestIndex < 0 {
		return SecurityAgreement{}, false
	}
	return best, true
}

func (a SecurityAgreement) HeaderValue() string {
	a = completeSecurityAgreement(a)
	if strings.TrimSpace(a.Protocol) == "" {
		return ""
	}
	parts := []string{strings.TrimSpace(a.Protocol)}
	if a.Algorithm != "" {
		parts = append(parts, "alg="+a.Algorithm)
	}
	if a.EncryptionAlgorithm != "" {
		parts = append(parts, "ealg="+a.EncryptionAlgorithm)
	}
	if a.SPIClient > 0 {
		parts = append(parts, "spi-c="+strconv.FormatUint(uint64(a.SPIClient), 10))
	}
	if a.SPIServer > 0 {
		parts = append(parts, "spi-s="+strconv.FormatUint(uint64(a.SPIServer), 10))
	}
	if a.PortClient > 0 {
		parts = append(parts, "port-c="+strconv.Itoa(a.PortClient))
	}
	if a.PortServer > 0 {
		parts = append(parts, "port-s="+strconv.Itoa(a.PortServer))
	}
	if a.Protocol == DefaultSecurityProtocol && a.Prot == "" && a.Mod == "" {
		// ipsec-3gpp 标准参数（TS 33.203 Annex H）：prot=esp;mod=trans。
		// 参考实现（1239t/vowifi-go register_profile.go）与 v155 实测格式。
		parts = append(parts, "prot="+DefaultSecurityProt, "mod="+DefaultSecurityMod)
	}
	return strings.Join(parts, ";")
}

func completeSecurityAgreement(a SecurityAgreement) SecurityAgreement {
	if strings.TrimSpace(a.Protocol) == "" {
		a.Protocol = DefaultSecurityProtocol
	}
	a.Protocol = strings.ToLower(strings.TrimSpace(a.Protocol))
	if strings.TrimSpace(a.Algorithm) == "" {
		a.Algorithm = DefaultSecurityAlgorithm
	}
	a.Algorithm = strings.ToLower(strings.TrimSpace(a.Algorithm))
	if strings.TrimSpace(a.EncryptionAlgorithm) == "" {
		a.EncryptionAlgorithm = DefaultSecurityEAlg
	}
	a.EncryptionAlgorithm = strings.ToLower(strings.TrimSpace(a.EncryptionAlgorithm))
	if a.PortClient < 0 {
		a.PortClient = 0
	}
	if a.PortServer < 0 {
		a.PortServer = 0
	}
	return a
}

func isZeroSecurityAgreement(a SecurityAgreement) bool {
	return strings.TrimSpace(a.Protocol) == "" &&
		strings.TrimSpace(a.Algorithm) == "" &&
		strings.TrimSpace(a.EncryptionAlgorithm) == "" &&
		a.SPIClient == 0 &&
		a.SPIServer == 0 &&
		a.PortClient == 0 &&
		a.PortServer == 0 &&
		len(a.Parameters) == 0 &&
		strings.TrimSpace(a.Raw) == ""
}

func parseSecurityAgreement(value string) (SecurityAgreement, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return SecurityAgreement{}, false
	}
	parts := splitSemicolonParams(raw)
	if len(parts) == 0 {
		return SecurityAgreement{}, false
	}
	agreement := SecurityAgreement{
		Protocol:   strings.ToLower(strings.TrimSpace(parts[0])),
		Parameters: map[string]string{},
		Raw:        raw,
	}
	for _, part := range parts[1:] {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = unquote(strings.TrimSpace(val))
		if key == "" {
			continue
		}
		agreement.Parameters[key] = val
		switch key {
		case "alg":
			agreement.Algorithm = strings.ToLower(strings.TrimSpace(val))
		case "ealg":
			agreement.EncryptionAlgorithm = strings.ToLower(strings.TrimSpace(val))
		case "spi-c":
			agreement.SPIClient = parseSecurityUint32(val)
		case "spi-s":
			agreement.SPIServer = parseSecurityUint32(val)
		case "port-c":
			agreement.PortClient = parseSecurityPort(val)
		case "port-s":
			agreement.PortServer = parseSecurityPort(val)
		}
	}
	return agreement, agreement.Protocol != ""
}

func splitSemicolonParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == ';' && !inQuote:
			if part := strings.TrimSpace(cur.String()); part != "" {
				out = append(out, part)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func securityAgreementScore(offer, client SecurityAgreement) int {
	score := 0
	if strings.EqualFold(offer.Protocol, client.Protocol) {
		score += 100
	}
	if strings.EqualFold(offer.Algorithm, client.Algorithm) {
		score += 20
	}
	if strings.EqualFold(offer.EncryptionAlgorithm, client.EncryptionAlgorithm) {
		score += 10
	}
	if offer.SPIClient > 0 && offer.SPIServer > 0 {
		score += 4
	}
	if offer.PortClient > 0 && offer.PortServer > 0 {
		score += 4
	}
	if q, ok := offer.Parameters["q"]; ok {
		score += securityQValue(q)
	}
	return score
}

func securityAgreementCompatible(offer, client SecurityAgreement) bool {
	if !strings.EqualFold(offer.Protocol, client.Protocol) {
		return false
	}
	if !strings.EqualFold(offer.Algorithm, client.Algorithm) {
		return false
	}
	if !strings.EqualFold(offer.EncryptionAlgorithm, client.EncryptionAlgorithm) {
		return false
	}
	return true
}

func securityQValue(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	raw, err := strconv.ParseFloat(value, 64)
	if err != nil || raw <= 0 {
		return 0
	}
	if raw > 1 {
		raw = 1
	}
	return int(raw * 10)
}

func parseSecurityUint32(value string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func parseSecurityPort(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}

func randomSecuritySPI(random io.Reader) uint32 {
	var b [4]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return 1
	}
	spi := binary.BigEndian.Uint32(b[:])
	if spi == 0 {
		return 1
	}
	return spi
}

func validateSecurityClientHeader(header string) error {
	agreement, ok := parseSecurityAgreement(header)
	if !ok {
		return fmt.Errorf("invalid Security-Client header")
	}
	if !strings.EqualFold(agreement.Protocol, DefaultSecurityProtocol) {
		return fmt.Errorf("unsupported Security-Client protocol %q", agreement.Protocol)
	}
	return nil
}
