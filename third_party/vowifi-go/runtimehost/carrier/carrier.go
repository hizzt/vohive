package carrier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

type E911Config struct {
	Enabled             bool   `json:"enabled"`
	Provider            string `json:"provider"`
	Websheet            string `json:"websheet"`
	EntitlementEndpoint string `json:"entitlement_endpoint"`
}

type CarrierIKEProfile struct {
	ProposalSet    string   `json:"proposal_set,omitempty"`
	DHGroups       []uint16 `json:"dh_groups,omitempty"`
	TransformOrder string   `json:"transform_order,omitempty"`
	RetryOnTimeout *bool    `json:"retry_on_timeout,omitempty"`
}

type CarrierEAPProfile struct {
	PreferAKAPrime *bool  `json:"prefer_aka_prime,omitempty"`
	IdentityMode   string `json:"identity_mode,omitempty"`
	NetworkName    string `json:"network_name,omitempty"`
}

type CarrierTransportProfile struct {
	Prefer4500OnNATOnly     *bool `json:"prefer_4500_on_nat_only,omitempty"`
	KeepSOCKSControlAlive   *bool `json:"keep_socks_control_alive,omitempty"`
	RequestPCSCF            *bool `json:"request_pcscf,omitempty"`
}

// CarrierCPProfile 控制 IKE_AUTH CFG(CP) 请求的地址族策略（vowifi_gateway swu_ike.py
// 的 cp_mode 家族）：v4/v6/dual 只请求对应属性；auto 按顺序探测直到拿到可用 PDN。
// Vodafone UK（234-15）实测为 IPv4-only IMS，v6 请求会收私有 Notify 16375 拒绝。
type CarrierCPProfile struct {
	Mode  string   `json:"mode,omitempty"`   // auto | v4 | v6 | dual
	Order []string `json:"order,omitempty"`  // auto 模式的探测顺序，默认 v4,dual,v6
}

type EffectiveCarrierConfig struct {
	MCC       string                  `json:"mcc"`
	MNC       string                  `json:"mnc"`
	PresetID  string                  `json:"preset_id"`
	E911      E911Config              `json:"e911"`
	IKE       CarrierIKEProfile       `json:"ike,omitempty"`
	EAP       CarrierEAPProfile       `json:"eap,omitempty"`
	Transport CarrierTransportProfile `json:"transport,omitempty"`
	CP        CarrierCPProfile        `json:"cp,omitempty"`
}

type EffectiveCarrierConfigInput struct {
	MCC string
	MNC string
}

type LoadResult struct {
	Path    string
	Missing bool
	Count   int
}

var (
	overridesMu sync.RWMutex
	overrides   = map[string]EffectiveCarrierConfig{}
)

func boolPtr(v bool) *bool { b := v; return &b }

var builtinCarriers = map[string]EffectiveCarrierConfig{
	"310280": {
		MCC:      "310",
		MNC:      "280",
		PresetID: "310280",
		E911: E911Config{
			Enabled:             true,
			Provider:            "att-ts43",
			Websheet:            "https://www.att.com/acctmgmt/wireless/e911",
			EntitlementEndpoint: "https://sentitlement2.mobile.att.net/WFC",
		},
		IKE: CarrierIKEProfile{
			ProposalSet:    "curve25519-single",
			DHGroups:       []uint16{31},
			TransformOrder: "ENCR-PRF-INTEG-DH",
			RetryOnTimeout: boolPtr(false),
		},
		EAP: CarrierEAPProfile{
			PreferAKAPrime: boolPtr(true),
			IdentityMode:   "permanent-only",
			NetworkName:    "WLAN",
		},
		Transport: CarrierTransportProfile{
			Prefer4500OnNATOnly:   boolPtr(false),
			KeepSOCKSControlAlive: boolPtr(true),
		},
	},
	"310410": {
		MCC:      "310",
		MNC:      "410",
		PresetID: "310410",
		E911: E911Config{
			Enabled:             true,
			Provider:            "att-ts43",
			Websheet:            "https://www.att.com/acctmgmt/wireless/e911",
			EntitlementEndpoint: "https://sentitlement2.mobile.att.net/WFC",
		},
		IKE: CarrierIKEProfile{
			ProposalSet:    "curve25519-single",
			DHGroups:       []uint16{31},
			TransformOrder: "ENCR-PRF-INTEG-DH",
			RetryOnTimeout: boolPtr(false),
		},
		EAP: CarrierEAPProfile{
			PreferAKAPrime: boolPtr(true),
			IdentityMode:   "permanent-only",
			NetworkName:    "WLAN",
		},
		Transport: CarrierTransportProfile{
			Prefer4500OnNATOnly:   boolPtr(false),
			KeepSOCKSControlAlive: boolPtr(true),
		},
	},
	"234015": {
		MCC:      "234",
		MNC:      "015",
		PresetID: "234015",
		E911: E911Config{
			Enabled: false,
		},
		IKE: CarrierIKEProfile{
			ProposalSet:    "v155-4prop",
			DHGroups:       []uint16{14, 2},
			TransformOrder: "ENCR-INTEG-PRF-DH",
			RetryOnTimeout: boolPtr(true),
		},
		EAP: CarrierEAPProfile{
			PreferAKAPrime: boolPtr(true),
			IdentityMode:   "permanent-only",
			NetworkName:    "WLAN",
		},
		Transport: CarrierTransportProfile{
			// NAT-T 必须：SOCKS5 代理场景 ePDG 看到的是代理出口（伦敦）IP 而非
			// 本机 IP，NAT_DETECTION_DESTINATION_IP 必然不匹配（NAT 已检出）。
			// ike_success2.pcap 实证：IKE_AUTH 及后续全部报文走 4500 + 4 字节
			// marker；留在 500 则 ePDG 对 IKE_AUTH 静默。08-23 01:00 A/B 复测
			// 再次证实（500 上 IKE_AUTH 全超时）。
			Prefer4500OnNATOnly:   boolPtr(true),
			KeepSOCKSControlAlive: boolPtr(true),
			RequestPCSCF:          boolPtr(false),
		},
		CP: CarrierCPProfile{
			// Vodafone UK 实测（vowifi_gateway）：IPv4-only IMS PDN；
			// v6-only 请求会收私有 Notify 16375 拒绝。
			Mode: "v4",
		},
	},
	"234030": {
		MCC:      "234",
		MNC:      "030",
		PresetID: "234030",
		E911: E911Config{
			Enabled: false,
		},
		IKE: CarrierIKEProfile{
			ProposalSet:    "v155-4prop",
			DHGroups:       []uint16{14, 2},
			TransformOrder: "ENCR-INTEG-PRF-DH",
			RetryOnTimeout: boolPtr(true),
		},
		EAP: CarrierEAPProfile{
			PreferAKAPrime: boolPtr(true),
			IdentityMode:   "permanent-only",
			NetworkName:    "WLAN",
		},
		Transport: CarrierTransportProfile{
			// 同 234015：NAT-T 4500 切换是 Vodafone ePDG 过 IKE_AUTH 的必要条件。
			Prefer4500OnNATOnly:   boolPtr(true),
			KeepSOCKSControlAlive: boolPtr(true),
		},
	},
}

func LoadCarrierOverrides(path string) (LoadResult, error) {
	path = strings.TrimSpace(path)
	result := LoadResult{Path: path, Missing: true}
	if path == "" {
		return result, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return result, err
	}
	var decoded map[string]EffectiveCarrierConfig
	if err := json.Unmarshal(raw, &decoded); err != nil {
		var list []EffectiveCarrierConfig
		if err2 := json.Unmarshal(raw, &list); err2 != nil {
			return result, err
		}
		decoded = make(map[string]EffectiveCarrierConfig, len(list))
		for _, cfg := range list {
			if key := presetKey(cfg.MCC, cfg.MNC); key != "" {
				decoded[key] = normalizeConfig(cfg)
			}
		}
	}
	next := make(map[string]EffectiveCarrierConfig, len(decoded))
	for key, cfg := range decoded {
		cfg = normalizeConfig(cfg)
		if cfg.MCC == "" || cfg.MNC == "" {
			cfg.MCC, cfg.MNC = splitPresetKey(key)
			cfg = normalizeConfig(cfg)
		}
		if cfg.PresetID != "" {
			key = cfg.PresetID
		}
		key = strings.TrimSpace(key)
		if key != "" {
			next[key] = cfg
		}
	}
	overridesMu.Lock()
	overrides = next
	overridesMu.Unlock()
	result.Missing = false
	result.Count = len(next)
	return result, nil
}

func ClearCarrierOverrides() {
	overridesMu.Lock()
	overrides = map[string]EffectiveCarrierConfig{}
	overridesMu.Unlock()
}

func ResolveEffectiveCarrierConfig(in EffectiveCarrierConfigInput) EffectiveCarrierConfig {
	mcc := strings.TrimSpace(in.MCC)
	mnc := normalizeMNC(in.MNC)
	key := presetKey(mcc, mnc)
	overridesMu.RLock()
	if cfg, ok := overrides[key]; ok {
		overridesMu.RUnlock()
		return normalizeConfig(cfg)
	}
	overridesMu.RUnlock()
	if cfg, ok := builtinCarriers[key]; ok {
		return normalizeConfig(cfg)
	}
	return normalizeConfig(EffectiveCarrierConfig{
		MCC:      mcc,
		MNC:      mnc,
		PresetID: mcc + mnc,
		E911: E911Config{
			Enabled:  false,
			Provider: "",
		},
	})
}

var blockedMCC = map[string]struct{}{
	"460": {},
}

func IsVoWiFiBlockedMCC(mcc string) bool {
	_, ok := blockedMCC[strings.TrimSpace(mcc)]
	return ok
}

type VoWiFiBlockedMCCError struct {
	MCC string
}

func (e VoWiFiBlockedMCCError) Error() string {
	return fmt.Sprintf("vowifi blocked by carrier policy for MCC %s", e.MCC)
}

func NewVoWiFiBlockedMCCError(mcc string) error {
	return VoWiFiBlockedMCCError{MCC: strings.TrimSpace(mcc)}
}

func IsVoWiFiPolicyBlockedError(err error) bool {
	var target VoWiFiBlockedMCCError
	return errors.As(err, &target)
}

func normalizeConfig(cfg EffectiveCarrierConfig) EffectiveCarrierConfig {
	cfg.MCC = strings.TrimSpace(cfg.MCC)
	cfg.MNC = normalizeMNC(cfg.MNC)
	if cfg.PresetID == "" {
		cfg.PresetID = presetKey(cfg.MCC, cfg.MNC)
	} else {
		cfg.PresetID = strings.TrimSpace(cfg.PresetID)
	}
	cfg.E911.Provider = strings.ToLower(strings.TrimSpace(cfg.E911.Provider))
	cfg.E911.Websheet = strings.TrimSpace(cfg.E911.Websheet)
	cfg.E911.EntitlementEndpoint = strings.TrimSpace(cfg.E911.EntitlementEndpoint)
	cfg.IKE = normalizeIKEProfile(cfg.IKE, cfg.MCC)
	cfg.EAP = normalizeEAPProfile(cfg.EAP)
	cfg.Transport = normalizeTransportProfile(cfg.Transport)
	cfg.CP = normalizeCPProfile(cfg.CP)
	return cfg
}

func normalizeIKEProfile(p CarrierIKEProfile, mcc string) CarrierIKEProfile {
	if strings.TrimSpace(p.ProposalSet) == "" {
		if mcc == "310" {
			p.ProposalSet = "curve25519-single"
		} else {
			p.ProposalSet = "v155-4prop"
		}
	}
	p.ProposalSet = strings.TrimSpace(p.ProposalSet)
	if len(p.DHGroups) == 0 {
		switch p.ProposalSet {
		case "curve25519-single":
			p.DHGroups = []uint16{31}
		case "modp-mixed":
			p.DHGroups = []uint16{31, 14, 2}
		default:
			p.DHGroups = []uint16{14, 2}
		}
	}
	if strings.TrimSpace(p.TransformOrder) == "" {
		if p.ProposalSet == "curve25519-single" {
			p.TransformOrder = "ENCR-PRF-INTEG-DH"
		} else {
			p.TransformOrder = "ENCR-INTEG-PRF-DH"
		}
	}
	if p.RetryOnTimeout == nil {
		v := p.ProposalSet != "curve25519-single"
		p.RetryOnTimeout = &v
	}
	return p
}

func normalizeEAPProfile(p CarrierEAPProfile) CarrierEAPProfile {
	if p.PreferAKAPrime == nil {
		v := true
		p.PreferAKAPrime = &v
	}
	if strings.TrimSpace(p.IdentityMode) == "" {
		p.IdentityMode = "permanent-only"
	}
	if strings.TrimSpace(p.NetworkName) == "" {
		p.NetworkName = "WLAN"
	}
	return p
}

func normalizeTransportProfile(p CarrierTransportProfile) CarrierTransportProfile {
	if p.Prefer4500OnNATOnly == nil {
		v := true
		p.Prefer4500OnNATOnly = &v
	}
	if p.KeepSOCKSControlAlive == nil {
		v := true
		p.KeepSOCKSControlAlive = &v
	}
	if p.RequestPCSCF == nil {
		v := false
		p.RequestPCSCF = &v
	}
	return p
}

func normalizeMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if len(mnc) == 2 {
		return "0" + mnc
	}
	return mnc
}

func normalizeCPProfile(p CarrierCPProfile) CarrierCPProfile {
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	switch p.Mode {
	case "v4", "v6", "dual":
	case "":
		p.Mode = "auto"
	default:
		p.Mode = "auto"
	}
	if len(p.Order) == 0 {
		if p.Mode == "auto" {
			// v4 优先：多数 ePDG 兼容 IPv4 CFG；v6-only 运营商靠探测轮到。
			p.Order = []string{"v4", "dual", "v6"}
		}
	}
	filtered := make([]string, 0, len(p.Order))
	for _, item := range p.Order {
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "v4", "v6", "dual":
			filtered = append(filtered, strings.ToLower(strings.TrimSpace(item)))
		}
	}
	if len(filtered) > 0 {
		p.Order = filtered
	}
	return p
}

func presetKey(mcc, mnc string) string {
	mcc = strings.TrimSpace(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return mcc + mnc
}

func splitPresetKey(key string) (string, string) {
	key = strings.TrimSpace(key)
	if len(key) < 5 {
		return "", ""
	}
	return key[:3], key[3:]
}

// Effective helpers for callers that need concrete values without nil checks.

func (p CarrierIKEProfile) EffectiveRetryOnTimeout() bool {
	if p.RetryOnTimeout == nil {
		return p.ProposalSet != "curve25519-single"
	}
	return *p.RetryOnTimeout
}

func (p CarrierEAPProfile) EffectivePreferAKAPrime() bool {
	if p.PreferAKAPrime == nil {
		return true
	}
	return *p.PreferAKAPrime
}

func (p CarrierTransportProfile) EffectivePrefer4500OnNATOnly() bool {
	if p.Prefer4500OnNATOnly == nil {
		return true
	}
	return *p.Prefer4500OnNATOnly
}

func (p CarrierTransportProfile) EffectiveKeepSOCKSControlAlive() bool {
	if p.KeepSOCKSControlAlive == nil {
		// 默认保活：SOCKS5 UDP relay 的生命周期绑定 TCP 控制连接（RFC 1928
		// 语义），dialAddr 后立即 Close TCP 会让伦敦代理在数十秒后回收
		// relay——设备实测隧道建立约 3 分钟后 ESP/keepalive 全部静默消失、
		// 无 DPD 无重建（空 socket），会话静默死亡。保活 TCP 才能维持 relay。
		return true
	}
	return *p.KeepSOCKSControlAlive
}

func (p CarrierTransportProfile) EffectiveRequestPCSCF() bool {
	if p.RequestPCSCF == nil {
		return false
	}
	return *p.RequestPCSCF
}

// EffectiveCPMode / EffectiveCPOrder 暴露 CFG 地址族策略。
func (p CarrierCPProfile) EffectiveCPMode() string {
	if p.Mode == "" {
		return "auto"
	}
	return p.Mode
}

func (p CarrierCPProfile) EffectiveCPOrder() []string {
	if len(p.Order) == 0 {
		return []string{"v4", "dual", "v6"}
	}
	return p.Order
}
