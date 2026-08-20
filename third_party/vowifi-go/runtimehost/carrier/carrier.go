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

type EffectiveCarrierConfig struct {
	MCC       string                  `json:"mcc"`
	MNC       string                  `json:"mnc"`
	PresetID  string                  `json:"preset_id"`
	E911      E911Config              `json:"e911"`
	IKE       CarrierIKEProfile       `json:"ike,omitempty"`
	EAP       CarrierEAPProfile       `json:"eap,omitempty"`
	Transport CarrierTransportProfile `json:"transport,omitempty"`
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
			KeepSOCKSControlAlive: boolPtr(false),
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
			KeepSOCKSControlAlive: boolPtr(false),
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
			Prefer4500OnNATOnly:   boolPtr(true),
			KeepSOCKSControlAlive: boolPtr(true),
			RequestPCSCF:          boolPtr(false),
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
		v := false
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
		return false
	}
	return *p.KeepSOCKSControlAlive
}

func (p CarrierTransportProfile) EffectiveRequestPCSCF() bool {
	if p.RequestPCSCF == nil {
		return false
	}
	return *p.RequestPCSCF
}
