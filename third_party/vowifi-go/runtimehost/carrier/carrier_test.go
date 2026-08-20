package carrier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEffectiveCarrierConfigEnablesATTNativeE911(t *testing.T) {
	ClearCarrierOverrides()
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "280"})
	if cfg.PresetID != "310280" {
		t.Fatalf("PresetID=%q, want 310280", cfg.PresetID)
	}
	if !cfg.E911.Enabled || cfg.E911.Provider != "att-ts43" || cfg.E911.Websheet == "" || cfg.E911.EntitlementEndpoint == "" {
		t.Fatalf("E911 config=%+v, want enabled ATT TS.43 preset", cfg.E911)
	}
}

func TestResolveEffectiveCarrierConfigNormalizesTwoDigitMNC(t *testing.T) {
	ClearCarrierOverrides()
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "28"})
	if cfg.PresetID != "310028" {
		t.Fatalf("PresetID=%q, want normalized 310028", cfg.PresetID)
	}
	if cfg.E911.Enabled {
		t.Fatalf("E911 enabled for unknown normalized preset: %+v", cfg.E911)
	}
}

func TestLoadCarrierOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "carriers.json")
	if err := os.WriteFile(path, []byte(`{
		"001001": {
			"mcc": "001",
			"mnc": "001",
			"e911": {
				"enabled": true,
				"provider": "ts43",
				"websheet": "https://example.test/e911",
				"entitlement_endpoint": "https://example.test/entitlement"
			}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := LoadCarrierOverrides(path)
	if err != nil {
		t.Fatalf("LoadCarrierOverrides() error = %v", err)
	}
	if res.Missing || res.Count != 1 {
		t.Fatalf("LoadResult=%+v, want one loaded override", res)
	}
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "001", MNC: "001"})
	if !cfg.E911.Enabled || cfg.E911.Provider != "ts43" || cfg.E911.Websheet != "https://example.test/e911" {
		t.Fatalf("override config=%+v", cfg)
	}
	ClearCarrierOverrides()
}

func TestBuiltinCarrierProfilesPresent(t *testing.T) {
	ClearCarrierOverrides()
	for _, key := range []string{"310280", "310410", "234015", "234030"} {
		mcc := key[:3]
		mnc := key[3:]
		cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: mcc, MNC: mnc})
		if cfg.PresetID != key {
			t.Fatalf("PresetID=%q, want %q", cfg.PresetID, key)
		}
		if len(cfg.IKE.DHGroups) == 0 {
			t.Fatalf("IKE.DHGroups empty for %q", key)
		}
		if cfg.IKE.ProposalSet == "" || cfg.IKE.TransformOrder == "" || cfg.EAP.NetworkName == "" || cfg.EAP.IdentityMode == "" {
			t.Fatalf("profile fields empty for %q: %+v", key, cfg)
		}
	}
	ClearCarrierOverrides()
}

func TestATTProfileUsesCurve25519Single(t *testing.T) {
	ClearCarrierOverrides()
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "310", MNC: "280"})
	if cfg.IKE.ProposalSet != "curve25519-single" {
		t.Fatalf("ProposalSet=%q, want curve25519-single", cfg.IKE.ProposalSet)
	}
	if len(cfg.IKE.DHGroups) != 1 || cfg.IKE.DHGroups[0] != 31 {
		t.Fatalf("DHGroups=%v, want [31]", cfg.IKE.DHGroups)
	}
	if cfg.IKE.EffectiveRetryOnTimeout() {
		t.Fatalf("ATT should not retry on timeout")
	}
}

func TestVodafoneProfileUsesV155(t *testing.T) {
	ClearCarrierOverrides()
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "234", MNC: "015"})
	if cfg.IKE.ProposalSet != "v155-4prop" {
		t.Fatalf("ProposalSet=%q, want v155-4prop", cfg.IKE.ProposalSet)
	}
	if len(cfg.IKE.DHGroups) != 2 || cfg.IKE.DHGroups[0] != 14 || cfg.IKE.DHGroups[1] != 2 {
		t.Fatalf("DHGroups=%v, want [14 2]", cfg.IKE.DHGroups)
	}
	if !cfg.IKE.EffectiveRetryOnTimeout() {
		t.Fatalf("Vodafone should retry on timeout")
	}
	// A 方案（保守回归）：Vodafone 固定走 500，不切 4500，SOCKS 不保活
	if cfg.Transport.EffectivePrefer4500OnNATOnly() {
		t.Fatalf("A scheme: Vodafone should NOT prefer 4500 on NAT (expect false)")
	}
	if cfg.Transport.EffectiveKeepSOCKSControlAlive() {
		t.Fatalf("A scheme: Vodafone should NOT keep SOCKS control alive (expect false)")
	}
}

func TestTwoDigitMNCNormalizedForCarrierLookup(t *testing.T) {
	ClearCarrierOverrides()
	a := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "234", MNC: "15"})
	b := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "234", MNC: "015"})
	if a.PresetID != b.PresetID || a.PresetID != "234015" {
		t.Fatalf("2-digit vs 3-digit MNC mismatch: %q vs %q", a.PresetID, b.PresetID)
	}
	if a.IKE.ProposalSet != b.IKE.ProposalSet {
		t.Fatalf("profile mismatch after MNC normalization")
	}
}

func TestDefaultCarrierFallsBackToV155(t *testing.T) {
	ClearCarrierOverrides()
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "262", MNC: "001"})
	if cfg.IKE.ProposalSet != "v155-4prop" {
		t.Fatalf("ProposalSet=%q, want v155-4prop for unknown MCC", cfg.IKE.ProposalSet)
	}
	if len(cfg.IKE.DHGroups) == 0 {
		t.Fatalf("DHGroups empty for default carrier")
	}
}

func TestLoadCarrierOverridesWithProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "carriers2.json")
	if err := os.WriteFile(path, []byte(`{
		"234015": {
			"mcc": "234",
			"mnc": "015",
			"ike": {"proposal_set":"curve25519-single","dh_groups":[31],"retry_on_timeout":false},
			"eap": {"network_name":"WLAN","identity_mode":"permanent-only"},
			"transport": {"prefer_4500_on_nat_only": false}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	res, err := LoadCarrierOverrides(path)
	if err != nil {
		t.Fatalf("LoadCarrierOverrides error=%v", err)
	}
	if res.Missing || res.Count != 1 {
		t.Fatalf("LoadResult=%+v", res)
	}
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "234", MNC: "015"})
	if cfg.IKE.ProposalSet != "curve25519-single" {
		t.Fatalf("override ProposalSet=%q", cfg.IKE.ProposalSet)
	}
	if cfg.Transport.EffectivePrefer4500OnNATOnly() {
		t.Fatalf("override Prefer4500OnNATOnly should be false")
	}
	ClearCarrierOverrides()
	// should fall back to builtin after clear
	cfg2 := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{MCC: "234", MNC: "015"})
	if cfg2.IKE.ProposalSet != "v155-4prop" {
		t.Fatalf("after clear, want builtin v155-4prop, got %q", cfg2.IKE.ProposalSet)
	}
}

func TestIsVoWiFiBlockedMCC(t *testing.T) {
	if !IsVoWiFiBlockedMCC("460") {
		t.Fatalf("460 should be blocked")
	}
	if IsVoWiFiBlockedMCC("234") || IsVoWiFiBlockedMCC("310") {
		t.Fatalf("234/310 should not be blocked")
	}
}
