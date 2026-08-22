package swu

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAlternate3GPPHostname(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"epdg.epc.mnc015.mcc234.pub.3gppnetwork.org", "epdg.epc.mnc15.mcc234.pub.3gppnetwork.org"},
		{"epdg.epc.mnc15.mcc234.pub.3gppnetwork.org", "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org"},
		{"epdg.epc.mnc460.mcc460.pub.3gppnetwork.org", ""},  // 3 位且不以 0 开头：无变体
		{"epdg.epc.mnc460.mcc460.pub.3gppnetwork.org.", ""}, // 尾点不剥（调用方已 normalize）
		{"ims.mnc015.mcc234.3gppnetwork.org", ""},           // 非 epdg 前缀
		{"epdg.epc.mnc1.mcc234.pub.3gppnetwork.org", ""},    // 1 位 MNC 非规范
	}
	for _, c := range cases {
		if got := alternate3GPPHostname(c.host); got != c.want {
			t.Fatalf("alternate3GPPHostname(%q)=%q want %q", c.host, got, c.want)
		}
	}
}

func TestEPDGDNSClientSubnet(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"epdg.epc.mnc015.mcc234.pub.3gppnetwork.org", "212.183.0.0/16"}, // UK
		{"epdg.epc.mnc002.mcc262.pub.3gppnetwork.org", "139.7.0.0/16"},   // Germany
		{"epdg.epc.mnc000.mcc460.pub.3gppnetwork.org", "223.5.5.0/24"},   // China
		{"epdg.example.com", ""}, // 无 MCC 段
		{"epdg.epc.mnc015.mccxxx.pub.3gppnetwork.org", ""},
	}
	for _, c := range cases {
		if got := epdgDNSClientSubnet(c.host); got != c.want {
			t.Fatalf("epdgDNSClientSubnet(%q)=%q want %q", c.host, got, c.want)
		}
	}
}

// stubResolver 按主机名返回固定结果，模拟系统 DNS。
type stubResolver struct {
	answers map[string][]net.IPAddr
	errs    map[string]error
}

func (s *stubResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if err, ok := s.errs[host]; ok {
		return nil, err
	}
	return s.answers[host], nil
}

func TestResolveEPDGAddressesPrefersSystemDNS(t *testing.T) {
	resolver := &stubResolver{
		answers: map[string][]net.IPAddr{
			"epdg.epc.mnc015.mcc234.pub.3gppnetwork.org": {
				{IP: net.ParseIP("88.82.14.51")},
				{IP: net.ParseIP("88.82.14.52")},
			},
		},
	}
	ips, err := resolveEPDGAddresses(context.Background(), resolver, "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org")
	if err != nil {
		t.Fatalf("resolveEPDGAddresses() error = %v", err)
	}
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("88.82.14.51")) {
		t.Fatalf("ips=%v", ips)
	}
}

func TestResolveEPDGAddressesIPPassthrough(t *testing.T) {
	ips, err := resolveEPDGAddresses(context.Background(), nil, "88.82.14.51")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("88.82.14.51")) {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}

func TestResolveEPDGAddressesFiltersLoopback(t *testing.T) {
	resolver := &stubResolver{
		answers: map[string][]net.IPAddr{
			"epdg.example": {
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("0.0.0.0")},
			},
		},
	}
	// 系统 DNS 全被过滤 + DoH 也失败（mock server 返回 500）→ 报错
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	orig := googleDNSOverHTTPS
	defer func() { googleDNSOverHTTPS = orig }()
	googleDNSOverHTTPS = server.URL

	_, err := resolveEPDGAddresses(context.Background(), resolver, "epdg.example")
	if err == nil {
		t.Fatal("want error for all-loopback system DNS + failing DoH")
	}
}

func TestResolveEPDGAddressesFallsBackToDoH(t *testing.T) {
	// 系统 DNS 主机名+备选主机名都失败 → DoH 回退成功
	resolver := &stubResolver{
		errs: map[string]error{
			"epdg.epc.mnc015.mcc234.pub.3gppnetwork.org": context.DeadlineExceeded,
			"epdg.epc.mnc15.mcc234.pub.3gppnetwork.org":  context.DeadlineExceeded,
		},
	}
	var gotSubnet string
	var gotName string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubnet = r.URL.Query().Get("edns_client_subnet")
		gotName = r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/dns-json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Status": 0,
			"Answer": []map[string]any{
				{"type": 1, "data": "88.82.14.60"},
				{"type": 1, "data": "88.82.14.61"},
				{"type": 1, "data": "88.82.14.60"},   // 去重
				{"type": 5, "data": "cname.example"}, // CNAME 跳过
			},
		})
	}))
	defer server.Close()
	orig := googleDNSOverHTTPS
	defer func() { googleDNSOverHTTPS = orig }()
	googleDNSOverHTTPS = server.URL

	ips, err := resolveEPDGAddresses(context.Background(), resolver, "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org")
	if err != nil {
		t.Fatalf("resolveEPDGAddresses() error = %v", err)
	}
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("88.82.14.60")) || !ips[1].Equal(net.ParseIP("88.82.14.61")) {
		t.Fatalf("ips=%v", ips)
	}
	// UK MCC 234 → 必须带 UK GeoDNS 子网就近解析
	if gotSubnet != "212.183.0.0/16" {
		t.Fatalf("edns_client_subnet=%q want 212.183.0.0/16", gotSubnet)
	}
	if gotName != "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org" {
		t.Fatalf("name=%q", gotName)
	}
}

func TestResolveEPDGAddressesAlternateHostnameSystemDNS(t *testing.T) {
	// 主机名（3 位 MNC）失败，备选（2 位 MNC）系统 DNS 成功 → 不走 DoH
	resolver := &stubResolver{
		answers: map[string][]net.IPAddr{
			"epdg.epc.mnc15.mcc234.pub.3gppnetwork.org": {
				{IP: net.ParseIP("88.82.14.70")},
			},
		},
		errs: map[string]error{
			"epdg.epc.mnc015.mcc234.pub.3gppnetwork.org": context.DeadlineExceeded,
		},
	}
	ips, err := resolveEPDGAddresses(context.Background(), resolver, "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org")
	if err != nil {
		t.Fatalf("resolveEPDGAddresses() error = %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("88.82.14.70")) {
		t.Fatalf("ips=%v", ips)
	}
}

// epdgTestResolver 给 manager 级测试注入确定性的 ePDG 解析，
// 避免依赖本机 DNS（epdg.example 在不同网络环境解析不一致）。
type epdgTestResolver struct {
	answers map[string][]net.IPAddr
}

func (e *epdgTestResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if a, ok := e.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func newEPDGTestResolver(host, ip string) *epdgTestResolver {
	return &epdgTestResolver{answers: map[string][]net.IPAddr{
		host: {{IP: net.ParseIP(ip)}},
	}}
}
