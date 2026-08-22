package swu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ePDG FQDN 解析（对齐 VoCat epdg_resolver.go）：
//  1. 系统 DNS（含备选 3GPP 主机名——MNC 2/3 位变体）
//  2. 全部失败时走 Google DoH，带 EDNS-Client-Subnet 就近解析——
//     部分 ePDG 的权威 DNS 只给归属国解析器返回地址（GeoDNS），
//     设备本地解析器（如伦敦 SOCKS5 出口侧的公共 DNS）拿到的
//     可能是空答案或次优地址。
var googleDNSOverHTTPS = "https://dns.google/resolve"

// ipAddrResolver 抽象 LookupIPAddr 便于测试注入。
type ipAddrResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type dnsOverHTTPSResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// resolveEPDGAddresses 解析 ePDG 主机名到公网 IP 列表。
// host 已是 IP 时直接返回（不走 DNS）。
func resolveEPDGAddresses(ctx context.Context, resolver ipAddrResolver, host string) ([]net.IP, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	hostsToTry := []string{host}
	if alt := alternate3GPPHostname(host); alt != "" && alt != host {
		hostsToTry = append(hostsToTry, alt)
	}

	var systemErr error
	for _, targetHost := range hostsToTry {
		addresses, err := resolver.LookupIPAddr(ctx, targetHost)
		if err == nil {
			valid := filterValidPublicEPDGAddresses(addresses)
			if len(valid) > 0 {
				return valid, nil
			}
		} else {
			systemErr = err
		}
	}

	subnet := epdgDNSClientSubnet(host)
	client := &http.Client{Timeout: 8 * time.Second}
	var fallbackErr error
	for _, targetHost := range hostsToTry {
		var fallback []net.IP
		fallback, fallbackErr = resolveEPDGWithECS(ctx, client, googleDNSOverHTTPS, targetHost, subnet)
		if fallbackErr == nil && len(fallback) > 0 {
			return fallback, nil
		}
	}
	if systemErr == nil {
		systemErr = errors.New("system DNS returned no usable public IP addresses")
	}
	return nil, fmt.Errorf("system DNS failed (%v); geographic DNS fallback failed: %w", systemErr, fallbackErr)
}

func filterValidPublicEPDGAddresses(addresses []net.IPAddr) []net.IP {
	result := make([]net.IP, 0, len(addresses))
	for _, addr := range addresses {
		if addr.IP == nil || addr.IP.IsLoopback() || addr.IP.IsUnspecified() {
			continue
		}
		result = append(result, addr.IP)
	}
	return result
}

// alternate3GPPHostname 返回 3GPP ePDG FQDN 的 MNC 2/3 位变体：
// 规范要求 MNC 补零到 3 位，但部分运营商 DNS 只部署了 2 位变体（或反之）。
func alternate3GPPHostname(host string) string {
	const prefix = "epdg.epc.mnc"
	if !strings.HasPrefix(host, prefix) {
		return ""
	}
	rest := host[len(prefix):]
	dot := strings.Index(rest, ".")
	if dot <= 0 {
		return ""
	}
	mnc := rest[:dot]
	suffix := rest[dot:]
	if len(mnc) == 3 && strings.HasPrefix(mnc, "0") {
		return prefix + mnc[1:] + suffix
	}
	if len(mnc) == 2 {
		return prefix + "0" + mnc + suffix
	}
	return ""
}

// epdgDNSClientSubnet 返回 GeoDNS 用的 EDNS client subnet——
// ePDG 权威 DNS 只向归属国解析器暴露地址时空结果才需要；
// 非空表示 DoH 查询按该国家网段就近解析。
func epdgDNSClientSubnet(host string) string {
	if idx := strings.Index(host, ".mcc"); idx >= 0 && len(host) >= idx+7 {
		mcc := host[idx+4 : idx+7]
		if isDecimalString(mcc) {
			return mccDefaultClientSubnet(mcc)
		}
	}
	return ""
}

// mccDefaultClientSubnet 返回国家 MCC 对应的标准 GeoDNS EDNS client subnet
// （VoCat carrier_compat.go 同表）。
func mccDefaultClientSubnet(mcc string) string {
	switch strings.TrimSpace(mcc) {
	case "262": // Germany
		return "139.7.0.0/16"
	case "204": // Netherlands
		return "109.39.0.0/16"
	case "234", "235": // UK
		return "212.183.0.0/16"
	case "515": // Philippines
		return "112.198.0.0/16"
	case "454": // Hong Kong
		return "203.0.0.0/16"
	case "466", "467": // Taiwan
		return "210.0.0.0/16"
	case "525": // Singapore
		return "202.166.0.0/16"
	case "440", "441": // Japan
		return "126.0.0.0/16"
	case "450": // South Korea
		return "211.0.0.0/16"
	case "310", "311", "312", "313", "314", "315", "316": // USA
		return "198.228.0.0/16"
	case "302": // Canada
		return "142.0.0.0/16"
	case "505": // Australia
		return "1.120.0.0/16"
	case "520": // Thailand
		return "171.96.0.0/16"
	case "510": // Indonesia
		return "182.0.0.0/16"
	case "502": // Malaysia
		return "115.132.0.0/16"
	case "208": // France
		return "194.51.0.0/16"
	case "214": // Spain
		return "212.166.0.0/16"
	case "222": // Italy
		return "83.224.0.0/16"
	case "228": // Switzerland
		return "178.192.0.0/16"
	case "232": // Austria
		return "194.138.0.0/16"
	case "206": // Belgium
		return "193.190.0.0/16"
	case "260": // Poland
		return "83.0.0.0/16"
	case "268": // Portugal
		return "194.65.0.0/16"
	case "272": // Ireland
		return "193.1.0.0/16"
	case "238": // Denmark
		return "193.162.0.0/16"
	case "240": // Sweden
		return "194.236.0.0/16"
	case "242": // Norway
		return "193.69.0.0/16"
	case "244": // Finland
		return "193.64.0.0/16"
	case "202": // Greece
		return "194.219.0.0/16"
	case "216": // Hungary
		return "195.199.0.0/16"
	case "230": // Czech Republic
		return "195.113.0.0/16"
	case "286": // Turkey
		return "195.175.0.0/16"
	case "425": // Israel
		return "192.114.0.0/16"
	case "404", "405": // India
		return "103.0.0.0/16"
	case "655": // South Africa
		return "196.0.0.0/16"
	case "724": // Brazil
		return "177.0.0.0/16"
	case "334": // Mexico
		return "187.188.0.0/16"
	case "452": // Vietnam
		return "118.69.0.0/16"
	case "455": // Macao
		return "202.175.0.0/16"
	case "530": // New Zealand
		return "202.27.0.0/16"
	case "460": // China
		return "223.5.5.0/24"
	}
	return ""
}

// resolveEPDGWithECS 走 Google DoH JSON API 解析 ePDG，可选带 EDNS client subnet。
func resolveEPDGWithECS(
	ctx context.Context,
	client *http.Client,
	endpoint, host, subnet string,
) ([]net.IP, error) {
	if client == nil {
		return nil, errors.New("nil DNS-over-HTTPS client")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse DNS-over-HTTPS endpoint: %w", err)
	}
	query := parsed.Query()
	query.Set("name", strings.TrimSpace(host))
	query.Set("type", "A")
	if strings.TrimSpace(subnet) != "" {
		query.Set("edns_client_subnet", strings.TrimSpace(subnet))
	}
	parsed.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build DNS-over-HTTPS request: %w", err)
	}
	request.Header.Set("Accept", "application/dns-json")
	request.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query DNS-over-HTTPS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS-over-HTTPS returned HTTP %d", response.StatusCode)
	}
	var payload dnsOverHTTPSResponse
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode DNS-over-HTTPS response: %w", err)
	}
	if payload.Status != 0 {
		return nil, fmt.Errorf("DNS-over-HTTPS returned DNS status %d", payload.Status)
	}
	result := make([]net.IP, 0, len(payload.Answer))
	for _, answer := range payload.Answer {
		if answer.Type != 1 && answer.Type != 28 {
			continue
		}
		ip := net.ParseIP(strings.TrimSuffix(strings.TrimSpace(answer.Data), "."))
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		duplicate := false
		for _, existing := range result {
			if existing.Equal(ip) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, append(net.IP(nil), ip...))
		}
	}
	if len(result) == 0 {
		return nil, errors.New("DNS-over-HTTPS response contained no ePDG IP addresses")
	}
	return result, nil
}
