package swu

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// mockSocks5Server 模拟 SOCKS5 UDP Associate 代理 + ePDG 回声。
type mockSocks5Server struct {
	tcpAddr string
	udpAddr string
	epdg    string // ePDG 地址（中继把它作为目标）
	mu      sync.Mutex
	closed  bool
	tcpLn   net.Listener
	relayLn *net.UDPConn  // 代理中继 UDP 端点
	epdgLn  *net.UDPConn  // ePDG 模拟 UDP
}

func startMockSocks5Server(ctx context.Context) (*mockSocks5Server, error) {
	// SOCKS5 TCP 控制连接
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	// 代理中继 UDP
	relayLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		tcpLn.Close()
		return nil, err
	}
	// ePDG 模拟 UDP
	epdgLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		tcpLn.Close()
		relayLn.Close()
		return nil, err
	}

	s := &mockSocks5Server{
		tcpAddr: tcpLn.Addr().String(),
		udpAddr: relayLn.LocalAddr().String(),
		epdg:    epdgLn.LocalAddr().String(),
		tcpLn:   tcpLn,
		relayLn: relayLn,
		epdgLn:  epdgLn,
	}
	go s.serveSOCKS5(ctx)
	go s.serveRelay(ctx)
	go s.serveEPDG(ctx)
	return s, nil
}

func (s *mockSocks5Server) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.tcpLn.Close()
	s.relayLn.Close()
	s.epdgLn.Close()
}

func (s *mockSocks5Server) serveSOCKS5(ctx context.Context) {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			return
		}
		go s.handleSOCKS5(ctx, conn)
	}
}

func (s *mockSocks5Server) handleSOCKS5(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 版本协商
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// 回复无认证
	_, _ = conn.Write([]byte{0x05, 0x00})

	// UDP ASSOCIATE
	req := make([]byte, 10)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x03 {
		return
	}
	// 回复中继 UDP 端点地址
	host, portStr, _ := net.SplitHostPort(s.udpAddr)
	var portInt int
	fmt.Sscanf(portStr, "%d", &portInt)
	relayIP := net.ParseIP(host)
	resp := []byte{0x05, 0x00, 0x00, 0x01}
	resp = append(resp, relayIP.To4()...)
	resp = append(resp, byte(portInt>>8), byte(portInt))
	_, _ = conn.Write(resp)

	// 保持连接直到上下文取消（UDP Associate 生命周期）
	<-ctx.Done()
}

// serveRelay 从中继 UDP 把 SOCKS5 数据报转发给 ePDG，再把 ePDG 回包封装后返回客户端。
// 转发时使用独立 UDP socket（fw），ePDG 的回复会落到 fw 上，从而与客户端请求流隔离。
func (s *mockSocks5Server) serveRelay(ctx context.Context) {
	fw, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return
	}
	defer fw.Close()
	for {
		buf := make([]byte, 65535)
		n, src, err := s.relayLn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		payload, _, ok := socks5ParseUDPDatagram(buf[:n])
		if !ok || len(payload) == 0 {
			continue
		}
		if _, err := fw.WriteToUDP(payload, s.epdgLn.LocalAddr().(*net.UDPAddr)); err != nil {
			continue
		}
		_ = fw.SetReadDeadline(time.Now().Add(3 * time.Second))
		rn, _, err := fw.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		out := socks5WrapUDPDatagram(s.epdg, buf[:rn])
		if _, err := s.relayLn.WriteToUDP(out, src); err != nil {
			continue
		}
	}
}

// serveEPDG 模拟 ePDG 回声：收到数据后大写并附加后缀返回。
func (s *mockSocks5Server) serveEPDG(ctx context.Context) {
	for {
		buf := make([]byte, 65535)
		n, src, err := s.epdgLn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		payload := make([]byte, n+5)
		copy(payload, buf[:n])
		for i := 0; i < n; i++ {
			if payload[i] >= 'a' && payload[i] <= 'z' {
				payload[i] -= 32
			}
		}
		copy(payload[n:], "!EPDG")
		_, _ = s.epdgLn.WriteToUDP(payload, src)
	}
}

func TestSocks5UDPTransport_ExchangeIKE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, srv.epdg, "", 5*time.Second)

	resp, err := transport.ExchangeIKE(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("ExchangeIKE: %v", err)
	}
	expected := "HELLO!EPDG"
	if string(resp) != expected {
		t.Fatalf("ExchangeIKE 响应不匹配: got=%q want=%q", resp, expected)
	}
}

func TestSocks5UDPTransport_ESP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, srv.epdg, "", 5*time.Second)

	if err := transport.SendESPPacket(ctx, []byte("ESP_DATA")); err != nil {
		t.Fatalf("SendESPPacket: %v", err)
	}
	resp, err := transport.ReadESPPacket(ctx)
	if err != nil {
		t.Fatalf("ReadESPPacket: %v", err)
	}
	expected := "ESP_DATA!EPDG"
	if string(resp) != expected {
		t.Fatalf("ESP 响应不匹配: got=%q want=%q", resp, expected)
	}
}

func TestSocks5UDPTransport_ProxyUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: "127.0.0.1:1", Enabled: true}, "127.0.0.1:9999", "", 1*time.Second)

	_, err := transport.ExchangeIKE(ctx, []byte("test"))
	if err == nil {
		t.Fatal("期望连接失败，但成功了")
	}
	t.Logf("预期错误: %v", err)
}

func TestSocks5UDPTransport_Close(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, srv.epdg, "", 5*time.Second)
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := transport.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = transport.ExchangeIKE(ctx, []byte("test"))
	if err == nil {
		t.Fatal("关闭后 ExchangeIKE 应失败")
	}
}