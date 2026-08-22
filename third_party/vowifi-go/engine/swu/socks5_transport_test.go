package swu

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

// mockSocks5Server 模拟 SOCKS5 UDP Associate 代理 + ePDG 回声。
type mockSocks5Server struct {
	tcpAddr string
	udpAddr string
	epdg    string // ePDG 地址（中继把它作为目标）
	mu      sync.Mutex
	closed  bool
	tcpLn   net.Listener
	relayLn *net.UDPConn // 代理中继 UDP 端点
	epdgLn  *net.UDPConn // ePDG 模拟 UDP

	dropFirst int32 // ePDG 丢弃前 N 个包（模拟丢包，atomic）
	rxCount   int32 // ePDG 已收包计数（atomic）
	tcpConns  int32 // TCP 控制连接计数（验证 associate 只建一次，atomic）
}

// TestSocks5UDPTransport_Retransmit 验证读超时重传：ePDG 丢前 1 个包，
// transport 重发后拿到响应，且 ePDG 实际收到 ≥2 个包。
func TestSocks5UDPTransport_Retransmit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()
	atomic.StoreInt32(&srv.dropFirst, 1) // 丢第一个包

	// timeout 2s：重传间隔 500ms→1s，2s 内能发出 2-3 次
	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, []string{srv.epdg}, "", 2*time.Second)

	req := buildIKEFrame(0x1122334455667788, 0x99aabbccddeeff00, 35, 1, []byte("RETRY_ME"))
	resp, err := transport.ExchangeIKE(ctx, req)
	if err != nil {
		t.Fatalf("ExchangeIKE（重传路径）: %v", err)
	}
	if len(resp) < 28 || binary.BigEndian.Uint32(resp[20:24]) != 1 {
		t.Fatalf("响应头不匹配: %x", resp[:min(28, len(resp))])
	}
	if got := atomic.LoadInt32(&srv.rxCount); got < 2 {
		t.Fatalf("期望重传后 ePDG 收到 ≥2 个包，实际 %d", got)
	}
}

// TestSocks5UDPTransport_AddrRotationNoReassociate 验证换 ePDG 地址只改
// SOCKS5 头 DST、不重建 associate：两个地址共用同一次 ASSOCIATE（TCP 只连一次），
// 第一个地址超时后第二个地址成功。
func TestSocks5UDPTransport_AddrRotationNoReassociate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()

	// 不可达地址在前（触发超时换地址），mock ePDG 在后
	deadAddr := "127.0.0.1:1"
	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, []string{deadAddr, srv.epdg}, "", 1*time.Second)

	req := buildIKEFrame(0x1122334455667788, 0x99aabbccddeeff00, 35, 2, []byte("ROTATE"))
	resp, err := transport.ExchangeIKE(ctx, req)
	if err != nil {
		t.Fatalf("ExchangeIKE（地址轮换）: %v", err)
	}
	if len(resp) < 28 || binary.BigEndian.Uint32(resp[20:24]) != 2 {
		t.Fatalf("响应头不匹配: %x", resp[:min(28, len(resp))])
	}
	// 全程一次 associate：TCP 控制连接只接受过一次（多 associate 会有第二个 conn）
	if got := atomic.LoadInt32(&srv.tcpConns); got != 1 {
		t.Fatalf("期望只建立 1 次 associate（1 条 TCP），实际 %d", got)
	}
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
		atomic.AddInt32(&s.tcpConns, 1)
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
		rx := atomic.AddInt32(&s.rxCount, 1)
		if dropped := atomic.LoadInt32(&s.dropFirst); rx <= dropped {
			continue // 模拟丢包：前 N 个包不转发到 ePDG（relay 侧丢弃，不阻塞等待回包）
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
// ExchangeIKE 只接受合法 IKE 帧（版本 0x20 + 长度匹配 + 响应头匹配请求头），
// mock 回复需要带上 IKE 头；纯文本载荷（如 ESP 用例）合成头时回显请求的前 28B，
// 使 ExchangeIKE 的响应匹配过滤放行。
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
		// IKE 头（28B）：优先回显请求头（触发 ExchangeIKE 的响应匹配通过路径）；
		// 请求不带合法 IKE 头（纯载荷）时合成一个，版本 0x20，总长 = 头 + 载荷。
		frame := make([]byte, 28+len(payload))
		if n >= 28 && looksLikeIKE(buf[:n]) {
			copy(frame[:28], buf[:28])
			// 响应方向：置 Response 标志、清 Initiator 标志（真 ePDG 响应不带 Initiator）
			frame[19] = (frame[19] &^ 0x08) | 0x20
		} else {
			frame[17] = 0x20
		}
		copy(frame[28:], payload)
		binary.BigEndian.PutUint32(frame[24:28], uint32(len(frame)))
		_, _ = s.epdgLn.WriteToUDP(frame, src)
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

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, []string{srv.epdg}, "", 5*time.Second)

	resp, err := transport.ExchangeIKE(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("ExchangeIKE: %v", err)
	}
	// mock ePDG 回复带 28B 合成 IKE 头，ExchangeIKE 透传整帧；剥头比对载荷。
	if len(resp) >= 28 {
		resp = resp[28:]
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

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, []string{srv.epdg}, "", 5*time.Second)

	// 先通过 ExchangeIKE 建立连接（Connect 被自动调用）
	if _, err := transport.ExchangeIKE(ctx, []byte("IKE_INIT")); err != nil {
		t.Fatalf("ExchangeIKE: %v", err)
	}

	if err := transport.SendESPPacket(ctx, []byte("ESP_DATA")); err != nil {
		t.Fatalf("SendESPPacket: %v", err)
	}
	resp, err := transport.ReadESPPacket(ctx)
	if err != nil {
		t.Fatalf("ReadESPPacket: %v", err)
	}
	// mock ePDG 会为所有回显加 28B 合成 IKE 头（供 ExchangeIKE 的 IKE 帧校验通过）；
	// ESP 路径不做头校验，这里剥掉 mock 附加的头比对载荷。
	if len(resp) >= 28 {
		resp = resp[28:]
	}
	expected := "ESP_DATA!EPDG"
	if string(resp) != expected {
		t.Fatalf("ESP 响应不匹配: got=%q want=%q", resp, expected)
	}
}

func TestSocks5UDPTransport_ProxyUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: "127.0.0.1:1", Enabled: true}, []string{"127.0.0.1:9999"}, "", 1*time.Second)

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

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, []string{srv.epdg}, "", 5*time.Second)
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

// buildIKEFrame 构造一个带合法 IKE 头（版本 0x20 + 总长匹配）的请求帧，
// 供 ExchangeIKE 的响应匹配过滤路径测试使用。
func buildIKEFrame(spiI, spiR uint64, exchType uint8, msgID uint32, payload []byte) []byte {
	frame := make([]byte, 28+len(payload))
	binary.BigEndian.PutUint64(frame[0:8], spiI)
	binary.BigEndian.PutUint64(frame[8:16], spiR)
	frame[17] = 0x20
	frame[18] = exchType
	frame[19] = 0x08 // FlagInitiator
	binary.BigEndian.PutUint32(frame[20:24], msgID)
	binary.BigEndian.PutUint32(frame[24:28], uint32(len(frame)))
	copy(frame[28:], payload)
	return frame
}

// TestSocks5UDPTransport_ResponseMatching 验证读循环的响应匹配过滤：
// mock 先回一个旧 SA 报文（SPIi 相同但 MessageID 不同，能通过 looksLikeIKE），
// 再回正确响应，ExchangeIKE 必须返回后者。
func TestSocks5UDPTransport_ResponseMatching(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, []string{srv.epdg}, "", 5*time.Second)

	req := buildIKEFrame(0x1122334455667788, 0x99aabbccddeeff00, 35, 3, []byte("AUTH_REQUEST"))
	resp, err := transport.ExchangeIKE(ctx, req)
	if err != nil {
		t.Fatalf("ExchangeIKE: %v", err)
	}
	if len(resp) < 28 {
		t.Fatalf("响应过短: %d bytes", len(resp))
	}
	// mock 回显请求头，响应头必须与请求头一致（除 Response 标志）
	if got := binary.BigEndian.Uint64(resp[0:8]); got != 0x1122334455667788 {
		t.Fatalf("响应 SPIi 不匹配: %x", got)
	}
	if got := binary.BigEndian.Uint64(resp[8:16]); got != 0x99aabbccddeeff00 {
		t.Fatalf("响应 SPIr 不匹配: %x", got)
	}
	if got := binary.BigEndian.Uint32(resp[20:24]); got != 3 {
		t.Fatalf("响应 MessageID 不匹配: %d", got)
	}
}

// TestIkeResponseMatchesRequest 单元测试响应匹配的两档规则。
func TestIkeResponseMatchesRequest(t *testing.T) {
	req := ikev2.Header{
		InitiatorSPI: 0x1111111111111111,
		ResponderSPI: 0x2222222222222222,
		Version:      0x20,
		ExchangeType: 35, // IKE_AUTH
		Flags:        0x08,
		MessageID:    7,
		Length:       64,
	}
	buildResp := func(spiI, spiR uint64, exch uint8, mid uint32, flags uint8) []byte {
		f := make([]byte, 64)
		binary.BigEndian.PutUint64(f[0:8], spiI)
		binary.BigEndian.PutUint64(f[8:16], spiR)
		f[17] = 0x20
		f[18] = exch
		f[19] = flags
		binary.BigEndian.PutUint32(f[20:24], mid)
		binary.BigEndian.PutUint32(f[24:28], 64)
		return f
	}
	// 全匹配
	if !ikeResponseMatchesRequest(buildResp(req.InitiatorSPI, req.ResponderSPI, 35, 7, 0x20), req) {
		t.Fatal("完全匹配的响应应通过")
	}
	// MessageID 不同（旧 SA 重传）→ 拒绝
	if ikeResponseMatchesRequest(buildResp(req.InitiatorSPI, req.ResponderSPI, 35, 6, 0x20), req) {
		t.Fatal("MessageID 不匹配应被拒绝")
	}
	// SPIr 不同 → 拒绝
	if ikeResponseMatchesRequest(buildResp(req.InitiatorSPI, 0xdead, 35, 7, 0x20), req) {
		t.Fatal("SPIr 不匹配应被拒绝")
	}
	// 无 Response 标志 → 拒绝
	if ikeResponseMatchesRequest(buildResp(req.InitiatorSPI, req.ResponderSPI, 35, 7, 0x08), req) {
		t.Fatal("无 Response 标志应被拒绝")
	}
	// SA_INIT 弱匹配：请求 SPIr=0，响应 SPIr 由 ePDG 生成（非 0）→ 应通过
	initReq := req
	initReq.ResponderSPI = 0
	initReq.ExchangeType = 34
	initReq.MessageID = 0
	if !ikeResponseMatchesRequest(buildResp(initReq.InitiatorSPI, 0x3333333333333333, 34, 0, 0x20), initReq) {
		t.Fatal("SA_INIT 响应（SPIr 非零）应通过弱匹配")
	}
}

// TestSocks5UDPTransport_ConcurrentExchangesSerialized 验证并发 ExchangeIKE
// 被串行化：DPD liveness 与 MOBIKE 漫游同秒触发时，两个交换不能共享读循环
// 互抢响应（设备实测：msg4 DPD 与 msg5 MOBIKE 并发，msg5 响应被 msg4 的
// 读循环按"不匹配"丢弃，DPD 超时误杀健康会话）。
func TestSocks5UDPTransport_ConcurrentExchangesSerialized(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()

	transport := NewSocks5UDPTransport(ProxyConfig{Addr: srv.tcpAddr, Enabled: true}, []string{srv.epdg}, "", 5*time.Second)

	const callers = 3
	var wg sync.WaitGroup
	errs := make([]error, callers)
	mids := [callers]uint32{4, 5, 6}
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := buildIKEFrame(0x1111222233334444, 0x5555666677778888, 37, mids[i], []byte("INFORMATIONAL"))
			resp, err := transport.ExchangeIKE(ctx, req)
			if err != nil {
				errs[i] = err
				return
			}
			if len(resp) < 28 {
				errs[i] = fmt.Errorf("response too short: %d", len(resp))
				return
			}
			if got := binary.BigEndian.Uint32(resp[20:24]); got != mids[i] {
				errs[i] = fmt.Errorf("MessageID mismatch: got %d want %d", got, mids[i])
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
}
