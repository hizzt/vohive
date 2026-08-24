package swu

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/esp"
	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

func TestPacketSessionSendsAndReceivesIPv4AndIPv6(t *testing.T) {
	aToB := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: aToB,
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(false),
		Transport: &captureESPPacketTransport{},
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}

	ipv4 := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd}
	if err := a.SendInnerPacket(context.Background(), ipv4); err != nil {
		t.Fatalf("SendInnerPacket(ipv4) error = %v", err)
	}
	if len(aToB.packets) != 1 {
		t.Fatalf("captured packets=%d, want 1", len(aToB.packets))
	}
	got4, err := b.ReceiveESPPacket(context.Background(), aToB.packets[0])
	if err != nil {
		t.Fatalf("ReceiveESPPacket(ipv4) error = %v", err)
	}
	if got4.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got4.Payload, ipv4) || got4.Sequence != 1 {
		t.Fatalf("got4=%+v payload=%x", got4, got4.Payload)
	}

	ipv6 := []byte{0x60, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}
	if err := a.SendInnerPacket(context.Background(), ipv6); err != nil {
		t.Fatalf("SendInnerPacket(ipv6) error = %v", err)
	}
	got6, err := b.ReceiveESPPacket(context.Background(), aToB.packets[1])
	if err != nil {
		t.Fatalf("ReceiveESPPacket(ipv6) error = %v", err)
	}
	if got6.NextHeader != esp.NextHeaderIPv6 || !bytes.Equal(got6.Payload, ipv6) || got6.Sequence != 2 {
		t.Fatalf("got6=%+v payload=%x", got6, got6.Payload)
	}

	outStats := a.PacketStats()
	if outStats.OutboundInnerPackets != 2 || outStats.OutboundInnerBytes != uint64(len(ipv4)+len(ipv6)) || outStats.OutboundESPPackets != 2 {
		t.Fatalf("out stats=%+v", outStats)
	}
	inStats := b.PacketStats()
	if inStats.InboundInnerPackets != 2 || inStats.InboundInnerBytes != uint64(len(ipv4)+len(ipv6)) || inStats.InboundESPPackets != 2 {
		t.Fatalf("in stats=%+v", inStats)
	}
}

func TestPacketSessionDefaultResultIsReady(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	result := session.Result()
	if !result.IsReady() || result.Mode != DataplaneModeUserspace || result.Reason == "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestPacketSessionResultClonesDNSServers(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			DNSServers:       []string{"10.0.0.1"},
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	result := session.Result()
	result.DNSServers[0] = "198.51.100.53"
	if got := session.Result().DNSServers[0]; got != "10.0.0.1" {
		t.Fatalf("Result() DNS=%q, want original", got)
	}
}

func TestPacketSessionReadInnerPacketUsesReadableTransport(t *testing.T) {
	wire := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	inner := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad}
	if err := a.SendInnerPacket(context.Background(), inner); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	got, err := b.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket() error = %v", err)
	}
	if got.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got.Payload, inner) {
		t.Fatalf("got=%+v payload=%x", got, got.Payload)
	}
	stats := b.PacketStats()
	if stats.InboundInnerPackets != 1 || stats.InboundESPPackets != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionRejectsReplayAndCountsDrop(t *testing.T) {
	transport := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	if err := a.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	if _, err := b.ReceiveESPPacket(context.Background(), transport.packets[0]); err != nil {
		t.Fatalf("ReceiveESPPacket(first) error = %v", err)
	}
	if _, err := b.ReceiveESPPacket(context.Background(), transport.packets[0]); !errors.Is(err, esp.ErrReplay) {
		t.Fatalf("ReceiveESPPacket(replay) err=%v, want ErrReplay", err)
	}
	stats := b.PacketStats()
	if stats.InboundErrors != 1 || stats.ReplayDrops != 1 || stats.InvalidDrops != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionCloseRejectsTrafficAndClosesTransport(t *testing.T) {
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !transport.closed {
		t.Fatalf("transport was not closed")
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00}); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("SendInnerPacket() err=%v, want ErrPacketTunnelClosed", err)
	}
	if _, err := session.ReceiveESPPacket(context.Background(), []byte{1, 2, 3}); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("ReceiveESPPacket() err=%v, want ErrPacketTunnelClosed", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
}

func TestPacketSessionCountsUnsupportedInnerPacket(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x10, 0x00}); !errors.Is(err, ErrUnsupportedInnerPacket) {
		t.Fatalf("SendInnerPacket() err=%v, want ErrUnsupportedInnerPacket", err)
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.UnsupportedDrops != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionCountsTransportFailure(t *testing.T) {
	wantErr := errors.New("send failed")
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA: packetChildSA(true),
		Transport: ESPPacketTransportFunc(func(context.Context, []byte) error {
			return wantErr
		}),
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); !errors.Is(err, wantErr) {
		t.Fatalf("SendInnerPacket() err=%v, want send failed", err)
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.OutboundInnerPackets != 0 || stats.OutboundESPPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

type captureESPPacketTransport struct {
	mu      sync.Mutex
	packets [][]byte
	closed  bool
}

func (t *captureESPPacketTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.packets = append(t.packets, append([]byte(nil), packet...))
	return nil
}

func (t *captureESPPacketTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if len(t.packets) == 0 {
		return nil, errors.New("no packets")
	}
	packet := append([]byte(nil), t.packets[0]...)
	t.packets = t.packets[1:]
	return packet, nil
}

func (t *captureESPPacketTransport) Close(ctx context.Context) error {
	t.closed = true
	return nil
}

func packetChildSA(aToB bool) ikev2.ChildSAResult {
	aOutbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x10}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x20}, 32),
	}
	aInbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x30}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x40}, 32),
	}
	child := ikev2.ChildSAResult{
		LocalSPI:  []byte{0x11, 0x11, 0x11, 0x11},
		RemoteSPI: []byte{0x22, 0x22, 0x22, 0x22},
		Keys: ikev2.ChildSAKeys{
			Profile:  ikev2.ESPKeyProfile{IntegrityID: ikev2.INTEG_HMAC_SHA2_256_128},
			Outbound: aOutbound,
			Inbound:  aInbound,
		},
	}
	if aToB {
		return child
	}
	child.LocalSPI = []byte{0x22, 0x22, 0x22, 0x22}
	child.RemoteSPI = []byte{0x11, 0x11, 0x11, 0x11}
	child.Keys.Outbound = aInbound
	child.Keys.Inbound = aOutbound
	return child
}

// TestReadInnerPacketDropsInvalidWithoutKillingSession 坏包不死会话：
// ICV 损坏/未知 SPI/重放包是 rekey 过渡期与网络噪声的常态（设备实证
// 2026-08-24：rekey 后新 SA 首包在旧 SA 视角 ICV 必然失败，曾把 pump
// 杀掉造成 30min 周期断链）。ReadInnerPacket 必须丢弃坏包继续读到好包，
// 会话与 pump 都保持存活（RFC 4303 §3.4.3；VoCat 同语义）。
func TestReadInnerPacketDropsInvalidWithoutKillingSession(t *testing.T) {
	wire := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	inner := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad}
	if err := a.SendInnerPacket(context.Background(), inner); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	good := append([]byte(nil), wire.packets[0]...)
	wire.packets = nil

	// 坏包 1：ICV 损坏（篡改尾部 ICV 字节）。
	corrupt := append([]byte(nil), good...)
	corrupt[len(corrupt)-1] ^= 0xff
	// 坏包 2：完全伪造字节（长度合法但内容随机）。
	forged := make([]byte, 8+16+16+16)
	for i := range forged {
		forged[i] = byte(i * 7)
	}
	// 坏包 3：截断包。
	truncated := append([]byte(nil), good[:len(good)/2]...)
	wire.packets = append(wire.packets, corrupt, forged, truncated, good)

	got, err := b.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket() after bad packets error = %v（会话应存活）", err)
	}
	if got.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got.Payload, inner) {
		t.Fatalf("got=%+v payload=%x（应穿透 3 个坏包读到好包）", got, got.Payload)
	}
	stats := b.PacketStats()
	if stats.InboundESPPackets != 1 {
		t.Fatalf("stats=%+v（只有好包计入）", stats)
	}
	if wire.closed {
		t.Fatalf("会话被误关")
	}
}

// TestReadInnerPacketDropsReplayWithoutKillingSession 重放包丢弃后会话存活
// （此前 ReceiveESPPacket 的 ErrReplay 会冒泡杀 pump）。
func TestReadInnerPacketDropsReplayWithoutKillingSession(t *testing.T) {
	transport := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	wire := &captureESPPacketTransport{}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	if err := a.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	packet := transport.packets[0]
	// 重放同一包两次 + 一个新好包。
	a2 := a
	_ = a2
	if err := a.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x15}); err != nil {
		t.Fatalf("SendInnerPacket(2) error = %v", err)
	}
	wire.packets = append(wire.packets, packet, packet, transport.packets[1])
	// 第一次读到原包（首次见到，非重放）。
	got, err := b.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket(first) error = %v", err)
	}
	if !bytes.Equal(got.Payload, []byte{0x45, 0x00, 0x00, 0x14}) {
		t.Fatalf("payload=%x", got.Payload)
	}
	// 第二次读到重放包（丢弃）后穿透到新包——会话存活。
	got, err = b.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket() after replay error = %v（会话应存活）", err)
	}
	if !bytes.Equal(got.Payload, []byte{0x45, 0x00, 0x00, 0x15}) {
		t.Fatalf("payload=%x（应丢弃重放包读到新包）", got.Payload)
	}
}

// withShrunkLiveness 时限压缩到测试可等的时间量级。
func withShrunkLiveness(t *testing.T) {
	t.Helper()
	oldInterval, oldThreshold, oldTimeout, oldMax := livenessProbeInterval, livenessIdleProbeThreshold, livenessProbeTimeout, livenessMaxProbeFailures
	livenessProbeInterval = 40 * time.Millisecond
	livenessIdleProbeThreshold = 120 * time.Millisecond
	livenessProbeTimeout = 200 * time.Millisecond
	livenessMaxProbeFailures = 3
	t.Cleanup(func() {
		livenessProbeInterval = oldInterval
		livenessIdleProbeThreshold = oldThreshold
		livenessProbeTimeout = oldTimeout
		livenessMaxProbeFailures = oldMax
	})
}

// 空闲（无下行）但未到升级阈值：只发 NAT-T 单字节，不发 ESP 主动探测。
func TestLivenessIdleSendsOnlyNATTKkeepalive(t *testing.T) {
	withShrunkLiveness(t)
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:         packetChildSA(true),
		Transport:       transport,
		Result:          TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
		LivenessHandler: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	defer session.Close(context.Background())
	// 拉长空闲（绕过升级阈值）：只允许 NAT-T，不允许 ESP 探测出站。
	session.mu.Lock()
	session.lastInbound = time.Now().Add(-livenessIdleProbeThreshold * 10)
	session.mu.Unlock()
	session.StartLivenessLoop(context.Background())
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		transport.mu.Lock()
		n := len(transport.packets)
		transport.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(transport.packets) == 0 {
		t.Fatal("NAT-T keepalive 未发出")
	}
	for _, p := range transport.packets {
		if len(p) != 1 || p[0] != 0xff {
			t.Fatalf("空闲未到阈值时出现了非 NAT-T 出站包: %x", p)
		}
	}
}

// 有持续下行流量：零保活出站（不发 NAT-T 也不发探测）。
func TestLivenessQuietWhenTrafficFlows(t *testing.T) {
	withShrunkLiveness(t)
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:         packetChildSA(true),
		Transport:       transport,
		Result:          TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
		LivenessHandler: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	defer session.Close(context.Background())
	session.StartLivenessLoop(context.Background())
	// 模拟持续下行刷新 lastInbound。
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				session.mu.Lock()
				session.lastInbound = time.Now()
				session.mu.Unlock()
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	if n := len(transport.packets); n != 0 {
		t.Fatalf("有下行流量时应零保活出站, got %d 包", n)
	}
}

// 持续无下行且探测一直失败：连续失败达到阈值才拆链。
func TestLivenessTearsDownAfterConsecutiveFailures(t *testing.T) {
	withShrunkLiveness(t)
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA: packetChildSA(true),
		Transport: &livenessFailTransport{
			inner:   transport,
			failFor: func(b []byte) bool { return len(b) != 1 || b[0] != 0xff },
		},
		Result:          TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true, RemoteInnerIP: "192.0.2.1", LocalInnerIP: "192.0.2.9"},
		LivenessHandler: func(context.Context) error { return errors.New("dpd dead") },
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	session.mu.Lock()
	session.lastInbound = time.Now().Add(-livenessIdleProbeThreshold * 10)
	session.mu.Unlock()
	session.StartLivenessLoop(context.Background())
	// livenessMaxProbeFailures=3 + 升级阈值前有若干 NAT-T tick，1.2s 足够收敛。
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if session.closed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	session.mu.Lock()
	closed := session.closed
	session.mu.Unlock()
	if !closed {
		t.Fatal("连续探测失败达到阈值后应拆链")
	}
}

// livenessFailTransport 只让 NAT-T 单字节包通过，其余（ESP 探测）全部失败，
// 用来制造"链路只能发不能收应答"的死链。
type livenessFailTransport struct {
	inner   *captureESPPacketTransport
	failFor func([]byte) bool
}

func (t *livenessFailTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	if t.failFor(packet) {
		return errors.New("link dead for probes")
	}
	return t.inner.SendESPPacket(ctx, packet)
}

func (t *livenessFailTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	return t.inner.ReadESPPacket(ctx)
}

func (t *livenessFailTransport) Close(ctx context.Context) error {
	return t.inner.Close(ctx)
}
