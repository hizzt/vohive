package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
	"github.com/txthinking/socks5"
)

// Socks5UDPTransport 通过 SOCKS5 UDP Associate 中继 IKE/ESP 流量到 ePDG。
// 使用 txthinking 做 TCP 握手 + UDP ASSOCIATE，是否保活 TCP 控制连接由 carrier profile 决定。
// UDP 读写使用手动封装/解封 SOCKS5 数据报（兼容代理行为）。
type Socks5UDPTransport struct {
	proxyAddr  string
	username   string
	password   string
	localAddr  string
	timeout    time.Duration

	mu       sync.Mutex
	client   *socks5.Client
	udpConn  *net.UDPConn       // 手动 UDP 连接（非 txthinking 的 conn）
	relayEP  *net.UDPAddr
	closed   bool

	remoteAddr string       // 当前活跃的 ePDG 地址
	addresses  []string     // 候选 ePDG 地址列表
	addrIndex  int
	useNATT    bool         // NAT 检测后切换到 4500 端口并加 NAT-T marker

	controlConn      net.Conn
	keepControlAlive bool
}

var _ ikev2.InitTransport = (*Socks5UDPTransport)(nil)
var _ ESPPacketReadWriteTransport = (*Socks5UDPTransport)(nil)
var _ ESPPacketTransportCloser = (*Socks5UDPTransport)(nil)

// NewSocks5UDPTransport 构造 SOCKS5 UDP Associate 传输层。
func NewSocks5UDPTransport(proxy ProxyConfig, remoteAddrs []string, localAddr string, timeout time.Duration) *Socks5UDPTransport {
	if len(remoteAddrs) == 0 {
		remoteAddrs = []string{""}
	}
	t := &Socks5UDPTransport{
		proxyAddr:  strings.TrimSpace(proxy.Addr),
		username:   proxy.Username,
		password:   proxy.Password,
		localAddr:  strings.TrimSpace(localAddr),
		addresses:  remoteAddrs,
		remoteAddr: remoteAddrs[0],
	}
	if timeout > 0 {
		t.timeout = timeout
	} else {
		t.timeout = 8 * time.Second
	}
	return t
}

func (t *Socks5UDPTransport) SetKeepControlAlive(keep bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.keepControlAlive = keep
}

func (t *Socks5UDPTransport) KeepControlAlive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.keepControlAlive
}

// Connect 建立 SOCKS5 UDP Associate 会话。
func (t *Socks5UDPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("socks5 transport closed")
	}
	if t.udpConn != nil {
		return nil
	}
	if t.proxyAddr == "" {
		return errors.New("socks5 proxy address is empty")
	}
	return t.dialAddr(ctx, t.remoteAddr)
}

// dialAddr 建立到指定 ePDG 地址的 SOCKS5 UDP Associate 会话。
func (t *Socks5UDPTransport) dialAddr(ctx context.Context, addr string) error {
	tc := int(t.timeout.Seconds())
	cl, err := socks5.NewClient(t.proxyAddr, t.username, t.password, tc, tc)
	if err != nil {
		return fmt.Errorf("socks5 client 创建失败: %w", err)
	}
	// 使用 txthinking 完成 TCP 握手 + UDP ASSOCIATE
	conn, err := cl.DialWithLocalAddr("udp", t.localAddr, addr, nil)
	if err != nil {
		return fmt.Errorf("socks5 UDP associate 失败: %w", err)
	}
	// DialWithLocalAddr 内部创建新的 Client 副本，需要从返回的 conn 取回
	realClient, ok := conn.(*socks5.Client)
	if !ok || realClient.UDPConn == nil {
		return fmt.Errorf("socks5 client 类型错误: %T", conn)
	}
	t.client = realClient

	// 获取 txthinking 内部创建的 UDPConn 的远端地址（中继地址）
	relayAddr := realClient.UDPConn.RemoteAddr()
	relayUDP, ok := relayAddr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("socks5 relay 地址类型错误: %T", relayAddr)
	}
	t.relayEP = relayUDP

	// 创建独立的 UDP 连接（与 txthinking 的 UDPConn 不同，避免 Read/Write 封装干扰）
	laddr, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	udpConn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return fmt.Errorf("socks5 UDP 创建失败: %w", err)
	}
	t.udpConn = udpConn

	if t.keepControlAlive {
		t.controlConn = cl.TCPConn
	} else {
		if cl.TCPConn != nil {
			cl.TCPConn.Close()
		}
		t.controlConn = nil
	}

	t.remoteAddr = addr
	return nil
}

// ExchangeIKE 通过 SOCKS5 UDP Associate 中继一次 IKE 请求-响应。
func (t *Socks5UDPTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if err := t.Connect(ctx); err != nil {
		return nil, err
	}

	t.mu.Lock()
	udpConn := t.udpConn
	relayEP := t.relayEP
	addrs := t.addresses
	startIdx := t.addrIndex
	t.mu.Unlock()
	if udpConn == nil || relayEP == nil {
		return nil, errors.New("socks5 relay not ready")
	}

	var lastErr error
	for i := startIdx; i < len(addrs); i++ {
		addr := addrs[i]
		// 如果地址变了，需要重新建立 UDP associate
		if i > startIdx || (i == 0 && addr != t.remoteAddr) {
			t.mu.Lock()
			t.closeConn()
			err := t.dialAddr(ctx, addr)
			if err != nil {
				t.mu.Unlock()
				lastErr = err
				continue
			}
			udpConn = t.udpConn
			relayEP = t.relayEP
			t.mu.Unlock()
		}

// 如果 NAT 检测到需要 NAT-T，IKE 报文前加 4 字节 0x00 marker
			ikeData := request
			if t.useNATT {
				ikeData = append([]byte{0, 0, 0, 0}, request...)
			}
			// 手动封装 SOCKS5 UDP 数据报
			dgram := socks5WrapUDPDatagram(addr, ikeData)
		if _, err := udpConn.WriteToUDP(dgram, relayEP); err != nil {
			lastErr = fmt.Errorf("socks5 IKE 发送失败: %w", err)
			continue
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(t.timeout))

		// 读取响应
		buf := make([]byte, 65535)
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if i+1 < len(addrs) {
				lastErr = fmt.Errorf("socks5 IKE 响应超时(%s): %w", addr, err)
				t.mu.Lock()
				t.closeConn()
				t.addrIndex = i + 1
				t.mu.Unlock()
			} else {
				lastErr = fmt.Errorf("socks5 IKE 响应超时(%s): %w", addr, err)
			}
			continue
		}
		_ = udpConn.SetReadDeadline(time.Time{})

		// 解析 SOCKS5 UDP 数据报
		payload, dstAddr, ok := socks5ParseUDPDatagram(buf[:n])
		if !ok {
			lastErr = fmt.Errorf("socks5 IKE 响应格式错误: got %d bytes, first 32: %x", n, buf[:min(32, n)])
			continue
		}
		_ = dstAddr

		// NAT-T 模式下响应报文也带 4 字节 0x00 marker，剥离后返回 IKE 报文
		if t.useNATT && len(payload) >= 4 && payload[0] == 0 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0 {
			payload = payload[4:]
		}

		// 成功
		t.mu.Lock()
		t.remoteAddr = addr
		t.addrIndex = i
		t.mu.Unlock()
		return payload, nil
	}
	return nil, lastErr
}

// SendESPPacket 通过 SOCKS5 UDP Associate 中继一个 ESP 数据包。
func (t *Socks5UDPTransport) SendESPPacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	udpConn := t.udpConn
	relayEP := t.relayEP
	addr := t.remoteAddr
	t.mu.Unlock()
	if udpConn == nil || relayEP == nil {
		return errors.New("socks5 transport not connected")
	}
	dgram := socks5WrapUDPDatagram(addr, data)
	_, err := udpConn.WriteToUDP(dgram, relayEP)
	return err
}

// ReadESPPacket 通过 SOCKS5 UDP Associate 中继读取一个 ESP 数据包。
func (t *Socks5UDPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	t.mu.Lock()
	udpConn := t.udpConn
	t.mu.Unlock()
	if udpConn == nil {
		return nil, errors.New("socks5 transport not connected")
	}
	if d, ok := ctx.Deadline(); ok {
		_ = udpConn.SetReadDeadline(d)
	} else {
		_ = udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	buf := make([]byte, 65535)
	n, _, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	payload, _, ok := socks5ParseUDPDatagram(buf[:n])
	if !ok {
		return nil, fmt.Errorf("socks5 ESP 响应格式错误: got %d bytes", n)
	}
	return payload, nil
}

// Close 关闭 SOCKS5 传输层。
func (t *Socks5UDPTransport) Close(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.closeConn()
	return nil
}

// RemoteAddr 返回当前活跃的 ePDG 远程地址。
func (t *Socks5UDPTransport) RemoteAddr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remoteAddr
}

// SwitchToNATT 在 NAT 检测后将远程端口切换为 4500（NAT-T），并启用 NAT-T marker。
// 需要重新建立 UDP Associate 连接。
func (t *Socks5UDPTransport) SwitchToNATT() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.useNATT {
		return
	}
	t.useNATT = true
	// 将所有地址端口改为 4500
	for i, a := range t.addresses {
		if host, _, err := net.SplitHostPort(a); err == nil {
			t.addresses[i] = net.JoinHostPort(host, "4500")
		}
	}
	// 更新当前地址并重置连接
	t.remoteAddr = ""
	t.addrIndex = 0
	t.closeConn()
}

func (t *Socks5UDPTransport) closeConn() {
	if t.udpConn != nil {
		_ = t.udpConn.Close()
		t.udpConn = nil
	}
	if t.controlConn != nil {
		_ = t.controlConn.Close()
		t.controlConn = nil
	}
	if t.client != nil {
		_ = t.client.Close()
		t.client = nil
	}
	t.relayEP = nil
}

// socks5WrapUDPDatagram 构造 SOCKS5 UDP 数据报（RSV + FRAG + ATYP + DST.ADDR + DST.PORT + DATA）。
func socks5WrapUDPDatagram(remoteAddr string, payload []byte) []byte {
	host, portStr, _ := net.SplitHostPort(remoteAddr)
	port := 500
	if p, err := strconv.Atoi(portStr); err == nil {
		port = p
	}
	out := []byte{0x00, 0x00, 0x00} // RSV(2) + FRAG(1)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, 0x01) // IPv4
			out = append(out, ip4...)
		} else {
			out = append(out, 0x04) // IPv6
			out = append(out, ip.To16()...)
		}
	} else {
		out = append(out, 0x03) // 域名
		out = append(out, byte(len(host)))
		out = append(out, host...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	out = append(out, payload...)
	return out
}

// socks5ParseUDPDatagram 解析 SOCKS5 UDP 数据报，返回 payload 和目标地址。
func socks5ParseUDPDatagram(data []byte) (payload []byte, dstAddr string, ok bool) {
	if len(data) < 4 {
		return nil, "", false
	}
	if data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x00 {
		return nil, "", false
	}
	pos := 4
	var host string
	switch data[3] {
	case 0x01: // IPv4
		if len(data) < pos+4+2 {
			return nil, "", false
		}
		host = net.IP(data[pos : pos+4]).String()
		pos += 4
	case 0x03: // 域名
		if len(data) < pos+1 {
			return nil, "", false
		}
		hlen := int(data[pos])
		pos++
		if len(data) < pos+hlen+2 {
			return nil, "", false
		}
		host = string(data[pos : pos+hlen])
		pos += hlen
	case 0x04: // IPv6
		if len(data) < pos+16+2 {
			return nil, "", false
		}
		host = net.IP(data[pos : pos+16]).String()
		pos += 16
	default:
		return nil, "", false
	}
	port := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	return data[pos:], net.JoinHostPort(host, strconv.Itoa(port)), true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}