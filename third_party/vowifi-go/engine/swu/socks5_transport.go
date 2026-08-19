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
)

// Socks5UDPTransport 通过 SOCKS5 UDP Associate 中继 IKE/ESP 流量到 ePDG。
// 使用自定义 SOCKS5 实现（兼容 ePDG 代理的 UDP 中继特性）。
type Socks5UDPTransport struct {
	proxyAddr string
	username  string
	password  string
	localAddr string
	timeout   time.Duration

	mu       sync.Mutex
	control  net.Conn // SOCKS5 TCP 控制连接，UDP Associate 期间必须保持打开
	relay    *net.UDPConn
	relayEP  *net.UDPAddr
	closed   bool

	remoteAddr string       // 当前活跃的 ePDG 地址
	addresses  []string     // 候选 ePDG 地址列表
	addrIndex  int
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

// Connect 建立 SOCKS5 UDP Associate 会话。
func (t *Socks5UDPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("socks5 transport closed")
	}
	if t.relay != nil {
		return nil
	}
	if t.proxyAddr == "" {
		return errors.New("socks5 proxy address is empty")
	}
	return t.dialAddr(ctx, t.remoteAddr)
}

// dialAddr 建立到指定 ePDG 地址的 SOCKS5 UDP Associate 会话。
func (t *Socks5UDPTransport) dialAddr(ctx context.Context, addr string) error {
	// TCP 连接到代理，完成 SOCKS5 握手 + UDP ASSOCIATE
	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.proxyAddr)
	if err != nil {
		return fmt.Errorf("socks5 控制连接失败: %w", err)
	}
	if d, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(d)
	} else {
		_ = control.SetDeadline(time.Now().Add(t.timeout))
	}
	// 注意：SOCKS5 UDP Associate 要求 TCP 控制连接在整个 UDP 会话期间保持打开，
	// 因此不能 defer control.Close()。关闭统一在 closeConn() 中处理。

	// 版本协商
	methods := []byte{0x00}
	if t.username != "" {
		methods = []byte{0x02, 0x00}
	}
	if _, err := control.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("socks5 版本协商失败: %w", err)
	}
	resp := make([]byte, 2)
	if err := readFull(control, resp); err != nil {
		return fmt.Errorf("socks5 版本协商响应失败: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5 版本不匹配: 0x%02x", resp[0])
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		if err := socks5SendUserPass(control, t.username, t.password); err != nil {
			return err
		}
	default:
		return fmt.Errorf("socks5 认证方法不被代理接受: 0x%02x", resp[1])
	}

	// UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := control.Write(req); err != nil {
		return fmt.Errorf("socks5 UDP ASSOCIATE 发送失败: %w", err)
	}
	reply, err := socks5ReadAssociateReply(control)
	if err != nil {
		return fmt.Errorf("socks5 UDP ASSOCIATE 回复失败: %w", err)
	}
	relayAddr := fmt.Sprintf("%s:%d", reply.IP, reply.Port)
	relayUDP, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		return fmt.Errorf("socks5 中继地址解析失败: %w", err)
	}

	// 创建 UDP socket 连接到中继端
	udpConn, err := net.DialUDP("udp", nil, relayUDP)
	if err != nil {
		return fmt.Errorf("socks5 UDP 中继连接失败: %w", err)
	}
	t.relay = udpConn
	t.relayEP = relayUDP
	t.control = control
	t.remoteAddr = addr
	return nil
}

// ExchangeIKE 通过 SOCKS5 UDP Associate 中继一次 IKE 请求-响应。
func (t *Socks5UDPTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if err := t.Connect(ctx); err != nil {
		return nil, err
	}

	t.mu.Lock()
	relay := t.relay
	addrs := t.addresses
	startIdx := t.addrIndex
	t.mu.Unlock()
	if relay == nil {
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
			relay = t.relay
			t.mu.Unlock()
		}

		// 构造 SOCKS5 UDP 数据报并发送
		dgram := socks5WrapUDPDatagram(addr, request)
		if _, err := relay.Write(dgram); err != nil {
			lastErr = fmt.Errorf("socks5 IKE 发送失败: %w", err)
			continue
		}
		_ = relay.SetReadDeadline(time.Now().Add(t.timeout))

		// 读取响应
		buf := make([]byte, 65535)
		n, err := relay.Read(buf)
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
		_ = relay.SetReadDeadline(time.Time{})

		// 解析 SOCKS5 UDP 数据报
		payload, _, ok := socks5ParseUDPDatagram(buf[:n])
		if !ok {
			lastErr = fmt.Errorf("socks5 IKE 响应格式错误: got %d bytes", n)
			continue
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
	relay := t.relay
	addr := t.remoteAddr
	t.mu.Unlock()
	if relay == nil {
		return errors.New("socks5 transport not connected")
	}
	dgram := socks5WrapUDPDatagram(addr, data)
	_, err := relay.Write(dgram)
	return err
}

// ReadESPPacket 通过 SOCKS5 UDP Associate 中继读取一个 ESP 数据包。
func (t *Socks5UDPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	t.mu.Lock()
	relay := t.relay
	t.mu.Unlock()
	if relay == nil {
		return nil, errors.New("socks5 transport not connected")
	}
	if d, ok := ctx.Deadline(); ok {
		_ = relay.SetReadDeadline(d)
	} else {
		_ = relay.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	buf := make([]byte, 65535)
	n, err := relay.Read(buf)
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

func (t *Socks5UDPTransport) closeConn() {
	if t.relay != nil {
		_ = t.relay.Close()
		t.relay = nil
	}
	if t.control != nil {
		_ = t.control.Close()
		t.control = nil
	}
}

// socks5 辅助函数

func readFull(r net.Conn, b []byte) error {
	n := 0
	for n < len(b) {
		nn, err := r.Read(b[n:])
		n += nn
		if err != nil {
			return err
		}
	}
	return nil
}

func socks5SendUserPass(control net.Conn, username, password string) error {
	req := []byte{0x01, byte(len(username))}
	req = append(req, []byte(username)...)
	req = append(req, byte(len(password)))
	req = append(req, []byte(password)...)
	if _, err := control.Write(req); err != nil {
		return fmt.Errorf("socks5 密码认证发送失败: %w", err)
	}
	resp := make([]byte, 2)
	if err := readFull(control, resp); err != nil {
		return fmt.Errorf("socks5 密码认证响应失败: %w", err)
	}
	if resp[0] != 0x01 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 密码认证拒绝")
	}
	return nil
}

type socks5Reply struct {
	IP   net.IP
	Port int
}

func socks5ReadAssociateReply(control net.Conn) (*socks5Reply, error) {
	header := make([]byte, 4)
	if err := readFull(control, header); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 回复头读取失败: %w", err)
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 回复状态错误: ver=0x%02x rep=0x%02x", header[0], header[1])
	}
	var addr net.IP
	switch header[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if err := readFull(control, b); err != nil {
			return nil, fmt.Errorf("socks5 UDP ASSOCIATE IPv4 地址读取失败: %w", err)
		}
		addr = net.IPv4(b[0], b[1], b[2], b[3])
	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		if err := readFull(control, lenBuf); err != nil {
			return nil, err
		}
		host := make([]byte, lenBuf[0])
		if err := readFull(control, host); err != nil {
			return nil, err
		}
		addr = net.ParseIP(string(host))
		if addr == nil {
			addr = net.IPv4zero
		}
	case 0x04: // IPv6
		b := make([]byte, 16)
		if err := readFull(control, b); err != nil {
			return nil, fmt.Errorf("socks5 UDP ASSOCIATE IPv6 地址读取失败: %w", err)
		}
		addr = net.IP(b)
	default:
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 未知地址类型: 0x%02x", header[3])
	}
	portBuf := make([]byte, 2)
	if err := readFull(control, portBuf); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 端口读取失败: %w", err)
	}
	return &socks5Reply{IP: addr, Port: int(binary.BigEndian.Uint16(portBuf))}, nil
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