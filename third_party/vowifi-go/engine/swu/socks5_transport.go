package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

// Socks5UDPTransport 通过 SOCKS5 UDP Associate 中继 IKE/ESP 流量到 ePDG。
// 同时满足 InitTransport（IKE 请求-响应）与 ESPPacketReadWriteTransport（ESP 包收发）。
// 与直连 UDP 的区别：所有数据报先封装成 SOCKS5 UDP 数据报发到代理分配的中继端点，
// 由代理转发给目标 ePDG；回程数据由代理从 ePDG 收下后同样封装返回。
type Socks5UDPTransport struct {
	proxyAddr  string
	username   string
	password   string
	remoteAddr string // ePDG 地址 host:port
	localAddr  string // 本端 UDP 地址（可选，用于绑定出端口）
	timeout    time.Duration

	mu      sync.Mutex
	control net.Conn // SOCKS5 TCP 控制连接（UDP Associate 生命周期内保持）
	relay   *net.UDPConn
	relayEP net.Addr // 代理分配的中继 UDP 端点
	closed  bool
}

var _ ikev2.InitTransport = (*Socks5UDPTransport)(nil)
var _ ESPPacketReadWriteTransport = (*Socks5UDPTransport)(nil)
var _ ESPPacketTransportCloser = (*Socks5UDPTransport)(nil)

// NewSocks5UDPTransport 构造 SOCKS5 UDP Associate 传输层。
// proxy 提供代理地址与可选的用户名/密码；remoteAddr 是目标 ePDG 地址（host:port）。
func NewSocks5UDPTransport(proxy ProxyConfig, remoteAddr, localAddr string, timeout time.Duration) *Socks5UDPTransport {
	t := &Socks5UDPTransport{
		proxyAddr:  strings.TrimSpace(proxy.Addr),
		username:   proxy.Username,
		password:   proxy.Password,
		remoteAddr: strings.TrimSpace(remoteAddr),
		localAddr:  strings.TrimSpace(localAddr),
	}
	if timeout > 0 {
		t.timeout = timeout
	} else {
		t.timeout = 8 * time.Second
	}
	return t
}

// Connect 建立 SOCKS5 UDP Associate 会话：TCP 握手 → UDP ASSOCIATE → 就绪。
// 之后 ExchangeIKE / SendESPPacket / ReadESPPacket 均通过本会话转发。
func (t *Socks5UDPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("socks5 transport closed")
	}
	if t.relay != nil {
		return nil
	}
	if strings.TrimSpace(t.proxyAddr) == "" {
		return errors.New("socks5 proxy address is empty")
	}

	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.proxyAddr)
	if err != nil {
		return fmt.Errorf("socks5 控制连接失败: %w", err)
	}
	if d, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(d)
	} else {
		_ = control.SetDeadline(time.Now().Add(t.timeout))
	}

	methods := []byte{0x00} // 无认证
	if t.username != "" {
		methods = []byte{0x02, 0x00} // 密码认证优先
	}
	// 版本协商
	if _, err := control.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		_ = control.Close()
		return fmt.Errorf("socks5 版本协商发送失败: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(control, resp); err != nil {
		_ = control.Close()
		return fmt.Errorf("socks5 版本协商响应失败: %w", err)
	}
	if resp[0] != 0x05 {
		_ = control.Close()
		return fmt.Errorf("socks5 版本不匹配: 0x%02x", resp[0])
	}
	switch resp[1] {
	case 0x00: // 无认证
	case 0x02: // 密码认证
		if err := socks5SendUserPass(control, t.username, t.password); err != nil {
			_ = control.Close()
			return err
		}
	default:
		_ = control.Close()
		return fmt.Errorf("socks5 认证方法不被代理接受: 0x%02x", resp[1])
	}

	// UDP ASSOCIATE：BND.ADDR=0.0.0.0 BND.PORT=0，让代理分配中继端点
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := control.Write(req); err != nil {
		_ = control.Close()
		return fmt.Errorf("socks5 UDP ASSOCIATE 请求失败: %w", err)
	}
	relayEP, err := socks5ReadAssociateReply(control, t.timeout)
	if err != nil {
		_ = control.Close()
		return err
	}

	udpConn, err := net.ListenUDP("udp", resolveUDPAddrOrNil(t.localAddr))
	if err != nil {
		_ = control.Close()
		return fmt.Errorf("socks5 中继 UDP socket 建立失败: %w", err)
	}

	t.control = control
	t.relay = udpConn
	t.relayEP = relayEP
	return nil
}

// ExchangeIKE 通过 SOCKS5 UDP Associate 中继一次 IKE 请求-响应。
func (t *Socks5UDPTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if err := t.Connect(ctx); err != nil {
		return nil, err
	}
	t.mu.Lock()
	relay, relayEP := t.relay, t.relayEP
	t.mu.Unlock()
	if relay == nil || relayEP == nil {
		return nil, errors.New("socks5 relay not ready")
	}

	dgram := socks5WrapUDPDatagram(t.remoteAddr, request)
	if _, err := relay.WriteToUDP(dgram, relayEP.(*net.UDPAddr)); err != nil {
		return nil, fmt.Errorf("socks5 IKE 发送失败: %w", err)
	}
	_ = relay.SetReadDeadline(time.Now().Add(t.timeout))

	for {
		buf := make([]byte, 65535)
		n, _, err := relay.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("socks5 IKE 响应超时: %w", err)
		}
		payload, _, ok := socks5ParseUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		return payload, nil
	}
}

// SendESPPacket 通过 SOCKS5 UDP Associate 中继一个 ESP 数据包。
func (t *Socks5UDPTransport) SendESPPacket(ctx context.Context, data []byte) error {
	if err := t.Connect(ctx); err != nil {
		return err
	}
	t.mu.Lock()
	relay, relayEP := t.relay, t.relayEP
	t.mu.Unlock()
	if relay == nil || relayEP == nil {
		return errors.New("socks5 relay not ready")
	}
	dgram := socks5WrapUDPDatagram(t.remoteAddr, data)
	if _, err := relay.WriteToUDP(dgram, relayEP.(*net.UDPAddr)); err != nil {
		return fmt.Errorf("socks5 ESP 发送失败: %w", err)
	}
	return nil
}

// ReadESPPacket 从 SOCKS5 中继读取一个 ESP 数据包并解封装。
func (t *Socks5UDPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if err := t.Connect(ctx); err != nil {
		return nil, err
	}
	t.mu.Lock()
	relay := t.relay
	t.mu.Unlock()
	if relay == nil {
		return nil, errors.New("socks5 relay not ready")
	}
	_ = relay.SetReadDeadline(time.Now().Add(t.timeout))
	for {
		buf := make([]byte, 65535)
		n, _, err := relay.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("socks5 ESP 接收失败: %w", err)
		}
		payload, _, ok := socks5ParseUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		return payload, nil
	}
}

// Close 关闭 SOCKS5 控制连接与中继 UDP socket。
func (t *Socks5UDPTransport) Close(ctx context.Context) error {
	_ = ctx // 保留用于接口一致性；SOCKS5 关闭默认无阻塞
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	var firstErr error
	if t.relay != nil {
		if err := t.relay.Close(); err != nil {
			firstErr = err
		}
		t.relay = nil
	}
	if t.control != nil {
		if err := t.control.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.control = nil
	}
	return firstErr
}

func resolveUDPAddrOrNil(addr string) *net.UDPAddr {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}
	return a
}

func socks5SendUserPass(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5 认证用户名/密码过长")
	}
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 认证发送失败: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 认证响应失败: %w", err)
	}
	if resp[1] != 0x00 {
		return errors.New("socks5 认证失败")
	}
	return nil
}

// socks5ReadAssociateReply 解析 UDP ASSOCIATE 应答，返回代理分配的中继 UDP 端点。
func socks5ReadAssociateReply(conn net.Conn, timeout time.Duration) (net.Addr, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 响应读取失败: %w", err)
	}
	if header[0] != 0x05 {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 版本不匹配: 0x%02x", header[0])
	}
	if header[1] != 0x00 {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 被拒绝: 状态 0x%02x", header[1])
	}
	var ip net.IP
	switch header[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, fmt.Errorf("socks5 UDP ASSOCIATE 地址读取失败: %w", err)
		}
		ip = b
	case 0x03: // 域名
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return nil, fmt.Errorf("socks5 UDP ASSOCIATE 域名长度读取失败: %w", err)
		}
		db := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(conn, db); err != nil {
			return nil, fmt.Errorf("socks5 UDP ASSOCIATE 域名读取失败: %w", err)
		}
		if resolved := net.ParseIP(string(db)); resolved != nil {
			ip = resolved
		} else {
			return nil, fmt.Errorf("socks5 UDP ASSOCIATE 域名未解析: %s", db)
		}
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, fmt.Errorf("socks5 UDP ASSOCIATE IPv6 地址读取失败: %w", err)
		}
		ip = b
	default:
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 未知地址类型: 0x%02x", header[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 端口读取失败: %w", err)
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(pb))}, nil
}

// socks5WrapUDPDatagram 构造 SOCKS5 UDP 数据报：RSV(2)+FRAG(1)+ATYP(1)+DST.ADDR+DST.PORT+DATA。
// remoteAddr 格式为 "host:port"。
func socks5WrapUDPDatagram(remoteAddr string, payload []byte) []byte {
	host, portStr, _ := net.SplitHostPort(remoteAddr)
	port := 4500
	if p, err := net.LookupPort("udp", portStr); err == nil {
		port = p
	}
	dstIP := net.ParseIP(host)
	out := []byte{0x00, 0x00, 0x00, 0x01}
	if ip4 := dstIP.To4(); ip4 != nil {
		out = append(out, ip4...)
	} else if ip6 := dstIP.To16(); ip6 != nil {
		out[3] = 0x04
		out = append(out, ip6...)
	} else {
		// 域名回退
		out[3] = 0x03
		out = append(out, byte(len(host)))
		out = append(out, host...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	out = append(out, payload...)
	return out
}

// socks5ParseUDPDatagram 解析 SOCKS5 UDP 数据报，返回 DATA 及目标地址/是否合法。
func socks5ParseUDPDatagram(dgram []byte) (payload, dst []byte, ok bool) {
	if len(dgram) < 4 || dgram[0] != 0x00 || dgram[1] != 0x00 || dgram[2] != 0x00 {
		return nil, nil, false
	}
	switch dgram[3] {
	case 0x01:
		if len(dgram) < 10 {
			return nil, nil, false
		}
		dst = dgram[4:8]
		return dgram[10:], dst, true
	case 0x03:
		if len(dgram) < 5 {
			return nil, nil, false
		}
		dl := int(dgram[4])
		if len(dgram) < 5+dl+2 {
			return nil, nil, false
		}
		dst = dgram[5 : 5+dl]
		return dgram[5+dl+2:], dst, true
	case 0x04:
		if len(dgram) < 22 {
			return nil, nil, false
		}
		dst = dgram[4:20]
		return dgram[22:], dst, true
	}
	return nil, nil, false
}