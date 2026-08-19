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
// 内部使用 txthinking/socks5 库（与旧版 engine/ipsec 一致的实现路径）。
type Socks5UDPTransport struct {
	proxyAddr  string
	username   string
	password   string
	localAddr  string
	timeout    time.Duration

	mu       sync.Mutex
	client   *socks5.Client
	conn     net.Conn // UDP 关联连接（Write/Read 自动封装/解封 SOCKS5 数据报）
	closed   bool

	remoteAddr string       // 当前活跃的 ePDG 地址
	addresses  []string     // 候选 ePDG 地址列表
	addrIndex  int
}

var _ ikev2.InitTransport = (*Socks5UDPTransport)(nil)
var _ ESPPacketReadWriteTransport = (*Socks5UDPTransport)(nil)
var _ ESPPacketTransportCloser = (*Socks5UDPTransport)(nil)

// NewSocks5UDPTransport 构造 SOCKS5 UDP Associate 传输层。
// remoteAddrs 是候选 ePDG 地址 host:port 列表，依次尝试直到成功。
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
	if t.conn != nil {
		return nil
	}
	if t.proxyAddr == "" {
		return errors.New("socks5 proxy address is empty")
	}
	return t.dialAddr(ctx, t.remoteAddr)
}

// dialAddr 使用 txthinking/socks5 客户端连接到指定地址。
func (t *Socks5UDPTransport) dialAddr(ctx context.Context, addr string) error {
	tc := int(t.timeout.Seconds())
	cl, err := socks5.NewClient(t.proxyAddr, t.username, t.password, tc, tc)
	if err != nil {
		return fmt.Errorf("socks5 client 创建失败: %w", err)
	}
	// 使用 Dial 建立 UDP associate（内部：TCP 握手 → UDP ASSOCIATE → 本地 UDP socket）
	conn, err := cl.DialWithLocalAddr("udp", t.localAddr, addr, nil)
	if err != nil {
		return fmt.Errorf("socks5 UDP associate 失败: %w", err)
	}
	t.client = cl
	t.conn = conn
	t.remoteAddr = addr
	return nil
}

// ExchangeIKE 通过 SOCKS5 UDP Associate 中继一次 IKE 请求-响应。
// 依次尝试候选地址直到收到响应。
func (t *Socks5UDPTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if err := t.Connect(ctx); err != nil {
		return nil, err
	}

	t.mu.Lock()
	conn := t.conn
	addrs := t.addresses
	startIdx := t.addrIndex
	t.mu.Unlock()
	if conn == nil {
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
			conn = t.conn
			t.mu.Unlock()
		}

		// 发送 IKE 请求
		if _, err := conn.Write(request); err != nil {
			lastErr = fmt.Errorf("socks5 IKE 发送失败: %w", err)
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(t.timeout))

		// 读取响应
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			if i+1 < len(addrs) {
				lastErr = fmt.Errorf("socks5 IKE 响应超时(%s): %w", addr, err)
				// 关闭当前连接，下次尝试下一个地址
				t.mu.Lock()
				t.closeConn()
				t.addrIndex = i + 1
				t.mu.Unlock()
			} else {
				lastErr = fmt.Errorf("socks5 IKE 响应超时(%s): %w", addr, err)
			}
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})

		// 成功，记录当前地址
		t.mu.Lock()
		t.remoteAddr = addr
		t.addrIndex = i
		t.mu.Unlock()
		return buf[:n], nil
	}
	return nil, lastErr
}

// SendESPPacket 通过 SOCKS5 UDP Associate 中继一个 ESP 数据包。
func (t *Socks5UDPTransport) SendESPPacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn == nil {
		return errors.New("socks5 transport not connected")
	}
	_, err := conn.Write(data)
	return err
}

// ReadESPPacket 通过 SOCKS5 UDP Associate 中继读取一个 ESP 数据包。
func (t *Socks5UDPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn == nil {
		return nil, errors.New("socks5 transport not connected")
	}
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(d)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Close 关闭 SOCKS5 传输层（TCP 控制连接 + UDP 中继 socket）。
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
		if t.conn != nil {
			_ = t.conn.Close()
			t.conn = nil
		}
		if t.client != nil {
			_ = t.client.Close()
			t.client = nil
		}
	}
	
	// socks5WrapUDPDatagram 构造 SOCKS5 UDP 数据报（RSV + FRAG + ATYP + DST.ADDR + DST.PORT + DATA）。
	func socks5WrapUDPDatagram(remoteAddr string, payload []byte) []byte {
		host, portStr, _ := net.SplitHostPort(remoteAddr)
		port := 500
		if p, err := net.LookupPort("udp", portStr); err == nil {
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