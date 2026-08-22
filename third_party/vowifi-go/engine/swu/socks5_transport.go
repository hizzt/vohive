package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
	"github.com/txthinking/socks5"
)

// Socks5UDPTransport 通过 SOCKS5 UDP Associate 中继 IKE/ESP 流量到 ePDG。
// 使用 txthinking 做 TCP 握手 + UDP ASSOCIATE，是否保活 TCP 控制连接由 carrier profile 决定。
// UDP 读写使用手动封装/解封 SOCKS5 数据报（兼容代理行为）。
type Socks5UDPTransport struct {
	proxyAddr string
	username  string
	password  string
	localAddr string
	timeout   time.Duration

	mu      sync.Mutex
	client  *socks5.Client
	udpConn *net.UDPConn // 手动 UDP 连接（非 txthinking 的 conn）
	relayEP *net.UDPAddr
	closed  bool

	// exchangeMu 串行化 IKE 请求-响应交换。DPD liveness（60s 周期）与上层
	// MOBIKE 漫游（公网 IP 轮询检测）可能并发调用 ExchangeIKE；两个读循环
	// 共享同一 UDP socket 会互相抢走对方的响应报文（按请求头匹配不上就
	// 丢弃），且 MOBIKE 换 ePDG 地址后旧交换的响应经 relay 回来目标 IP 已
	// 变，代理不转发导致健康会话被 DPD 误判死亡拆掉。串行化后后发的交换
	// 等前一个完成（重传兜底）再发，天然互不干扰。
	exchangeMu sync.Mutex

	remoteAddr string   // 当前活跃的 ePDG 地址
	addresses  []string // 候选 ePDG 地址列表
	addrIndex  int
	useNATT    bool // NAT 检测后切换到 4500 端口并加 NAT-T marker

	// lastInboundAt 记录最近一次收到代理下行数据报的时间（任意读方：
	// ExchangeIKE 的交换读循环或 ReadESPPacket 的 pump 读循环——两个
	// goroutine 各自 ReadFromUDP 同一 socket，内核只把包投给其中一个，
	// pump 视角看不到 ExchangeIKE 收走的 IKE 响应）。ReadESPPacket 的
	// 5min 空闲死链判定以它为准，否则 DPD 响应被 ExchangeIKE 消费后
	// pump 仍判"无下行"误拆健康会话（设备实测：DPD 1s 回包，8s 后 pump
	// 仍报 5min 空闲超时）。
	lastInboundAt atomic.Value // time.Time

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
	// 串行化并发交换（DPD liveness 与 MOBIKE 漫游可能同秒触发），
	// 避免两个读循环共享 UDP socket 互抢响应/交叉换 relay 目标。
	t.exchangeMu.Lock()
	defer t.exchangeMu.Unlock()
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

	// 请求头用于读循环里的响应匹配过滤（旧 SA 重传报文能通过 looksLikeIKE
	// 但 MessageID/SPI 对不上，必须按请求头匹配丢弃）。
	reqHeader, headerErr := ikev2.ParseHeader(request)

	var lastErr error
	for i := startIdx; i < len(addrs); i++ {
		addr := addrs[i]
		// 换 ePDG 地址不重建 associate：SOCKS5 UDP ASSOCIATE 报文本身不含
		// 目标地址（txthinking 只把它写进未使用的 Client.Dst），DST 逐包写在
		// 数据报头里，同一 relay 天然可发往任意 ePDG；重建 associate（新 TCP +
		// 新 UDP 口）在伦敦代理上会放大故障（SwitchToNATT 的注释有实证）。
		if udpConn == nil || relayEP == nil {
			t.mu.Lock()
			err := t.dialAddr(ctx, addr)
			if err == nil {
				udpConn = t.udpConn
				relayEP = t.relayEP
			}
			t.mu.Unlock()
			if err != nil {
				lastErr = err
				continue
			}
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
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE -> %s (%d bytes): %x\n", addr, len(ikeData), ikeData)
		}

		// 读取响应：NAT-T 4500 端口上 ESP 数据包/NAT-T keepalive 会与 IKE 响应混流
		// （实测 ePDG 在 EAP-AKA Response 后同毫秒先回 ESP 包再回 IKE 包）。
		// 非 IkeHeader 前缀（ESP SPI / keepalive）的报文直接跳过继续读；
		// 读超时按指数退避重发同一请求（ePDG 间歇不应期时单发必丢），
		// 累计到总 deadline 仍未收到才换下一个地址。
		// 总等待 = min(t.timeout, ctx 剩余)：握手阶段调用方无 ctx 限制走 t.timeout；
		// DPD/INFORMATIONAL 探测调用方带 30-90s ctx——设备实测代理对 IKE 控制
		// 报文的下行转发可延迟 45-60s（ESP 数据通道正常秒回），固定 8s 会让
		// DPD 必超时误杀健康会话（响应晚到后又被下一轮按 MessageID 丢弃）。
		totalTimeout := t.timeout
		if d, ok := ctx.Deadline(); ok {
			if remaining := time.Until(d) - time.Second; remaining > totalTimeout {
				// 调用方愿意等更久（DPD/INFORMATIONAL）：延长总等待，
				// 重传间隔上限同步放大，让晚到的响应（实测 45-60s）能等到。
				totalTimeout = remaining
			}
		}
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE wait window %v (t.timeout=%v ctx-ok=%v)\n", totalTimeout, t.timeout, func() bool { _, ok := ctx.Deadline(); return ok }())
		}
		deadline := time.Now().Add(totalTimeout)
		interval := ikeRetransmitInterval(totalTimeout)
		maxInterval := ikeMaxRetransmitInterval(totalTimeout)
		var payload []byte
		readOK := false
		for {
			readDeadline := nextIKEReadDeadline(deadline, interval)
			_ = udpConn.SetReadDeadline(readDeadline)
			buf := make([]byte, 65535)
			n, _, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if isReadTimeout(err) && time.Now().Before(deadline) {
					// 本轮等待超时：重发同一请求，间隔翻倍
					if _, werr := udpConn.WriteToUDP(dgram, relayEP); werr == nil {
						if os.Getenv("SWU_DEBUG_IKE") != "" {
							fmt.Fprintf(os.Stderr, "[swu] IKE retransmit -> %s (interval %v)\n", addr, interval)
						}
					}
					interval = nextIKERetransmitInterval(interval, maxInterval)
					continue
				}
				break // 总超时或连接错误
			}
			p, dstAddr, ok := socks5ParseUDPDatagram(buf[:n])
			if !ok {
				continue
			}
			_ = dstAddr
			t.noteInboundDatagram() // ExchangeIKE 收到的响应对 pump 的空闲判定同样有效
			// NAT-T 模式下响应报文也带 4 字节 0x00 marker，剥离后返回 IKE 报文
			if t.useNATT && len(p) >= 4 && p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 {
				p = p[4:]
			}
			if !looksLikeIKE(p) {
				if os.Getenv("SWU_DEBUG_IKE") != "" {
					fmt.Fprintf(os.Stderr, "[swu] IKE <- skipped non-IKE datagram (%d bytes): %x\n", len(p), p[:min(32, len(p))])
				}
				continue
			}
			if headerErr == nil && !ikeResponseMatchesRequest(p, reqHeader) {
				if os.Getenv("SWU_DEBUG_IKE") != "" {
					fmt.Fprintf(os.Stderr, "[swu] IKE <- dropped unmatched response (%d bytes): %x\n", len(p), p[:min(32, len(p))])
				}
				continue
			}
			payload = p
			readOK = true
			break
		}
		if !readOK {
			lastErr = fmt.Errorf("socks5 IKE 响应超时(%s)", addr)
			if i+1 < len(addrs) {
				t.mu.Lock()
				t.addrIndex = i + 1
				t.mu.Unlock()
			}
			continue
		}

		// 成功
		t.mu.Lock()
		t.remoteAddr = addr
		t.addrIndex = i
		t.mu.Unlock()
		return payload, nil
	}
	// 全部地址失败：addrIndex 回到 0，下一次调用从首个地址重试，
	// 避免停在列表尾部导致前序地址永久饿死（DH 降级重试的第二次
	// ExchangeIKE 也能重新轮询全部地址）。
	t.mu.Lock()
	t.addrIndex = 0
	t.mu.Unlock()
	return nil, lastErr
}

// ikeResponseMatchesRequest 判断响应报文头是否属于本次请求。
// 匹配项：SPIi、ExchangeType、MessageID、Response 标志置位。
// SPIr 仅在请求非 0 时比对（SA_INIT 请求 SPIr=0 而响应 SPIr 由 ePDG 生成）。
// 不校验 Initiator 标志——RFC 7296 §3.1 要求响应方清零 I 位，但实测
// Vodafone ePDG 的 INFORMATIONAL 响应带 I 位（msg5 首字母 2=I|R），校验
// 会误杀 DPD 响应进重传循环；上层 parseInformationalHeader 也不校验 I 位。
func ikeResponseMatchesRequest(resp []byte, req ikev2.Header) bool {
	rh, err := ikev2.ParseHeader(resp)
	if err != nil {
		return false
	}
	if rh.Flags&ikev2.FlagResponse == 0 {
		return false
	}
	if rh.InitiatorSPI != req.InitiatorSPI {
		return false
	}
	if req.ResponderSPI != 0 && rh.ResponderSPI != req.ResponderSPI {
		return false
	}
	if rh.ExchangeType != req.ExchangeType || rh.MessageID != req.MessageID {
		return false
	}
	return true
}

// ikeRetransmitInterval 返回 IKE 请求重传的初始间隔（默认 500ms，超时更短则跟随）。
func ikeRetransmitInterval(timeout time.Duration) time.Duration {
	if timeout > 0 && timeout < 500*time.Millisecond {
		return timeout
	}
	return 500 * time.Millisecond
}

// ikeMaxRetransmitInterval 返回重传间隔上限（默认 4s，超时更短则跟随）。
func ikeMaxRetransmitInterval(timeout time.Duration) time.Duration {
	if timeout > 0 && timeout < 4*time.Second {
		return timeout
	}
	return 4 * time.Second
}

// nextIKEReadDeadline 计算下一轮读的截止时间：now+interval，但不超过总 deadline。
func nextIKEReadDeadline(deadline time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return deadline
	}
	next := time.Now().Add(interval)
	if next.Before(deadline) {
		return next
	}
	return deadline
}

// nextIKERetransmitInterval 重传间隔翻倍并封顶。
func nextIKERetransmitInterval(interval, maxInterval time.Duration) time.Duration {
	if interval <= 0 {
		return maxInterval
	}
	next := interval * 2
	if maxInterval > 0 && next > maxInterval {
		return maxInterval
	}
	return next
}

// isReadTimeout 判断 UDP 读错误是否为超时（可重传）。
func isReadTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// noteInboundDatagram 在任意读方收到代理下行数据报时刷新共享下行时间戳。
func (t *Socks5UDPTransport) noteInboundDatagram() {
	t.lastInboundAt.Store(time.Now())
}

// LastInboundAt 返回最近一次下行数据报时间（从未收到过返回零值）。
func (t *Socks5UDPTransport) LastInboundAt() time.Time {
	if v, ok := t.lastInboundAt.Load().(time.Time); ok {
		return v
	}
	return time.Time{}
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
// 读到对端 NAT-T keepalive（单字节 0xff）跳过继续读；空闲读超时（ctx 未取消）
// 时发送本端 keepalive 维持 NAT 映射与代理 relay，然后继续等。
// 与直连版 UDPESPPacketTransport.ReadESPPacket 的行为差异：直连版读超时
// 直接返回错误；本版因需要保活代理 relay 而在空闲期循环发 keepalive，
// 超过 nattIdleSessionTimeout（5 分钟）无任何下行流量才返回超时错误，
// 让 packet pump 走正常退出/重建路径（会话死链检测兜底）。
func (t *Socks5UDPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	t.mu.Lock()
	udpConn := t.udpConn
	relayEP := t.relayEP
	addr := t.remoteAddr
	t.mu.Unlock()
	if udpConn == nil {
		return nil, errors.New("socks5 transport not connected")
	}
	lastKeepalive := time.Now()
	idleStart := time.Now()
	// 空闲基准并入共享下行时间戳：ExchangeIKE 读走的 IKE 响应同样证明链路活
	// （DPD 响应被交换循环消费后 pump 自己的 idleStart 不再更新，5min 死链
	// 判定会误拆——设备实测 14:44:04 DPD 1s 得到响应、14:44:12 pump 仍报超时）。
	if last := t.LastInboundAt(); !last.IsZero() {
		idleStart = last
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		readDeadline := time.Now().Add(nattKeepaliveInterval)
		if d, ok := ctx.Deadline(); ok && d.Before(readDeadline) {
			readDeadline = d
		}
		_ = udpConn.SetReadDeadline(readDeadline)
		buf := make([]byte, 65535)
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if isReadTimeout(err) && ctx.Err() == nil {
				if shared := t.LastInboundAt(); shared.After(idleStart) {
					idleStart = shared // 其他读方（ExchangeIKE）刚收到下行
				}
				if time.Since(idleStart) >= nattIdleSessionTimeout {
					return nil, fmt.Errorf("socks5 ESP 空闲超时（%v 无下行流量）", nattIdleSessionTimeout)
				}
				// 空闲超时：发 NAT-T keepalive（0xff 单字节）保活，继续等
				if relayEP != nil && time.Since(lastKeepalive) >= nattKeepaliveInterval {
					ka := socks5WrapUDPDatagram(addr, []byte{0xff})
					if _, werr := udpConn.WriteToUDP(ka, relayEP); werr == nil {
						lastKeepalive = time.Now()
					}
				}
				continue
			}
			return nil, err
		}
		payload, _, ok := socks5ParseUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		t.noteInboundDatagram()
		if len(payload) == 1 && payload[0] == 0xff {
			// 对端 NAT-T keepalive：丢弃继续读。对端还在发 keepalive
			// 即链路存活，刷新空闲基准，防止健康空闲会话被 5min 死链判定误拆。
			idleStart = time.Now()
			continue
		}
		idleStart = time.Now()
		return payload, nil
	}
}

// nattKeepaliveInterval 是会话期 NAT-T keepalive（0xff）的发送间隔。
const nattKeepaliveInterval = 15 * time.Second

// nattIdleSessionTimeout 是会话空闲上限：超过该时长无任何下行 ESP/keepalive
// 即判定会话死链，返回错误触发重建。
const nattIdleSessionTimeout = 5 * time.Minute

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
// 不重建 SOCKS5 UDP Associate：成功路径实证（ike_success2.pcap）整段会话从 500 切
// 4500 复用同一个 associate（同一 UDP socket/relay），仅改每个数据报的 DST.PORT；
// 重建 associate（新 TCP + 新 UDP 口）在伦敦代理上会导致 4500 流量全部无响应。
func (t *Socks5UDPTransport) SwitchToNATT() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.useNATT {
		return
	}
	t.useNATT = true
	// 将所有地址端口改为 4500（原地，不动连接）
	for i, a := range t.addresses {
		if host, _, err := net.SplitHostPort(a); err == nil {
			t.addresses[i] = net.JoinHostPort(host, "4500")
		}
	}
	// remoteAddr 保持不变（同一 host），避免 ExchangeIKE 因地址变化触发重建。
	// 但 port 变了，若 remoteAddr 含旧端口需同步：
	if host, _, err := net.SplitHostPort(t.remoteAddr); err == nil {
		t.remoteAddr = net.JoinHostPort(host, "4500")
	}
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

// sameHost 判断两个 host:port 地址是否同一主机（忽略端口）。
func sameHost(a, b string) bool {
	ha, _, errA := net.SplitHostPort(a)
	hb, _, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ha == hb
}

// looksLikeIKE 判断一个 UDP 载荷是否是 IKE 报文（区分 4500 端口上混流的
// ESP 数据包与 NAT-T keepalive）：IKE 头第 18 字节是版本 0x20，且总长合法。
func looksLikeIKE(p []byte) bool {
	if len(p) < 28 {
		return false
	}
	if p[17] != 0x20 {
		return false
	}
	total := int(binary.BigEndian.Uint32(p[24:28]))
	return total == len(p)
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
