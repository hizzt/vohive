package voiceclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var ErrSIPFlowClosed = errors.New("SIP flow is closed")

type WireSIPFlow struct {
	Network               string
	ServerAddr            string
	LocalAddr             string
	Resolver              SIPServerResolver
	Timeout               time.Duration
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int
	// OverrideTarget 非空时直连该地址（ipsec-3gpp 受保护 REGISTER → P-CSCF port-s）。
	OverrideTarget string

	mu          sync.Mutex
	conn        net.Conn
	reader      *bufio.Reader
	network     string
	target      string
	targets     []string
	targetIndex int
	closed      bool
}

var _ SIPRegisterTransport = (*WireSIPFlow)(nil)
var _ SIPRequestTransport = (*WireSIPFlow)(nil)
var _ SIPInviteTransport = (*WireSIPFlow)(nil)

func (f *WireSIPFlow) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	return f.roundTrip(ctx, SIPRequestMessage{
		Method:  "REGISTER",
		URI:     msg.URI,
		Headers: cloneStringMap(msg.Headers),
		Body:    append([]byte(nil), msg.Body...),
	}, nil)
}

func (f *WireSIPFlow) RoundTripRequest(ctx context.Context, msg SIPRequestMessage) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, nil)
}

func (f *WireSIPFlow) RoundTripInvite(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, onProvisional)
}

func (f *WireSIPFlow) WriteRequest(ctx context.Context, msg SIPRequestMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	attempts := 0
	shouldRetry := func(err error) bool {
		if ctx.Err() != nil || !isSIPRetryableTransportError(err) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		return f.advanceTargetLocked()
	}
	for {
		conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.closeConnLocked()
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		attempt := cloneSIPRequestMessage(msg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return err
		}
		if _, err := conn.Write(wire); err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		return nil
	}
}

func (f *WireSIPFlow) SendCRLFKeepalive(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	conn := f.conn
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if conn == nil {
		target := strings.TrimSpace(f.ServerAddr)
		if target == "" && len(f.targets) > 0 && f.targetIndex >= 0 && f.targetIndex < len(f.targets) {
			target = f.targets[f.targetIndex]
		}
		if target == "" {
			return errors.New("SIP flow has no connected remote for keepalive")
		}
		var err error
		conn, _, timeout, err = f.ensureConnLocked(ctx, SIPRequestMessage{URI: "sip:" + target})
		if err != nil {
			return err
		}
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		f.closeConnLocked()
		return err
	}
	if _, err := conn.Write([]byte("\r\n\r\n")); err != nil {
		f.closeConnLocked()
		return err
	}
	return nil
}

func (f *WireSIPFlow) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeConnLocked()
}

func (f *WireSIPFlow) Reset() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	err := f.closeConnLocked()
	f.targets = nil
	f.targetIndex = 0
	return err
}

func (f *WireSIPFlow) roundTrip(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return SIPResponse{}, errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	attempts := 0
	shouldRetry := func(err error) bool {
		if ctx.Err() != nil || !isSIPRetryableTransportError(err) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		return f.advanceTargetLocked()
	}
	for {
		conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
		if err != nil {
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.closeConnLocked()
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		attempt := cloneSIPRequestMessage(msg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return SIPResponse{}, err
		}
		if _, err := conn.Write(wire); err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if strings.HasPrefix(network, "tcp") {
			resp, err := readFinalSIPResponse(ctx, f.reader, attempt, onProvisional)
			if err != nil {
				f.closeConnLocked()
				if ctx.Err() != nil {
					return SIPResponse{}, ctx.Err()
				}
				if !shouldRetry(err) {
					return SIPResponse{}, err
				}
				continue
			}
			return resp, nil
		}
		resp, err := f.readUDPResponseLocked(ctx, conn, timeout, wire, attempt, onProvisional)
		if err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		return resp, nil
	}
}

func (f *WireSIPFlow) readUDPResponseLocked(ctx context.Context, conn net.Conn, timeout time.Duration, wire []byte, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	buf := make([]byte, 65535)
	interval := sipRetransmitInterval(timeout, f.RetransmitInterval)
	maxInterval := sipMaxRetransmitInterval(timeout, f.MaxRetransmitInterval)
	deadline := time.Now().Add(timeout)
	retransmits := 0
	gotResponse := false
	retransmitExhausted := false
	for {
		readInterval := interval
		if gotResponse || retransmitExhausted {
			readInterval = time.Until(deadline)
		}
		if err := conn.SetReadDeadline(nextSIPReadDeadline(deadline, readInterval)); err != nil {
			return SIPResponse{}, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !isSIPTimeout(err) || !time.Now().Before(deadline) {
				return SIPResponse{}, err
			}
			if !gotResponse && !retransmitExhausted && shouldSIPRetransmit(retransmits, f.MaxRetransmits) {
				if _, writeErr := conn.Write(wire); writeErr != nil {
					return SIPResponse{}, writeErr
				}
				retransmits++
				interval = nextSIPRetransmitInterval(interval, maxInterval)
				continue
			}
			if !gotResponse {
				retransmitExhausted = true
				continue
			}
			return SIPResponse{}, err
		}
		if !isSIPResponseWire(buf[:n]) {
			continue
		}
		if os.Getenv("SWU_DEBUG_SIP") != "" {
			fmt.Fprintf(os.Stderr, "[swu] SIP <- (%d bytes wire)\n---SIP-BEGIN---\n%s\n---SIP-END---\n", n, buf[:n])
		}
		resp, err := ParseSIPResponse(buf[:n])
		if err != nil {
			return SIPResponse{}, err
		}
		if !isProvisionalResponse(resp.StatusCode, msg.Method) {
			return resp, nil
		}
		if onProvisional != nil {
			if err := onProvisional(ctx, msg, resp); err != nil {
				return SIPResponse{}, err
			}
		}
		gotResponse = true
	}
}

func (f *WireSIPFlow) ensureConnLocked(ctx context.Context, msg SIPRequestMessage) (net.Conn, string, time.Duration, error) {
	if f.closed {
		return nil, "", 0, ErrSIPFlowClosed
	}
	network := strings.ToLower(strings.TrimSpace(f.Network))
	if network == "" {
		network = "udp"
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	wantTarget := strings.TrimSpace(f.ServerAddr)
	if override := strings.TrimSpace(f.OverrideTarget); override != "" {
		wantTarget = override
	}
	if f.conn != nil && f.network == network && (wantTarget == "" || f.target == wantTarget) {
		return f.conn, network, timeout, nil
	}
	if override := strings.TrimSpace(f.OverrideTarget); override != "" {
		// 受保护 REGISTER（TS 33.203）：P-CSCF port-s 上的连接跨
		// re-REGISTER 复用（SA 换装不影响连接本身，seq 由 SA 各自维护）
		// ——v155 行为对齐：连接活着就不重建，避免运营商侧可见的周期性
		// RST+重拨指纹。仅当无连接/目标变化时拨新连接：从 port-c 源端口
		// 拨（ESP 选择器按 Security-Client 宣告的 port-c 匹配）；TCP 关旧
		// 连接置 SO_LINGER=0 走 RST，port-c 立即可重绑（UDP 无连接语义，
		// 重拨即重绑同端口）。UDP 模式下部分运营商 P-CSCF 只对 5060 UDP
		// 应答，走同一受保护路径。
		if f.conn != nil && f.target == override {
			return f.conn, network, timeout, nil
		}
		if f.conn != nil {
			_ = f.closeConnLocked()
		}
		conn, err := sipDialFunc(ctx, network, override, f.LocalAddr, timeout)
		if err != nil {
			if os.Getenv("SWU_DEBUG_IMSIPSEC") != "" {
				fmt.Fprintf(os.Stderr, "[imsipsec] protected dial %s bind %s failed: %v\n", override, f.LocalAddr, err)
			}
			// port-c 重绑失败（TIME_WAIT/冲突）→ 随机源端口仍能完成注册，
			// 但 ESP 选择器不会命中——记录在 dial error 里由上层观察。
			conn, err = sipDialFunc(ctx, network, override, "", timeout)
		}
		if err != nil {
			if os.Getenv("SWU_DEBUG_IMSIPSEC") != "" {
				fmt.Fprintf(os.Stderr, "[imsipsec] protected dial %s failed, fallback plaintext server addr\n", override)
			}
			conn, err = sipDialFunc(ctx, network, strings.TrimSpace(f.ServerAddr), f.LocalAddr, timeout)
			if err != nil {
				return nil, "", 0, err
			}
		}
		f.conn = conn
		f.network = network
		f.target = override
		if strings.HasPrefix(network, "tcp") {
			f.reader = bufio.NewReader(conn)
		} else {
			f.reader = nil
		}
		return conn, network, timeout, nil
	}
	targets, err := f.ensureTargetsLocked(ctx, network, msg.URI)
	if err != nil {
		return nil, "", 0, err
	}
	if len(targets) == 0 {
		return nil, "", 0, errSIPDNSResolverEmpty()
	}
	target := targets[f.targetIndex]
	if f.conn != nil && f.network == network && f.target == target {
		return f.conn, network, timeout, nil
	}
	_ = f.closeConnLocked()
	conn, err := sipDialFunc(ctx, network, target, f.LocalAddr, timeout)
	if err != nil {
		return nil, "", 0, err
	}
	f.conn = conn
	f.network = network
	f.target = target
	if strings.HasPrefix(network, "tcp") {
		f.reader = bufio.NewReader(conn)
	} else {
		f.reader = nil
	}
	return conn, network, timeout, nil
}

func (f *WireSIPFlow) ensureTargetsLocked(ctx context.Context, network, uri string) ([]string, error) {
	if target := strings.TrimSpace(f.ServerAddr); target != "" {
		if len(f.targets) != 1 || f.targets[0] != target {
			f.targets = []string{target}
			f.targetIndex = 0
		}
		return f.targets, nil
	}
	if len(f.targets) == 0 {
		targets, err := resolveSIPServerAddrs(ctx, f.Resolver, network, uri)
		if err != nil {
			return nil, err
		}
		f.targets = appendSIPTargets(nil, targets...)
		f.targetIndex = 0
	}
	if f.targetIndex < 0 || f.targetIndex >= len(f.targets) {
		f.targetIndex = 0
	}
	return f.targets, nil
}

func (f *WireSIPFlow) advanceTargetLocked() bool {
	if len(f.targets) <= 1 {
		return false
	}
	f.targetIndex = (f.targetIndex + 1) % len(f.targets)
	return true
}

func (f *WireSIPFlow) targetCountLocked() int {
	if len(f.targets) == 0 {
		return 1
	}
	return len(f.targets)
}

func (f *WireSIPFlow) closeConnLocked() error {
	if f.conn == nil {
		f.reader = nil
		f.network = ""
		f.target = ""
		return nil
	}
	// 置 SO_LINGER=0 再关：TCP 走 RST 复位而非四次挥手，本地端口不进
	// TIME_WAIT——port-c 随后的受保护重拨才能重绑同端口（ESP 选择器前提）。
	if tcp, ok := f.conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	err := f.conn.Close()
	f.conn = nil
	f.reader = nil
	f.network = ""
	f.target = ""
	return err
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneSIPRequestMessage(msg SIPRequestMessage) SIPRequestMessage {
	msg.Headers = cloneStringMap(msg.Headers)
	msg.Body = append([]byte(nil), msg.Body...)
	return msg
}
