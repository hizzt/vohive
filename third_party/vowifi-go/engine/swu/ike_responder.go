package swu

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

// IKEResponder 应答 ePDG 主动发起的 IKE INFORMATIONAL 请求。
//
// 背景：引擎此前是纯发起方（responder 能力为零）。设备实测（112+伦敦
// SOCKS5，Vodafone UK）：会话空闲 ~40s 后 ePDG 的 DPD 探测（INFORMATIONAL
// 空请求）到来时无人应答，ePDG 判定对端死亡拆除 IKE/CHILD SA → ESP 下行
// 停止 → 空闲超时触发整链重建（~5min 周期）。参考实现（Python 参考
// swu_ike.py:4533 注释 "Previously ignored -> the ePDG's DPD would eventually
// tear the tunnel down"；VoCat relay.go:126-158 DPD 应答方）都实现了
// 应答方能力，这是 1.5.5 存活的差异点之一（另有周期 SIP 事务维持双向流）。
type IKEResponder struct {
	mu       sync.Mutex
	init     ikev2.InitResult
	keys     ikev2.IKEKeys
	random   interface{ Read([]byte) (int, error) }
	imei     string
	imeiSV   string
	onDelete func() // 收到 DELETE 通知时触发（nil = 不处理）
	closed   bool

	send func([]byte) error // 经原 relay/端口发出（nil = 未接线，丢弃请求）
}

// NewIKEResponder 构造应答方。send 回调用 SendESPPacket 同一 socket 发出。
func NewIKEResponder(init ikev2.InitResult, keys ikev2.IKEKeys, imei string, send func([]byte) error) *IKEResponder {
	return &IKEResponder{
		init: init,
		keys: keys,
		imei: imei,
		send: send,
	}
}

// SetOnDelete 注册 DELETE 处理回调（ePDG 拆 SA 时通知上层走重建）。
func (r *IKEResponder) SetOnDelete(fn func()) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.onDelete = fn
	r.mu.Unlock()
}

// Close 停止应答（会话关闭时调用）。
func (r *IKEResponder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
}

// HandleInbound 处理一条入站 IKE 报文。返回 true 表示报文已被应答方消费
// （调用方丢弃，不再走 ESP 解密路径）；false 表示不属于应答方职责。
// 响应（对端请求）经构造时传入的 send 回调原路发出；迟到响应丢弃。
func (r *IKEResponder) HandleInbound(ctx context.Context, packet []byte) bool {
	if r == nil {
		return false
	}
	header, err := ikev2.ParseHeader(packet)
	if err != nil {
		return false
	}
	r.mu.Lock()
	closed := r.closed
	init := r.init
	keys := r.keys
	imei := r.imei
	send := r.send
	onDelete := r.onDelete
	r.mu.Unlock()
	if closed {
		return false
	}
	// 只处理本 IKE SA 的报文（SA_INIT 阶段 SPIr=0 的响应另有接收方，
	// 应答方只在会话建立后工作，SPI 对不上的属于旧 SA 残留）。
	if header.InitiatorSPI != init.InitiatorSPI || header.ResponderSPI != init.ResponderSPI {
		return false
	}
	if header.ExchangeType != ikev2.ExchangeINFORMATIONAL {
		// CREATE_CHILD_SA 请求（ePDG 主动 rekey）暂不实现——按 VoCat 策略
		// 触发重建兜底；其余类型非应答方职责。
		if header.ExchangeType == ikev2.ExchangeCREATE_CHILD_SA && header.Flags&ikev2.FlagResponse == 0 {
			if onDelete != nil {
				go onDelete()
			}
			return true
		}
		return false
	}
	// INFORMATIONAL：解密（对端为发起方，fromInitiator=true 用对端方向密钥）
	msg, inner, err := ikev2.UnprotectMessage(packet, keys, true)
	if err != nil {
		// 解密失败的请求：按 RFC 7296 §2.21 重发未加密 INVALID_SYNTAX 通知
		// 的实现成本高且罕见，直接丢弃，让重传超时机制兜底。
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE responder: decrypt failed (%v), dropping request\n", err)
		}
		return true
	}
	_ = msg
	isResponse := header.Flags&ikev2.FlagResponse != 0
	if isResponse {
		// 迟到的响应（本方请求的响应经响应匹配后丢失后到达）或重复响应：
		// 丢弃即可，不消费对端 ESP 流。
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE responder: dropping late/dup response msgid=%d\n", header.MessageID)
		}
		return true
	}
	// 对端请求：解析内层 payload 决定应答内容
	var replyInner []ikev2.Payload
	var deviceErr error
	hasDelete := false
	hasDeviceIdentityReq := false
	for _, p := range inner {
		switch p.Type {
		case ikev2.PayloadNotify:
			n, err := ikev2.ParseNotify(p.Body)
			if err != nil {
				continue
			}
			switch n.NotifyType {
			case ikev2.NotifyDeviceIdentity:
				hasDeviceIdentityReq = true
			}
		case ikev2.PayloadDelete:
			hasDelete = true
		}
	}
	switch {
	case hasDelete:
		// ePDG 拆 SA：回 ACK（空 INFORMATIONAL 响应）后通知上层重建。
		// 回 ACK 失败也要通知——SA 已死，重建是唯一出路。
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE responder: DELETE received, ack + rebuild\n")
		}
		replyInner = nil
		_ = r.sendResponse(send, header.MessageID, replyInner)
		if onDelete != nil {
			go onDelete()
		}
		return true
	case hasDeviceIdentityReq:
		// ePDG 请求设备身份：回 DEVICE_IDENTITY 通知（对齐 Python 参考
		// handle_INFORMATIONAL_request 的 DEVICE_IDENTITY 分支）。
		var dev *ikev2.DeviceIdentity
		if len(imei) == 15 {
			dev = &ikev2.DeviceIdentity{
				IdentityType: ikev2.DeviceIdentityTypeIMEI,
				Value:        imei,
			}
		} else {
			dev = &ikev2.DeviceIdentity{
				IdentityType: ikev2.DeviceIdentityTypeIMEI,
				Value:        imei + "0", // IMEI 少于 15 位时凑 IMEISV 形状（极少发生）
			}
		}
		np, err := ikev2.DeviceIdentityNotify(*dev)
		if err != nil {
			deviceErr = err
		} else {
			replyInner = []ikev2.Payload{np}
		}
	default:
		// 空请求 = ePDG DPD 探测：回空加密响应（静默在线确认）。
		replyInner = nil
	}
	if deviceErr != nil {
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE responder: device identity build failed (%v), replying empty\n", deviceErr)
		}
		replyInner = nil
	}
	if os.Getenv("SWU_DEBUG_IKE") != "" {
		fmt.Fprintf(os.Stderr, "[swu] IKE responder: answering INFORMATIONAL request msgid=%d payloads=%d (dpd=%t delete=%t device=%t)\n",
			header.MessageID, len(replyInner), len(inner) == 0, hasDelete, hasDeviceIdentityReq)
	}
	if err := r.sendResponse(send, header.MessageID, replyInner); err != nil {
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE responder: send response failed: %v\n", err)
		}
	}
	return true
}

// sendResponse 构造加密 INFORMATIONAL 响应并经原路径发出。
func (r *IKEResponder) sendResponse(send func([]byte) error, messageID uint32, inner []ikev2.Payload) error {
	if send == nil {
		return fmt.Errorf("responder send not wired")
	}
	_, raw, err := ikev2.BuildInformationalResponseFrom(r.init, r.keys, messageID, false, inner, nil)
	if err != nil {
		return err
	}
	return send(raw)
}

var _ = time.Second // 保持 time import（调试输出扩展预留）
