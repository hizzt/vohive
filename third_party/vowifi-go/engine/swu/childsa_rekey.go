package swu

import (
	"context"
	"fmt"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/esp"
	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

// childSARekeyInterval 是 CHILD_SA 主动 rekey 周期（对齐 Python 参考
// _rekey_tick 的 30min PFS 刷新：ESP SA 长期不换会撞运营商侧 SA 生命周期
// 上限或序列号上限，静默失效后只能整链重建；周期 rekey 无感换新）。
const childSARekeyInterval = 30 * time.Minute

// childSARekeyExchangeTimeout 是单次 CREATE_CHILD_SA 交换超时（rekey 非紧急，
// 给代理慢转发留足窗口；失败保留旧 SA 下轮再试）。
const childSARekeyExchangeTimeout = 60 * time.Second

// ChildSARekeyFunc 执行一次 CHILD_SA rekey 交换，返回新 ChildSA。
// 由 control 层（ikePacketTunnelControl）提供——它持有 transport/init/keys/
// nextMessageID；MessageID 分配在 control 侧保证与 DPD/MOBIKE 不冲突。
type ChildSARekeyFunc func(ctx context.Context) (ikev2.ChildSAResult, error)

// RekeyChildSA 执行一次 CHILD_SA rekey（control 层的 CREATE_CHILD_SA 交换），
// 返回新 ChildSA 供 ApplyChildSA 热切换。
func (s *PacketSession) RekeyChildSA(ctx context.Context) (ikev2.ChildSAResult, error) {
	if s == nil || s.rekeyHandler == nil {
		return ikev2.ChildSAResult{}, ErrInvalidPacketTunnel
	}
	return s.rekeyHandler(ctx)
}

// StartRekeyLoop 启动 CHILD_SA 周期 rekey：每 childSARekeyInterval 用
// CREATE_CHILD_SA（N(REKEY_SA)）无感换新 ESP SA。rekey 失败保留旧 SA 继续跑
// （下轮重试）——旧 SA 在 ePDG 侧到期前总有成功的一轮；成功后切换出/入 SA，
// 旧 SA 的迟到入站包由 ReadInnerPacket 的 SPI mismatch 跳过逻辑天然兼容。
func (s *PacketSession) StartRekeyLoop(ctx context.Context) {
	if s == nil || s.rekeyHandler == nil {
		return
	}
	rekey := ChildSARekeyFunc(s.RekeyChildSA)
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.closed || s.rekeyCancel != nil {
		s.mu.Unlock()
		cancel()
		return
	}
	s.rekeyCancel = cancel
	s.mu.Unlock()

	go func() {
		defer cancel()
		timer := time.NewTimer(childSARekeyInterval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.mu.Lock()
				closed := s.closed
				s.mu.Unlock()
				if closed {
					return
				}
				exchangeCtx, exchangeCancel := context.WithTimeout(ctx, childSARekeyExchangeTimeout)
				child, err := rekey(exchangeCtx)
				exchangeCancel()
				if err != nil {
					// 保守策略：rekey 失败不动旧 SA（还能跑），下轮再试。
					logEvent("WARN", "CHILD_SA rekey 交换失败，保留旧 SA 下轮重试", map[string]string{"error": err.Error()})
					timer.Reset(childSARekeyInterval)
					continue
				}
				if err := s.ApplyChildSA(child); err != nil {
					logEvent("WARN", "CHILD_SA 新 SA 应用失败，保留旧 SA 下轮重试", map[string]string{"error": err.Error()})
					timer.Reset(childSARekeyInterval)
					continue
				}
				logEvent("INFO", "CHILD_SA rekey 成功，ESP SA 已无感切换",
					map[string]string{"new_spi": fmt.Sprintf("%x", child.LocalSPI)})
				timer.Reset(childSARekeyInterval)
			}
		}
	}()
}

// ApplyChildSA 用新 ChildSA 热切换出/入 ESP SA。切换在锁内原子完成；
// 切换前旧 SA 的最后几个出站包若还在路上，对端按旧 SA 解密后丢弃序号，
// 属 rekey 过渡期正常损耗（RFC 7296 §2.8.1 允许短窗口重叠）。
func (s *PacketSession) ApplyChildSA(child ikev2.ChildSAResult) error {
	if s == nil {
		return ErrInvalidPacketTunnel
	}
	if !hasChildSA(child) {
		return fmt.Errorf("%w: rekey result has empty child sa", ErrInvalidPacketTunnel)
	}
	outbound, err := esp.NewOutboundSAFromChild(child)
	if err != nil {
		return fmt.Errorf("%w: outbound: %v", ErrInvalidPacketTunnel, err)
	}
	inbound, err := esp.NewInboundSAFromChild(child)
	if err != nil {
		return fmt.Errorf("%w: inbound: %v", ErrInvalidPacketTunnel, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrPacketTunnelClosed
	}
	s.outbound = outbound
	s.inbound = inbound
	s.child = child
	return nil
}

func (s *PacketSession) childSALocalSPI() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.child.LocalSPI...)
}


// StopRekeyLoop 由 Close 调用，幂等。
func (s *PacketSession) StopRekeyLoop() {
	s.mu.Lock()
	if s.rekeyCancel != nil {
		s.rekeyCancel()
		s.rekeyCancel = nil
	}
	s.mu.Unlock()
}
