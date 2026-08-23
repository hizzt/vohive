package swu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

var ErrInvalidPacketPump = errors.New("invalid swu packet pump")

type InnerPacketReader interface {
	ReadInnerPacket(context.Context) ([]byte, error)
}

type InnerPacketWriter interface {
	WriteInnerPacket(context.Context, []byte) error
}

type InnerPacketDevice interface {
	InnerPacketReader
	InnerPacketWriter
}

type InnerPacketDeviceCloser interface {
	InnerPacketDevice
	Close(context.Context) error
}

type PacketPumpDirection string

const (
	PacketPumpDeviceToESP PacketPumpDirection = "device_to_esp"
	PacketPumpESPToDevice PacketPumpDirection = "esp_to_device"
)

type PacketPumpStats struct {
	DeviceToESPPackets uint64
	DeviceToESPBytes   uint64
	ESPToDevicePackets uint64
	ESPToDeviceBytes   uint64
	DeviceReadErrors   uint64
	DeviceWriteErrors  uint64
	ESPReadErrors      uint64
	ESPSendErrors      uint64
	// IMS ipsec-3gpp ESP 层逐包失败计数（丢包不杀泵）。
	DeviceToESPTransformErrors uint64
	ESPToDeviceTransformErrors uint64
}

// InnerPacketTransform 在 pump 收发路径上对内层 IP 包做逐包变换
// （IMS ipsec-3gpp 的 userspace ESP 封装/解封装）。nil 时直通。
// 变换错误只丢当前包并计数，不终止泵——ESP 层坏包（重放/ICV 失配）
// 不应拖垮整个隧道。
type InnerPacketTransform interface {
	TransformOutbound(packet []byte) ([]byte, error)
	TransformInbound(packet []byte) ([]byte, error)
}

type PacketPumpConfig struct {
	Session PacketTunnelReadSession
	Device  InnerPacketDevice
	// Transform 可选；Install 前的实现必须透传（imsipsec.Transform 即如此）。
	Transform InnerPacketTransform
	OnError   func(PacketPumpDirection, error)
}

type PacketPump struct {
	session  PacketTunnelReadSession
	device   InnerPacketDevice
	transform InnerPacketTransform
	onError  func(PacketPumpDirection, error)

	mu      sync.Mutex
	stats   PacketPumpStats
	started bool
	done    chan struct{}
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	err     error
	once    sync.Once
}

func NewPacketPump(cfg PacketPumpConfig) (*PacketPump, error) {
	if cfg.Session == nil {
		return nil, fmt.Errorf("%w: session is nil", ErrInvalidPacketPump)
	}
	if cfg.Device == nil {
		return nil, fmt.Errorf("%w: device is nil", ErrInvalidPacketPump)
	}
	return &PacketPump{
		session:   cfg.Session,
		device:    cfg.Device,
		transform: cfg.Transform,
		onError:   cfg.OnError,
		done:      make(chan struct{}),
	}, nil
}

func (p *PacketPump) Start(ctx context.Context) error {
	if p == nil {
		return ErrInvalidPacketPump
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return fmt.Errorf("%w: already started", ErrInvalidPacketPump)
	}
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.started = true
	p.mu.Unlock()

	p.wg.Add(3)
	go p.deviceToESP(ctx)
	go p.espToDevice(ctx)
	go p.closeOnContext(ctx)
	go func() {
		p.wg.Wait()
		close(p.done)
	}()
	return nil
}

func (p *PacketPump) Done() <-chan struct{} {
	if p == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return p.done
}

func (p *PacketPump) Wait() (PacketPumpStats, error) {
	if p == nil {
		return PacketPumpStats{}, ErrInvalidPacketPump
	}
	p.mu.Lock()
	started := p.started
	done := p.done
	p.mu.Unlock()
	if !started {
		return PacketPumpStats{}, fmt.Errorf("%w: not started", ErrInvalidPacketPump)
	}
	<-done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats, p.err
}

func (p *PacketPump) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	started := p.started
	cancel := p.cancel
	done := p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	var err error
	if closer, ok := p.device.(InnerPacketDeviceCloser); ok {
		err = closer.Close(ctx)
	}
	if closeErr := p.session.Close(ctx); err == nil {
		err = closeErr
	}
	if !started {
		return err
	}
	select {
	case <-done:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	return err
}

func (p *PacketPump) deviceToESP(ctx context.Context) {
	defer p.wg.Done()
	for {
		packet, err := p.device.ReadInnerPacket(ctx)
		if err != nil {
			if p.isNormalStop(ctx, err) {
				p.requestStop()
				return
			}
			p.recordError(PacketPumpDeviceToESP, err, func(stats *PacketPumpStats) { stats.DeviceReadErrors++ })
			return
		}
		if len(packet) == 0 {
			continue
		}
		if p.transform != nil {
			transformed, err := p.transform.TransformOutbound(packet)
			if err != nil {
				p.mu.Lock()
				p.stats.DeviceToESPTransformErrors++
				p.mu.Unlock()
				logEvent("WARN", "IMS ESP 出向封装失败，丢包", map[string]string{
					"error": err.Error(),
				})
				continue
			}
			packet = transformed
		}
		if err := p.session.SendInnerPacket(ctx, packet); err != nil {
			if p.isNormalStop(ctx, err) {
				p.requestStop()
				return
			}
			p.recordError(PacketPumpDeviceToESP, err, func(stats *PacketPumpStats) { stats.ESPSendErrors++ })
			return
		}
		p.mu.Lock()
		p.stats.DeviceToESPPackets++
		p.stats.DeviceToESPBytes += uint64(len(packet))
		p.mu.Unlock()
	}
}

func (p *PacketPump) espToDevice(ctx context.Context) {
	defer p.wg.Done()
	lastStatsLog := time.Now()
	for {
		packet, err := p.session.ReadInnerPacket(ctx)
		if err != nil {
			if p.isNormalStop(ctx, err) {
				p.requestStop()
				return
			}
			p.recordError(PacketPumpESPToDevice, err, func(stats *PacketPumpStats) { stats.ESPReadErrors++ })
			return
		}
		if len(packet.Payload) == 0 {
			continue
		}
		payload := packet.Payload
		if p.transform != nil {
			transformed, err := p.transform.TransformInbound(payload)
			if err != nil {
				p.mu.Lock()
				p.stats.ESPToDeviceTransformErrors++
				p.mu.Unlock()
				logEvent("WARN", "IMS ESP 入向解封失败，丢包", map[string]string{
					"error": err.Error(),
				})
				continue
			}
			payload = transformed
		}
		if err := p.device.WriteInnerPacket(ctx, payload); err != nil {
			if p.isNormalStop(ctx, err) {
				p.requestStop()
				return
			}
			p.recordError(PacketPumpESPToDevice, err, func(stats *PacketPumpStats) { stats.DeviceWriteErrors++ })
			return
		}
		p.mu.Lock()
		p.stats.ESPToDevicePackets++
		p.stats.ESPToDeviceBytes += uint64(len(packet.Payload))
		stats := p.stats
		p.mu.Unlock()
		// 周期打点下行统计：注册诊断期曾出现"上行 ESP 出站但零下行"的静默故障，
		// 无周期事件时只能靠 tcpdump 旁证。600ms 内不重复打。
		if now := time.Now(); now.Sub(lastStatsLog) >= 60*time.Second {
			lastStatsLog = now
			logEvent("INFO", "ESP 数据面统计", map[string]string{
				"out_packets": strconv.FormatUint(stats.DeviceToESPPackets, 10),
				"in_packets":  strconv.FormatUint(stats.ESPToDevicePackets, 10),
				"in_bytes":    strconv.FormatUint(stats.ESPToDeviceBytes, 10),
			})
		}
	}
}

func (p *PacketPump) closeOnContext(ctx context.Context) {
	defer p.wg.Done()
	<-ctx.Done()
	if closer, ok := p.device.(InnerPacketDeviceCloser); ok {
		_ = closer.Close(context.Background())
	}
	_ = p.session.Close(context.Background())
}

func (p *PacketPump) recordError(direction PacketPumpDirection, err error, update func(*PacketPumpStats)) {
	p.mu.Lock()
	if update != nil {
		update(&p.stats)
	}
	p.mu.Unlock()
	p.once.Do(func() {
		if p.onError != nil {
			p.onError(direction, err)
		}
		p.mu.Lock()
		p.err = err
		cancel := p.cancel
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
}

func (p *PacketPump) requestStop() {
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (p *PacketPump) isNormalStop(ctx context.Context, err error) bool {
	return err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, ErrPacketTunnelClosed) ||
		(ctx != nil && ctx.Err() != nil)
}
