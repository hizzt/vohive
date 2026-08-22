package swu

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// EventLogger 是引擎层事件日志接口：断链、重建、rekey 等生命周期事件经它
// 上报，主仓（vohive）注入实现接入面板实时日志流（zap→SSE）。third_party
// 保持零依赖独立编译，nil 时回退裸 stderr。
type EventLogger interface {
	LogEvent(level, msg string, fields map[string]string)
}

// EventLoggerFunc 适配函数签名。
type EventLoggerFunc func(level, msg string, fields map[string]string)

func (f EventLoggerFunc) LogEvent(level, msg string, fields map[string]string) {
	f(level, msg, fields)
}

var (
	eventLoggerMu sync.RWMutex
	eventLogger   EventLogger
)

// SetEventLogger 注册引擎事件日志器（主仓启动时调用一次）。
func SetEventLogger(l EventLogger) {
	eventLoggerMu.Lock()
	eventLogger = l
	eventLoggerMu.Unlock()
}

// logEvent 输出一条引擎事件：已注册 logger → 双写（logger + 可选 stderr
// 调试回显）；未注册 → 裸 stderr（行为与改造前一致）。
func logEvent(level, msg string, fields map[string]string) {
	eventLoggerMu.RLock()
	l := eventLogger
	eventLoggerMu.RUnlock()
	if l != nil {
		l.LogEvent(level, msg, fields)
		// SWU_DEBUG_IKE 时同时打 stderr 便于设备侧 journalctl 排查。
		if os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintln(os.Stderr, formatEvent(level, msg, fields))
		}
		return
	}
	fmt.Fprintln(os.Stderr, formatEvent(level, msg, fields))
}

func formatEvent(level, msg string, fields map[string]string) string {
	if len(fields) == 0 {
		return "[swu] " + msg
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	// 稳定输出顺序：按 key 字典序。
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	parts := make([]string, 0, len(fields))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, fields[k]))
	}
	return "[swu] " + msg + " (" + strings.Join(parts, " ") + ")"
}
