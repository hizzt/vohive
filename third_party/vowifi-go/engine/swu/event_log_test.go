package swu

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func TestLogEventRoutesToRegisteredLogger(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	SetEventLogger(EventLoggerFunc(func(level, msg string, fields map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		got["level"] = level
		got["msg"] = msg
		got["consecutive"] = fields["consecutive"]
	}))
	defer SetEventLogger(nil)
	logEvent("WARN", "ESP 保活探测失败，链路疑似中断", map[string]string{"consecutive": "2/3"})
	mu.Lock()
	defer mu.Unlock()
	if got["level"] != "WARN" || got["msg"] != "ESP 保活探测失败，链路疑似中断" || got["consecutive"] != "2/3" {
		t.Fatalf("routed event=%v", got)
	}
}

func TestLogEventFallsBackToStderr(t *testing.T) {
	SetEventLogger(nil)
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	logEvent("INFO", "CHILD_SA rekey 成功，ESP SA 已无感切换", map[string]string{"new_spi": "aabbccdd"})
	w.Close()
	os.Stderr = old
	buf := make([]byte, 256)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "[swu] CHILD_SA rekey 成功") || !strings.Contains(out, "new_spi=aabbccdd") {
		t.Fatalf("stderr fallback output=%q", out)
	}
}
