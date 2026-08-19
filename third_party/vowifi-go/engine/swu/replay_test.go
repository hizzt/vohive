package swu

import (
	"context"
	"encoding/base64"
	"testing"
	"time"
)

func TestReplayOldIKE(t *testing.T) {
	b64 := "17R8QrysXKAAAAAAAAAAACEgIggAAAAAAAACPCIAALQCAAAsAQEABAMAAAwBAAAMgA4AgAMAAAgDAAAMAwAACAIAAAUAAAAIBAAADgIAACwCAQAEAwAADAEAAAyADgCAAwAACAMAAAwDAAAIAgAABQAAAAgEAAACAgAALAMBAAQDAAAMAQAADIAOAIADAAAIAwAAAgMAAAgCAAACAAAACAQAAAIAAAAsBAEABAMAAAwBAAAMgA4BAAMAAAgDAAACAwAACAIAAAIAAAAIBAAAAigAAQgADgAAY3YV+te8OJoJqx1xPedbg/zaj+08/WpZk0FCEiSDtQir6uoQgpqVAoAh162osXmC44E+LuPAmBTS4kt35rC4HnVMdu0kyt5LoYiwjSPEHaG9UwenyVATDAYQVvFHmW1Qy4Yo4gh80DlHxAnCZhdlhTAZl0uPM8yaxeP7UMx/JeBXMU7YHbYmzMUWJbozCeGsvBU50uI9jLQs3ICBRvaA3/iVqZ4liRuyLNY8iyQ8+B92Ovbkh60dukc/qX82blzNqBMBB2M5H8enBx3BVOdESf1QtuYNq1Joqpl8IySPpz9i2ftyCjzqiywaYjD7Ip/nCB5iG59Oe+nRSjaPgkbkQSkAACSdMTqxqpv3TI7YzIfGQcAw//5rr9iDisRxF2ALaHbq0ykAABwBAEAEu1IL0zbwzz10QE85K4CtXOsZphMpAAAcAQBABezUm7anc5FlD9zFKaSUVwSBXDDsAAAACAAAQC4="
	ikePayload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(ikePayload) != 572 {
		t.Fatalf("expected 572 bytes, got %d", len(ikePayload))
	}
	t.Logf("Old binary IKE payload loaded: %d bytes", len(ikePayload))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srv, err := startMockSocks5Server(ctx)
	if err != nil {
		t.Fatalf("mock server start: %v", err)
	}
	defer srv.close()

	transport := NewSocks5UDPTransport(
		ProxyConfig{Addr: srv.tcpAddr, Enabled: true},
		[]string{srv.epdg}, "", 5*time.Second,
	)

	resp, err := transport.ExchangeIKE(ctx, ikePayload)
	if err != nil {
		t.Fatalf("ExchangeIKE: %v", err)
	}
	t.Logf("Got response: %d bytes, first 32: %x", len(resp), resp[:min(len(resp), 32)])
}
