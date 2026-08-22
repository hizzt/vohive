package swu

import (
	"context"
	"testing"
)

func TestApplyChildSASwapsBothSAs(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession: %v", err)
	}
	// 对端视角的 ChildSA：SPI 互换，密钥同源可解密。
	child := packetChildSA(false)
	if err := session.ApplyChildSA(child); err != nil {
		t.Fatalf("ApplyChildSA: %v", err)
	}
	session.mu.Lock()
	gotChild := session.child
	session.mu.Unlock()
	if string(gotChild.LocalSPI) != string(child.LocalSPI) {
		t.Fatalf("child local spi = %x, want %x", gotChild.LocalSPI, child.LocalSPI)
	}
	// 热切换后新 SA 能立刻收发：peer 持有同一 child 的对端视角
	// （outbound/inbound 互换），session 新 outbound 加密的包 peer 能解。
	peerChild := child
	peerChild.LocalSPI, peerChild.RemoteSPI = child.RemoteSPI, child.LocalSPI
	peerChild.Keys.Outbound, peerChild.Keys.Inbound = child.Keys.Inbound, child.Keys.Outbound
	peer, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   peerChild,
		Transport: &captureESPPacketTransport{},
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession(peer): %v", err)
	}
	inner := []byte{0x45, 0x00, 0x00, 0x14}
	if err := session.SendInnerPacket(context.Background(), inner); err != nil {
		t.Fatalf("SendInnerPacket: %v", err)
	}
	transport := session.transport.(*captureESPPacketTransport)
	if len(transport.packets) == 0 {
		t.Fatal("no ESP packet sent after rekey")
	}
	got, err := peer.ReceiveESPPacket(context.Background(), transport.packets[len(transport.packets)-1])
	if err != nil {
		t.Fatalf("ReceiveESPPacket after rekey: %v", err)
	}
	if string(got.Payload) != string(inner) {
		t.Fatalf("payload=%x, want %x", got.Payload, inner)
	}
}

func TestApplyChildSAClosedSession(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession: %v", err)
	}
	session.mu.Lock()
	session.closed = true
	session.mu.Unlock()
	child := packetChildSA(false)
	if err := session.ApplyChildSA(child); err == nil {
		t.Fatal("ApplyChildSA on closed session must fail")
	}
}

func TestRekeyChildSANilHandler(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession: %v", err)
	}
	if _, err := session.RekeyChildSA(context.Background()); err == nil {
		t.Fatal("RekeyChildSA without handler must fail")
	}
}
