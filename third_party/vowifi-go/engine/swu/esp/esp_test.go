package esp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

func TestSealOpenRoundTrip(t *testing.T) {
	sa, err := NewSA(SA{
		SPI:           0xdeadbeef,
		EncryptionKey: bytes.Repeat([]byte{0x11}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x22}, 32),
		Integrity:     IntegrityHMACSHA2_256_128,
	})
	if err != nil {
		t.Fatalf("NewSA() error = %v", err)
	}
	payload := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb, 0xcc}
	packet, err := sa.Seal(NextHeaderIPv4, payload, SealOptions{
		Sequence: 7,
		IV:       bytes.Repeat([]byte{0xa5}, 16),
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if binary.BigEndian.Uint32(packet[0:4]) != 0xdeadbeef || binary.BigEndian.Uint32(packet[4:8]) != 7 {
		t.Fatalf("packet header=%x", packet[:8])
	}
	if len(packet) != 8+16+16+16 {
		t.Fatalf("packet len=%d", len(packet))
	}
	openSA, err := NewSA(SA{
		SPI:           0xdeadbeef,
		EncryptionKey: bytes.Repeat([]byte{0x11}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x22}, 32),
		Integrity:     IntegrityHMACSHA2_256_128,
	})
	if err != nil {
		t.Fatalf("NewSA(open) error = %v", err)
	}
	out, err := openSA.Open(packet)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if out.SPI != 0xdeadbeef || out.Sequence != 7 || out.NextHeader != NextHeaderIPv4 || !bytes.Equal(out.Payload, payload) {
		t.Fatalf("open=%+v payload=%x", out, out.Payload)
	}
}

func TestOpenRejectsTamperedICV(t *testing.T) {
	sa, err := NewSA(SA{
		SPI:           0x01020304,
		EncryptionKey: bytes.Repeat([]byte{0x33}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x44}, 32),
		Integrity:     IntegrityHMACSHA2_256_128,
	})
	if err != nil {
		t.Fatalf("NewSA() error = %v", err)
	}
	packet, err := sa.Seal(NextHeaderIPv6, []byte{0x60, 0x00, 0x00}, SealOptions{Sequence: 1, IV: bytes.Repeat([]byte{0x55}, 16)})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	packet[len(packet)-1] ^= 0xff
	_, err = sa.Open(packet)
	if !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open() err=%v, want ErrInvalidPacket", err)
	}
}

func TestReplayDetection(t *testing.T) {
	sealer, err := NewSA(SA{
		SPI:              0x11111111,
		EncryptionKey:    bytes.Repeat([]byte{0x77}, 16),
		IntegrityKey:     bytes.Repeat([]byte{0x88}, 32),
		Integrity:        IntegrityHMACSHA2_256_128,
		ReplayWindowSize: 64,
	})
	if err != nil {
		t.Fatalf("NewSA() error = %v", err)
	}
	packet10, err := sealer.Seal(NextHeaderIPv4, []byte{1, 2, 3}, SealOptions{Sequence: 10, IV: bytes.Repeat([]byte{0x99}, 16)})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	packet9, err := sealer.Seal(NextHeaderIPv4, []byte{4, 5, 6}, SealOptions{Sequence: 9, IV: bytes.Repeat([]byte{0xaa}, 16)})
	if err != nil {
		t.Fatalf("Seal(9) error = %v", err)
	}
	opener, err := NewSA(SA{
		SPI:              0x11111111,
		EncryptionKey:    bytes.Repeat([]byte{0x77}, 16),
		IntegrityKey:     bytes.Repeat([]byte{0x88}, 32),
		Integrity:        IntegrityHMACSHA2_256_128,
		ReplayWindowSize: 64,
	})
	if err != nil {
		t.Fatalf("NewSA(open) error = %v", err)
	}
	if _, err := opener.Open(packet10); err != nil {
		t.Fatalf("Open(10) error = %v", err)
	}
	if _, err := opener.Open(packet9); err != nil {
		t.Fatalf("Open(9 out-of-order) error = %v", err)
	}
	if _, err := opener.Open(packet9); !errors.Is(err, ErrReplay) {
		t.Fatalf("Open(replay) err=%v, want ErrReplay", err)
	}
}

func TestNewSAFromChildDirections(t *testing.T) {
	child := ikev2.ChildSAResult{
		LocalSPI:  []byte{0xca, 0xfe, 0xba, 0xbe},
		RemoteSPI: []byte{0xde, 0xad, 0xbe, 0xef},
		Keys: ikev2.ChildSAKeys{
			Profile: ikev2.ESPKeyProfile{IntegrityID: ikev2.INTEG_HMAC_SHA2_256_128},
			Outbound: ikev2.ESPKeys{
				EncryptionKey: bytes.Repeat([]byte{0x10}, 16),
				IntegrityKey:  bytes.Repeat([]byte{0x20}, 32),
			},
			Inbound: ikev2.ESPKeys{
				EncryptionKey: bytes.Repeat([]byte{0x30}, 16),
				IntegrityKey:  bytes.Repeat([]byte{0x40}, 32),
			},
		},
	}
	outbound, err := NewOutboundSAFromChild(child)
	if err != nil {
		t.Fatalf("NewOutboundSAFromChild() error = %v", err)
	}
	inbound, err := NewInboundSAFromChild(child)
	if err != nil {
		t.Fatalf("NewInboundSAFromChild() error = %v", err)
	}
	if outbound.SPI != 0xdeadbeef || inbound.SPI != 0xcafebabe {
		t.Fatalf("SPIs outbound=%08x inbound=%08x", outbound.SPI, inbound.SPI)
	}
	if !bytes.Equal(outbound.EncryptionKey, bytes.Repeat([]byte{0x10}, 16)) ||
		!bytes.Equal(inbound.EncryptionKey, bytes.Repeat([]byte{0x30}, 16)) {
		t.Fatalf("keys outbound=%x inbound=%x", outbound.EncryptionKey, inbound.EncryptionKey)
	}
}

// TS 33.203 ipsec-3gpp 二层 ESP 算法矩阵：hmac-md5-96 / des-ede3-cbc /
// null 加密（RFC 2410）——换运营商协商组合的硬前提（hmac-sha-1-96 +
// aes-cbc 已由现役隧道 SA 覆盖）。
func TestSealOpenRoundTripAlgorithmMatrix(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd}
	cases := []struct {
		name    string
		cipher  EncryptionAlgorithm
		encKey  []byte
		integ   IntegrityAlgorithm
		integOK []byte
		ivLen   int
	}{
		{
			name:    "md5-96+aes-cbc",
			cipher:  CipherAES128CBC,
			encKey:  bytes.Repeat([]byte{0x33}, 16),
			integ:   IntegrityHMACMD5_96,
			integOK: bytes.Repeat([]byte{0x44}, 16),
			ivLen:   16,
		},
		{
			name:    "sha1-96+3des-cbc",
			cipher:  Cipher3DESCBC,
			encKey:  bytes.Repeat([]byte{0x55}, 24),
			integ:   IntegrityHMACSHA1_96,
			integOK: bytes.Repeat([]byte{0x66}, 20),
			ivLen:   8,
		},
		{
			name:    "md5-96+null",
			cipher:  CipherNULL,
			integ:   IntegrityHMACMD5_96,
			integOK: bytes.Repeat([]byte{0x77}, 16),
			ivLen:   0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa, err := NewSA(SA{
				SPI:           0x11223344,
				EncryptionKey: tc.encKey,
				IntegrityKey:  tc.integOK,
				Integrity:     tc.integ,
				Cipher:        tc.cipher,
			})
			if err != nil {
				t.Fatalf("NewSA() error = %v", err)
			}
			packet, err := sa.Seal(NextHeaderIPv4, payload, SealOptions{Sequence: 3})
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			openSA, err := NewSA(SA{
				SPI:           0x11223344,
				EncryptionKey: tc.encKey,
				IntegrityKey:  tc.integOK,
				Integrity:     tc.integ,
				Cipher:        tc.cipher,
			})
			if err != nil {
				t.Fatalf("NewSA(open) error = %v", err)
			}
			out, err := openSA.Open(packet)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if out.NextHeader != NextHeaderIPv4 || !bytes.Equal(out.Payload, payload) {
				t.Fatalf("open=%+v payload=%x", out, out.Payload)
			}
			// ICV 长度：md5-96/sha1-96 均为 12。
			if len(packet)-len(payload) < 8+2+12 {
				t.Fatalf("packet too short for ESP header+pad+ICV: %d", len(packet))
			}
			if tc.cipher == CipherNULL {
				// RFC 2410：无 IV，IV 区域零长度。
				if len(packet) != 8+len(payload)+2+12 {
					t.Fatalf("null cipher packet len=%d, want %d", len(packet), 8+len(payload)+2+12)
				}
			}
		})
	}
}

func TestNewSARejectsBadCipherKeyLengths(t *testing.T) {
	if _, err := NewSA(SA{
		SPI:           1,
		EncryptionKey: bytes.Repeat([]byte{0x01}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x02}, 20),
		Integrity:     IntegrityHMACSHA1_96,
		Cipher:        Cipher3DESCBC,
	}); err == nil {
		t.Fatal("3DES with 16-byte key should be rejected")
	}
	if _, err := NewSA(SA{
		SPI:           1,
		IntegrityKey:  bytes.Repeat([]byte{0x02}, 20),
		Integrity:     IntegrityHMACSHA1_96,
		Cipher:        CipherNULL,
	}); err != nil {
		t.Fatalf("null cipher without encryption key should be accepted: %v", err)
	}
}
