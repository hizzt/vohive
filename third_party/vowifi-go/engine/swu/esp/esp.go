package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

const (
	NextHeaderIPv4 = 4
	NextHeaderIPv6 = 41
)

var (
	ErrInvalidSA     = errors.New("invalid esp sa")
	ErrInvalidPacket = errors.New("invalid esp packet")
	ErrReplay        = errors.New("esp replay detected")
)

type IntegrityAlgorithm uint16

const (
	IntegrityHMACSHA1_96      IntegrityAlgorithm = IntegrityAlgorithm(ikev2.INTEG_HMAC_SHA1_96)
	IntegrityHMACSHA2_256_128 IntegrityAlgorithm = IntegrityAlgorithm(ikev2.INTEG_HMAC_SHA2_256_128)
	// IntegrityHMACMD5_96：IKEv2 没有此 ID（隧道 SA 用不到），按 RFC 2406
	// HMAC-MD5-96 的 IANA 值 1。TS 33.203 Security-Server 协商 hmac-md5-96
	// 时用于 IMS ipsec-3gpp 二层 ESP（IK[:16] 做密钥），ICV 截 12 字节。
	IntegrityHMACMD5_96 IntegrityAlgorithm = 1
)

// EncryptionAlgorithm 区分 ESP 加密器。CipherAES128CBC 是隧道 CHILD_SA
// 现役路径；Cipher3DESCBC/CipherNULL 是 IMS ipsec-3gpp 二层 ESP 的
// TS 33.203 协商组合（des-ede3-cbc / null），1239t keys.go 同源实现。
type EncryptionAlgorithm int

const (
	CipherAES128CBC EncryptionAlgorithm = iota
	Cipher3DESCBC
	CipherNULL
)

type SA struct {
	SPI              uint32
	EncryptionKey    []byte
	IntegrityKey     []byte
	Integrity        IntegrityAlgorithm
	Cipher           EncryptionAlgorithm
	ICVLength        int
	BlockSize        int
	Sequence         uint32
	HighestSequence  uint32
	ReplayWindowSize uint32
	ReplayBitmap     uint64
}

type SealOptions struct {
	Sequence uint32
	IV       []byte
	Random   io.Reader
}

type OpenResult struct {
	SPI        uint32
	Sequence   uint32
	NextHeader uint8
	Payload    []byte
}

func NewOutboundSAFromChild(child ikev2.ChildSAResult) (*SA, error) {
	spi, err := spiFromBytes(child.RemoteSPI)
	if err != nil {
		return nil, err
	}
	return NewSA(SA{
		SPI:           spi,
		EncryptionKey: child.Keys.Outbound.EncryptionKey,
		IntegrityKey:  child.Keys.Outbound.IntegrityKey,
		Integrity:     IntegrityAlgorithm(child.Keys.Profile.IntegrityID),
		ICVLength:     integrityICVLength(IntegrityAlgorithm(child.Keys.Profile.IntegrityID)),
		BlockSize:     16,
	})
}

func NewInboundSAFromChild(child ikev2.ChildSAResult) (*SA, error) {
	spi, err := spiFromBytes(child.LocalSPI)
	if err != nil {
		return nil, err
	}
	return NewSA(SA{
		SPI:              spi,
		EncryptionKey:    child.Keys.Inbound.EncryptionKey,
		IntegrityKey:     child.Keys.Inbound.IntegrityKey,
		Integrity:        IntegrityAlgorithm(child.Keys.Profile.IntegrityID),
		ICVLength:        integrityICVLength(IntegrityAlgorithm(child.Keys.Profile.IntegrityID)),
		BlockSize:        16,
		ReplayWindowSize: 64,
	})
}

func NewSA(sa SA) (*SA, error) {
	if sa.SPI == 0 {
		return nil, fmt.Errorf("%w: spi is zero", ErrInvalidSA)
	}
	blockSize := aes.BlockSize
	switch sa.Cipher {
	case CipherAES128CBC:
		if len(sa.EncryptionKey) != 16 && len(sa.EncryptionKey) != 24 && len(sa.EncryptionKey) != 32 {
			return nil, fmt.Errorf("%w: AES key length %d", ErrInvalidSA, len(sa.EncryptionKey))
		}
	case Cipher3DESCBC:
		if len(sa.EncryptionKey) != 24 {
			return nil, fmt.Errorf("%w: 3DES key length %d", ErrInvalidSA, len(sa.EncryptionKey))
		}
		blockSize = des.BlockSize
	case CipherNULL:
		// RFC 2410：无加密无 IV，仍保留常规 padding 字节流。
		sa.EncryptionKey = nil
		blockSize = 1
	}
	if sa.BlockSize != 0 && sa.BlockSize != blockSize {
		return nil, fmt.Errorf("%w: block size %d", ErrInvalidSA, sa.BlockSize)
	}
	sa.BlockSize = blockSize
	if len(sa.IntegrityKey) == 0 {
		return nil, fmt.Errorf("%w: integrity key is empty", ErrInvalidSA)
	}
	if sa.ICVLength == 0 {
		sa.ICVLength = integrityICVLength(sa.Integrity)
	}
	if sa.ICVLength <= 0 {
		return nil, fmt.Errorf("%w: unsupported integrity %d", ErrInvalidSA, sa.Integrity)
	}
	return &sa, nil
}

func (s *SA) Seal(nextHeader uint8, payload []byte, opts SealOptions) ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidSA
	}
	seq := opts.Sequence
	if seq == 0 {
		if s.Sequence == ^uint32(0) {
			return nil, fmt.Errorf("%w: sequence overflow", ErrInvalidSA)
		}
		s.Sequence++
		seq = s.Sequence
	} else if seq > s.Sequence {
		s.Sequence = seq
	}
	iv := append([]byte(nil), opts.IV...)
	if len(iv) == 0 && s.Cipher != CipherNULL {
		random := opts.Random
		if random == nil {
			random = rand.Reader
		}
		iv = make([]byte, s.BlockSize)
		if _, err := io.ReadFull(random, iv); err != nil {
			return nil, err
		}
	}
	if s.Cipher != CipherNULL && len(iv) != s.BlockSize {
		return nil, fmt.Errorf("%w: iv length %d", ErrInvalidPacket, len(iv))
	}
	plain := espPlaintext(payload, nextHeader, s.BlockSize)
	ciphertext, err := s.encrypt(iv, plain)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 8, 8+len(iv)+len(ciphertext)+s.ICVLength)
	binary.BigEndian.PutUint32(packet[0:4], s.SPI)
	binary.BigEndian.PutUint32(packet[4:8], seq)
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)
	icv, err := s.integrity(packet)
	if err != nil {
		return nil, err
	}
	packet = append(packet, icv...)
	return packet, nil
}

func (s *SA) Open(packet []byte) (OpenResult, error) {
	if s == nil {
		return OpenResult{}, ErrInvalidSA
	}
	if len(packet) < 8+s.BlockSize+s.ICVLength+s.BlockSize {
		return OpenResult{}, fmt.Errorf("%w: too short", ErrInvalidPacket)
	}
	spi := binary.BigEndian.Uint32(packet[0:4])
	if spi != s.SPI {
		return OpenResult{}, fmt.Errorf("%w: spi %08x != %08x", ErrInvalidPacket, spi, s.SPI)
	}
	seq := binary.BigEndian.Uint32(packet[4:8])
	if seq == 0 {
		return OpenResult{}, fmt.Errorf("%w: sequence zero", ErrInvalidPacket)
	}
	bodyEnd := len(packet) - s.ICVLength
	gotICV := packet[bodyEnd:]
	wantICV, err := s.integrity(packet[:bodyEnd])
	if err != nil {
		return OpenResult{}, err
	}
	if !hmac.Equal(gotICV, wantICV) {
		return OpenResult{}, fmt.Errorf("%w: icv mismatch", ErrInvalidPacket)
	}
	if err := s.checkReplay(seq); err != nil {
		return OpenResult{}, err
	}
	body := packet[8:bodyEnd]
	if s.Cipher == CipherNULL {
		// RFC 2410：无 IV，body 即（伪）密文。
		payload, nextHeader, err := parseESPPlaintext(body)
		if err != nil {
			return OpenResult{}, err
		}
		s.acceptSequence(seq)
		return OpenResult{SPI: spi, Sequence: seq, NextHeader: nextHeader, Payload: payload}, nil
	}
	if len(body) < s.BlockSize || (len(body)-s.BlockSize)%s.BlockSize != 0 {
		return OpenResult{}, fmt.Errorf("%w: invalid encrypted body length", ErrInvalidPacket)
	}
	iv := body[:s.BlockSize]
	ciphertext := body[s.BlockSize:]
	plain, err := s.decrypt(iv, ciphertext)
	if err != nil {
		return OpenResult{}, err
	}
	payload, nextHeader, err := parseESPPlaintext(plain)
	if err != nil {
		return OpenResult{}, err
	}
	s.acceptSequence(seq)
	return OpenResult{SPI: spi, Sequence: seq, NextHeader: nextHeader, Payload: payload}, nil
}

func (s *SA) integrity(data []byte) ([]byte, error) {
	var mac hashMAC
	switch s.Integrity {
	case IntegrityHMACSHA1_96:
		mac = hmac.New(sha1.New, s.IntegrityKey)
	case IntegrityHMACSHA2_256_128:
		mac = hmac.New(sha256.New, s.IntegrityKey)
	case IntegrityHMACMD5_96:
		mac = hmac.New(md5.New, s.IntegrityKey)
	default:
		return nil, fmt.Errorf("%w: unsupported integrity %d", ErrInvalidSA, s.Integrity)
	}
	_, _ = mac.Write(data)
	sum := mac.Sum(nil)
	if s.ICVLength > len(sum) {
		return nil, fmt.Errorf("%w: icv length %d", ErrInvalidSA, s.ICVLength)
	}
	return append([]byte(nil), sum[:s.ICVLength]...), nil
}

type hashMAC interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func (s *SA) checkReplay(seq uint32) error {
	if s.ReplayWindowSize == 0 {
		return nil
	}
	window := s.ReplayWindowSize
	if window > 64 {
		window = 64
	}
	if seq > s.HighestSequence {
		return nil
	}
	diff := s.HighestSequence - seq
	if diff >= window {
		return ErrReplay
	}
	if s.ReplayBitmap&(uint64(1)<<diff) != 0 {
		return ErrReplay
	}
	return nil
}

func (s *SA) acceptSequence(seq uint32) {
	if s.ReplayWindowSize == 0 {
		if seq > s.HighestSequence {
			s.HighestSequence = seq
		}
		return
	}
	if seq > s.HighestSequence {
		diff := seq - s.HighestSequence
		if diff >= 64 {
			s.ReplayBitmap = 1
		} else {
			s.ReplayBitmap = (s.ReplayBitmap << diff) | 1
		}
		s.HighestSequence = seq
		return
	}
	diff := s.HighestSequence - seq
	if diff < 64 {
		s.ReplayBitmap |= uint64(1) << diff
	}
}

func espPlaintext(payload []byte, nextHeader uint8, blockSize int) []byte {
	padLen := (blockSize - ((len(payload) + 2) % blockSize)) % blockSize
	out := make([]byte, 0, len(payload)+padLen+2)
	out = append(out, payload...)
	for i := 1; i <= padLen; i++ {
		out = append(out, byte(i))
	}
	out = append(out, byte(padLen), nextHeader)
	return out
}

func parseESPPlaintext(plain []byte) ([]byte, uint8, error) {
	if len(plain) < 2 {
		return nil, 0, fmt.Errorf("%w: plaintext too short", ErrInvalidPacket)
	}
	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]
	if padLen+2 > len(plain) {
		return nil, 0, fmt.Errorf("%w: pad length %d", ErrInvalidPacket, padLen)
	}
	paddingStart := len(plain) - 2 - padLen
	for i := 0; i < padLen; i++ {
		if plain[paddingStart+i] != byte(i+1) {
			return nil, 0, fmt.Errorf("%w: bad padding", ErrInvalidPacket)
		}
	}
	return append([]byte(nil), plain[:paddingStart]...), nextHeader, nil
}

func aesCBCEncrypt(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(plain)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid AES-CBC input", ErrInvalidPacket)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid AES-CBC input", ErrInvalidPacket)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func integrityICVLength(integ IntegrityAlgorithm) int {
	switch integ {
	case IntegrityHMACSHA1_96:
		return 12
	case IntegrityHMACSHA2_256_128:
		return 16
	case IntegrityHMACMD5_96:
		return 12
	default:
		return 0
	}
}

// encrypt 按 SA 的加密器封装 ESP 明文（padding 已含）。
func (s *SA) encrypt(iv, plain []byte) ([]byte, error) {
	switch s.Cipher {
	case CipherAES128CBC:
		return aesCBCEncrypt(s.EncryptionKey, iv, plain)
	case Cipher3DESCBC:
		return tripleDesCBCEncrypt(s.EncryptionKey, iv, plain)
	case CipherNULL:
		// RFC 2410：明文原样即"密文"，无 IV。
		return append([]byte(nil), plain...), nil
	default:
		return nil, fmt.Errorf("%w: unsupported cipher %d", ErrInvalidSA, s.Cipher)
	}
}

func (s *SA) decrypt(iv, ciphertext []byte) ([]byte, error) {
	switch s.Cipher {
	case CipherAES128CBC:
		return aesCBCDecrypt(s.EncryptionKey, iv, ciphertext)
	case Cipher3DESCBC:
		return tripleDesCBCDecrypt(s.EncryptionKey, iv, ciphertext)
	case CipherNULL:
		return append([]byte(nil), ciphertext...), nil
	default:
		return nil, fmt.Errorf("%w: unsupported cipher %d", ErrInvalidSA, s.Cipher)
	}
}

func tripleDesCBCEncrypt(key, iv, plain []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(plain)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid 3DES-CBC input", ErrInvalidPacket)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func tripleDesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid 3DES-CBC input", ErrInvalidPacket)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func spiFromBytes(spi []byte) (uint32, error) {
	if len(spi) != 4 {
		return 0, fmt.Errorf("%w: spi length %d", ErrInvalidSA, len(spi))
	}
	v := binary.BigEndian.Uint32(spi)
	if v == 0 {
		return 0, fmt.Errorf("%w: spi is zero", ErrInvalidSA)
	}
	return v, nil
}
