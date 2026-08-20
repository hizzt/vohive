package ikev2

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	DefaultNonceLength          = 32
	DefaultIKEKeyMaterialLength = 192
)

var (
	ErrInvalidInitConfig   = errors.New("invalid ikev2 init config")
	ErrInvalidInitResponse = errors.New("invalid ikev2 init response")
	ErrInvalidKEPayload    = errors.New("invalid ke payload: ePDG rejected DH group")
)

type InitTransport interface {
	ExchangeIKE(context.Context, []byte) ([]byte, error)
}

type UDPTransport struct {
	RemoteAddr      string
	LocalAddr       string
	Timeout         time.Duration
	UseNonESPMarker bool
	ReadBufferSize  int
}

func (t UDPTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	remote := strings.TrimSpace(t.RemoteAddr)
	if remote == "" {
		return nil, fmt.Errorf("%w: remote address is empty", ErrInvalidInitConfig)
	}
	dialer := net.Dialer{}
	if strings.TrimSpace(t.LocalAddr) != "" {
		addr, err := net.ResolveUDPAddr("udp", t.LocalAddr)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	}
	conn, err := dialer.DialContext(ctx, "udp", remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if timeout := t.Timeout; timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	wire := request
	if t.UseNonESPMarker {
		wire = append([]byte{0, 0, 0, 0}, request...)
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	size := t.ReadBufferSize
	if size <= 0 {
		size = 64 * 1024
	}
	buf := make([]byte, size)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := append([]byte(nil), buf[:n]...)
	if len(resp) >= 4 && resp[0] == 0 && resp[1] == 0 && resp[2] == 0 && resp[3] == 0 {
		resp = resp[4:]
	}
	return resp, nil
}

type InitConfig struct {
		Transport         InitTransport
		Random            io.Reader
		SA                SecurityAssociation
		InitiatorSPI      uint64
		NonceI            []byte
		X25519PrivateKey  []byte
		DHGroup           uint16 // 0=Curve25519, 14=MODP2048
		LocalIP           net.IP
		LocalPort         uint16
		RemoteIP          net.IP
		RemotePort        uint16
		KeyMaterialLength int
	}

type InitResult struct {
	RequestBytes    []byte
	ResponseBytes   []byte
	Request         Message
	Response        Message
	SelectedSA      SecurityAssociation
	InitiatorSPI    uint64
	ResponderSPI    uint64
	NonceI          []byte
	NonceR          []byte
	PublicKeyI      []byte
	PublicKeyR      []byte
	SharedSecret    []byte
	PRF             crypto.Hash
	SKEYSEED        []byte
	KeyMaterial     []byte
	Keys            IKEKeys
	MOBIKESupported bool
	NATDetected     bool
}

func RunIKE_SA_INIT(ctx context.Context, cfg InitConfig) (InitResult, error) {
	if cfg.Transport == nil {
		return InitResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidInitConfig)
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	spiI := cfg.InitiatorSPI
	var err error
	if spiI == 0 {
		spiI, err = randomSPI(random)
		if err != nil {
			return InitResult{}, err
		}
	}
	nonceI := append([]byte(nil), cfg.NonceI...)
	if len(nonceI) == 0 {
		nonceI, err = randomBytes(random, DefaultNonceLength)
		if err != nil {
			return InitResult{}, err
		}
	}
priv, err := x25519PrivateKey(cfg.X25519PrivateKey, random)
		if err != nil {
			return InitResult{}, err
		}
		pubI := priv.PublicKey().Bytes()
		dhGroup := cfg.DHGroup
		if dhGroup == 0 {
			dhGroup = DHGroupCurve25519
		}
		sa := cfg.SA
		if len(sa.Proposals) == 0 {
			sa = DefaultIKEProposal()
		}
		saPayload, err := SecurityAssociationPayload(sa)
		if err != nil {
			return InitResult{}, err
		}
		var kePayload Payload
		var privKey *big.Int
		switch dhGroup {
		case DHGroup2048BitMODP:
			pubB, privB, err := generateMODP2048Keypair(random)
			if err != nil {
				return InitResult{}, err
			}
			kePayload = KeyExchangePayload(DHGroup2048BitMODP, pubB)
			pubI = pubB
			privKey = privB
		case DHGroup1024BitMODP:
			pubB, privB, err := generateMODP1024Keypair(random)
			if err != nil {
				return InitResult{}, err
			}
			kePayload = KeyExchangePayload(DHGroup1024BitMODP, pubB)
			pubI = pubB
			privKey = privB
		default:
			kePayload = KeyExchangePayload(DHGroupCurve25519, pubI)
		}
		payloads := []Payload{
			saPayload,
			kePayload,
			NoncePayload(nonceI),
		}
		payloads = append(payloads, initNATPayloads(cfg, spiI, 0)...)
		payloads = append(payloads, MOBIKESupportedNotify())
		req := Message{
			Header: Header{
				InitiatorSPI: spiI,
				ExchangeType: ExchangeIKE_SA_INIT,
				Flags:        FlagInitiator,
			},
			Payloads: payloads,
		}
		reqBytes, err := req.MarshalBinary()
		if err != nil {
			return InitResult{}, err
		}
		respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
		if err != nil {
			return InitResult{}, err
		}
		resp, err := ParseMessage(respBytes)
		if err != nil {
			return InitResult{}, err
		}
		parsed, err := parseInitResponse(resp, spiI)
		if err != nil {
			return InitResult{}, err
		}
		var shared []byte
		switch dhGroup {
		case DHGroup2048BitMODP:
			shared = modp2048SharedSecret(privKey, parsed.keyExchange.KeyData)
		case DHGroup1024BitMODP:
			shared = modp1024SharedSecret(privKey, parsed.keyExchange.KeyData)
		default:
			respPub, err := ecdh.X25519().NewPublicKey(parsed.keyExchange.KeyData)
			if err != nil {
				return InitResult{}, fmt.Errorf("%w: responder KE: %w", ErrInvalidInitResponse, err)
			}
			shared, err = priv.ECDH(respPub)
			if err != nil {
				return InitResult{}, fmt.Errorf("%w: ECDH: %w", ErrInvalidInitResponse, err)
			}
		}
	profile, err := KeyMaterialProfileFromSA(parsed.sa)
	if err != nil {
		return InitResult{}, err
	}
	prfHash := profile.PRF
	skeyseed, err := SKEYSEED(prfHash, nonceI, parsed.nonceR, shared)
	if err != nil {
		return InitResult{}, err
	}
	keyMaterialLength := cfg.KeyMaterialLength
	if keyMaterialLength <= 0 {
		keyMaterialLength = profile.RequiredLength()
	}
	keyMaterial, err := DeriveIKESAKeyMaterial(prfHash, skeyseed, nonceI, parsed.nonceR, spiI, resp.Header.ResponderSPI, keyMaterialLength)
	if err != nil {
		return InitResult{}, err
	}
	var keys IKEKeys
	if len(keyMaterial) >= profile.RequiredLength() {
		keys, err = SplitIKEKeys(profile, keyMaterial)
		if err != nil {
			return InitResult{}, err
		}
	}
	return InitResult{
		RequestBytes:    append([]byte(nil), reqBytes...),
		ResponseBytes:   append([]byte(nil), respBytes...),
		Request:         req,
		Response:        resp,
		SelectedSA:      parsed.sa,
		InitiatorSPI:    spiI,
		ResponderSPI:    resp.Header.ResponderSPI,
		NonceI:          nonceI,
		NonceR:          parsed.nonceR,
		PublicKeyI:      pubI,
		PublicKeyR:      parsed.keyExchange.KeyData,
		SharedSecret:    shared,
		PRF:             prfHash,
		SKEYSEED:        skeyseed,
		KeyMaterial:     keyMaterial,
		Keys:            keys,
		MOBIKESupported: parsed.mobikeSupported,
		NATDetected:     detectNAT(parsed.notifies, spiI, resp.Header.ResponderSPI, cfg),
	}, nil
}

type parsedInitResponse struct {
	sa              SecurityAssociation
	keyExchange     KeyExchange
	nonceR          []byte
	notifies        []Notify
	mobikeSupported bool
}

func parseInitResponse(resp Message, spiI uint64) (parsedInitResponse, error) {
	h := resp.Header
	if h.InitiatorSPI != spiI {
		return parsedInitResponse{}, fmt.Errorf("%w: initiator SPI mismatch", ErrInvalidInitResponse)
	}
	if h.ResponderSPI == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: responder SPI is zero", ErrInvalidInitResponse)
	}
	if h.ExchangeType != ExchangeIKE_SA_INIT || h.MessageID != 0 || h.Flags&FlagResponse == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: unexpected header", ErrInvalidInitResponse)
	}
	var out parsedInitResponse
	for _, p := range resp.Payloads {
		switch p.Type {
		case PayloadNotify:
			n, err := ParseNotify(p.Body)
			if err != nil {
				return parsedInitResponse{}, err
			}
			out.notifies = append(out.notifies, n)
			if n.NotifyType == NotifyInvalidKEPayload {
				return parsedInitResponse{}, NotifyErrorFor(n)
			}
			if n.NotifyType == NotifyMOBIKESupported {
				out.mobikeSupported = true
			}
		}
	}
	for _, p := range resp.Payloads {
		switch p.Type {
		case PayloadSA:
			sa, err := ParseSecurityAssociation(p.Body)
			if err != nil {
				return parsedInitResponse{}, err
			}
			out.sa = sa
		case PayloadKE:
			ke, err := ParseKeyExchange(p.Body)
			if err != nil {
				return parsedInitResponse{}, err
			}
			if ke.DHGroup != DHGroupCurve25519 && ke.DHGroup != DHGroup2048BitMODP && ke.DHGroup != DHGroup1024BitMODP {
				return parsedInitResponse{}, fmt.Errorf("%w: unsupported DH group %d", ErrInvalidInitResponse, ke.DHGroup)
			}
			out.keyExchange = ke
		case PayloadNonce:
			out.nonceR = append([]byte(nil), p.Body...)
		}
	}
	if len(out.sa.Proposals) == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: missing SA", ErrInvalidInitResponse)
	}
	if len(out.keyExchange.KeyData) == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: missing KE", ErrInvalidInitResponse)
	}
	if len(out.nonceR) == 0 {
		return parsedInitResponse{}, fmt.Errorf("%w: missing nonce", ErrInvalidInitResponse)
	}
	return out, nil
}

func initNATPayloads(cfg InitConfig, spiI, spiR uint64) []Payload {
	if cfg.LocalIP == nil || cfg.RemoteIP == nil || cfg.LocalPort == 0 || cfg.RemotePort == 0 {
		return nil
	}
	src, err := NATDetectionNotify(NotifyNATDetectionSourceIP, spiI, spiR, cfg.LocalIP, cfg.LocalPort)
	if err != nil {
		return nil
	}
	dst, err := NATDetectionNotify(NotifyNATDetectionDestinationIP, spiI, spiR, cfg.RemoteIP, cfg.RemotePort)
	if err != nil {
		return nil
	}
	return []Payload{src, dst}
}

func detectNAT(notifies []Notify, spiI, spiR uint64, cfg InitConfig) bool {
	if cfg.LocalIP == nil || cfg.RemoteIP == nil || cfg.LocalPort == 0 || cfg.RemotePort == 0 {
		return false
	}
	sourceHash, sourceErr := NATDetectionHash(spiI, spiR, cfg.RemoteIP, cfg.RemotePort)
	destHash, destErr := NATDetectionHash(spiI, spiR, cfg.LocalIP, cfg.LocalPort)
	if sourceErr != nil || destErr != nil {
		return false
	}
	for _, n := range notifies {
		switch n.NotifyType {
		case NotifyNATDetectionSourceIP:
			if !bytesEqual(n.NotificationData, sourceHash) {
				return true
			}
		case NotifyNATDetectionDestinationIP:
			if !bytesEqual(n.NotificationData, destHash) {
				return true
			}
		}
	}
	return false
}

func selectedPRFHash(sa SecurityAssociation) crypto.Hash {
	for _, p := range sa.Proposals {
		for _, tr := range p.Transforms {
			if tr.Type == TransformPRF {
				if h, err := PRFHashForTransform(tr.ID); err == nil {
					return h
				}
			}
		}
	}
	return crypto.SHA256
}

func x25519PrivateKey(raw []byte, random io.Reader) (*ecdh.PrivateKey, error) {
	if len(raw) > 0 {
		return ecdh.X25519().NewPrivateKey(append([]byte(nil), raw...))
	}
	return ecdh.X25519().GenerateKey(random)
}

// RFC 3526 Group 14 (2048-bit MODP): p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
var modp2048Prime *big.Int

// RFC 2409 Group 2 (1024-bit MODP)
var modp1024Prime *big.Int

func init() {
	modp2048Prime, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	modp1024Prime, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
}

func generateMODP2048Keypair(random io.Reader) (pub []byte, priv *big.Int, err error) {
	if random == nil {
		random = rand.Reader
	}
	privBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, privBytes); err != nil {
		return nil, nil, err
	}
	priv = new(big.Int).SetBytes(privBytes)
	priv.Mod(priv, modp2048Prime)
	if priv.Sign() == 0 {
		priv.SetInt64(1)
	}
	two := big.NewInt(2)
	pubBig := new(big.Int).Exp(two, priv, modp2048Prime)
	pubBytes := make([]byte, 256) // 2048 bits = 256 bytes
	pubFill := pubBig.Bytes()
	copy(pubBytes[256-len(pubFill):], pubFill)
	return pubBytes, priv, nil
}

func generateMODP1024Keypair(random io.Reader) (pub []byte, priv *big.Int, err error) {
	if random == nil {
		random = rand.Reader
	}
	privBytes := make([]byte, 32)
	if _, err := io.ReadFull(random, privBytes); err != nil {
		return nil, nil, err
	}
	priv = new(big.Int).SetBytes(privBytes)
	priv.Mod(priv, modp1024Prime)
	if priv.Sign() == 0 {
		priv.SetInt64(1)
	}
	two := big.NewInt(2)
	pubBig := new(big.Int).Exp(two, priv, modp1024Prime)
	pubBytes := make([]byte, 128) // 1024 bits = 128 bytes
	pubFill := pubBig.Bytes()
	copy(pubBytes[128-len(pubFill):], pubFill)
	return pubBytes, priv, nil
}

func modp2048SharedSecret(priv *big.Int, peerPub []byte) []byte {
	peer := new(big.Int).SetBytes(peerPub)
	secret := new(big.Int).Exp(peer, priv, modp2048Prime)
	secretBytes := make([]byte, 256)
	secretFill := secret.Bytes()
	copy(secretBytes[256-len(secretFill):], secretFill)
	return secretBytes
}

func modp1024SharedSecret(priv *big.Int, peerPub []byte) []byte {
	peer := new(big.Int).SetBytes(peerPub)
	secret := new(big.Int).Exp(peer, priv, modp1024Prime)
	secretBytes := make([]byte, 128)
	secretFill := secret.Bytes()
	copy(secretBytes[128-len(secretFill):], secretFill)
	return secretBytes
}

func randomSPI(random io.Reader) (uint64, error) {
	for {
		b, err := randomBytes(random, 8)
		if err != nil {
			return 0, err
		}
		spi := binary.BigEndian.Uint64(b)
		if spi != 0 {
			return spi, nil
		}
	}
}

func randomBytes(random io.Reader, n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("%w: invalid random length %d", ErrInvalidInitConfig, n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(random, b); err != nil {
		return nil, err
	}
	return b, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
