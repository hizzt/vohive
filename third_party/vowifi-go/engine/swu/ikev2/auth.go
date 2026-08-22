package ikev2

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu/eapaka"
)

var (
	ErrInvalidAuthConfig   = errors.New("invalid ikev2 auth config")
	ErrInvalidAuthResponse = errors.New("invalid ikev2 auth response")
)

const (
	maxAKAControlFollowups  = 3
	maxFullAuthEAPExchanges = 8
)

type AuthConfig struct {
	Transport        InitTransport
	Init             InitResult
	Keys             IKEKeys
	InitiatorID      Identity
	ResponderID      *Identity
	DeviceIdentity   *DeviceIdentity
	EAPIdentity      string
	ChildSA          SecurityAssociation
	ChildSPI         []byte
	TSi              TrafficSelectors
	TSr              TrafficSelectors
	Configuration    Configuration
	Random           io.Reader
	InitialIV        []byte
	EAPIdentityIV    []byte
	InitialMessageID uint32
}

type AuthResult struct {
	InitialRequestBytes    []byte
	InitialResponseBytes   []byte
	IdentityRequestBytes   []byte
	IdentityResponseBytes  []byte
	InitialResponseInner   []Payload
	IdentityResponseInner  []Payload
	EAPRequest             *eapaka.Packet
	EAPAfterIdentity       *eapaka.Packet
	IdentityTranscript     [][]byte
	DeviceIdentityAnswered *Payload
	NextMessageID          uint32
}

type AKAChallengeConfig struct {
	Transport          InitTransport
	Init               InitResult
	Keys               IKEKeys
	SIM                sim.AKAProvider
	EAPKeys            eapaka.Keys
	Identity           string
	Request            eapaka.Packet
	IdentityTranscript [][]byte
	ChildSPI           []byte
	MessageID          uint32
	Random             io.Reader
	IV                 []byte
	EAPReauthIV        []byte
	EAPReauthCounter   uint16
	EAPReauthCounterOK bool
}

type AKAChallengeResult struct {
	RequestBytes             []byte
	ResponseBytes            []byte
	ResponseInner            []Payload
	EAPResponse              eapaka.Packet
	EAPNext                  *eapaka.Packet
	EAPKeys                  eapaka.Keys
	EAPEncryptedAttributes   []eapaka.Attribute
	EAPNextPseudonym         string
	EAPNextReauthID          string
	EAPReauthenticated       bool
	EAPReauthCounter         uint16
	EAPReauthCounterTooSmall bool
	EAPNotifications         []eapaka.Packet
	EAPClientError           bool
	ChildSA                  *ChildSAResult
	SyncFailure              bool
	AuthFailure              bool
	KDFNegotiated            bool
	NextMessageID            uint32
	FollowupRequestBytes     [][]byte
	FollowupResponseBytes    [][]byte
	FinalResponseBytes       []byte
	FinalResponseInner       []Payload
}

type FullAuthConfig struct {
	Transport          InitTransport
	Init               InitResult
	Keys               IKEKeys
	SIM                sim.AKAProvider
	EAPKeys            eapaka.Keys
	InitiatorID        Identity
	ResponderID        *Identity
	DeviceIdentity     *DeviceIdentity
	EAPIdentity        string
	EAPReauthIdentity  string
	EAPReauthCounter   uint16
	EAPReauthCounterOK bool
	ChildSA            SecurityAssociation
	ChildSPI           []byte
	TSi                TrafficSelectors
	TSr                TrafficSelectors
	Configuration      Configuration
	Random             io.Reader
	InitialIV          []byte
	EAPIdentityIV      []byte
	EAPReauthIV        []byte
	InitialMessageID   uint32
}

// FullAuthResult 增加 AUTH 完成标记与最终交换字节。
type FullAuthResult struct {
	Auth                     AuthResult
	IdentityExchanges        []EAPIdentityExchange
	AKAChallenges            []AKAChallengeResult
	ChildSA                  *ChildSAResult
	EAPKeys                  eapaka.Keys
	EAPLast                  *eapaka.Packet
	EAPNotifications         []eapaka.Packet
	EAPClientError           bool
	EAPNextPseudonym         string
	EAPNextReauthID          string
	EAPReauthenticated       bool
	EAPReauthCounter         uint16
	EAPReauthCounterTooSmall bool
	SyncFailure              bool
	AuthFailure              bool
	KDFNegotiations          int
	NextMessageID            uint32
	FinalResponseBytes       []byte
	FinalResponseInner       []Payload
	IKEAuthCompleted         bool
	AuthRequestBytes         []byte
	AuthResponseBytes        []byte
}

type EAPIdentityExchange struct {
	Request       eapaka.Packet
	Response      eapaka.Packet
	RequestBytes  []byte
	ResponseBytes []byte
	ResponseInner []Payload
	EAPNext       *eapaka.Packet
	Transcript    [][]byte
	NextMessageID uint32
}

func dumpAuthPayloadTypes(tag string, payloads []Payload) {
	if os.Getenv("SWU_DEBUG_AUTH") == "" && os.Getenv("SWU_DEBUG_IKE") == "" {
		return
	}
	for _, p := range payloads {
		switch p.Type {
		case PayloadNotify:
			if len(p.Body) >= 4 {
				protocolID := p.Body[0]
				spiSize := p.Body[1]
				notifyType := binary.BigEndian.Uint16(p.Body[2:4])
				fmt.Fprintf(os.Stderr, "[swu] %s: NOTIFY protocol=%d spi_size=%d type=%d (0x%04x) body_len=%d body=%x\n", tag, protocolID, spiSize, notifyType, notifyType, len(p.Body), p.Body)
			} else {
				fmt.Fprintf(os.Stderr, "[swu] %s: NOTIFY (short body, len=%d body=%x)\n", tag, len(p.Body), p.Body)
			}
		case PayloadEAP:
			if len(p.Body) >= 4 {
				eapCode := p.Body[0]
				eapType := p.Body[2]
				fmt.Fprintf(os.Stderr, "[swu] %s: EAP code=%d type=%d len=%d\n", tag, eapCode, eapType, len(p.Body))
			} else {
				fmt.Fprintf(os.Stderr, "[swu] %s: EAP (short body, len=%d)\n", tag, len(p.Body))
			}
		case PayloadCP:
			if len(p.Body) >= 1 {
				cpType := p.Body[0]
				fmt.Fprintf(os.Stderr, "[swu] %s: CP type=%d len=%d\n", tag, cpType, len(p.Body))
			}
		default:
			fmt.Fprintf(os.Stderr, "[swu] %s: payload type=%d len=%d\n", tag, p.Type, len(p.Body))
		}
	}
}

func RunIKE_AUTH_EAPIdentity(ctx context.Context, cfg AuthConfig) (AuthResult, error) {
	if cfg.Transport == nil {
		return AuthResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return AuthResult{}, err
	}
	spiI, spiR := cfg.Init.InitiatorSPI, cfg.Init.ResponderSPI
	if spiI == 0 || spiR == 0 {
		return AuthResult{}, fmt.Errorf("%w: missing IKE SPIs", ErrInvalidAuthConfig)
	}
	messageID := cfg.InitialMessageID
	if messageID == 0 {
		messageID = 1
	}
	initialInner, err := BuildIKEAuthInitialPayloads(cfg)
	if err != nil {
		return AuthResult{}, err
	}
	initialIV, err := authIV(cfg.Random, keys.Profile, cfg.InitialIV)
	if err != nil {
		return AuthResult{}, err
	}
	_, initialReqBytes, err := ProtectMessage(authHeader(cfg.Init, messageID, true), keys, true, initialInner, initialIV)
	if err != nil {
		return AuthResult{}, err
	}
	if os.Getenv("SWU_DEBUG_IKE") != "" {
		// 自解密验证：用同一密钥解回自己的密文，确认加密层自洽。
		if _, inner, derr := UnprotectMessage(append([]byte(nil), initialReqBytes...), keys, true); derr != nil {
			fmt.Fprintf(os.Stderr, "[swu] IKE_AUTH(1) self-decrypt FAILED: %v\n", derr)
		} else {
			fmt.Fprintf(os.Stderr, "[swu] IKE_AUTH(1) self-decrypt ok, inner types=%x\n", payloadTypesHex(inner))
		}
		fmt.Fprintf(os.Stderr, "[swu] IKE_AUTH(1) raw (%d bytes): %x\n", len(initialReqBytes), initialReqBytes)
	}
	initialRespBytes, err := cfg.Transport.ExchangeIKE(ctx, initialReqBytes)
	if err != nil {
		return AuthResult{}, err
	}
	initialResp, initialInnerResp, err := unprotectAuthResponse(initialRespBytes, cfg.Init, keys, messageID)
	if err != nil {
		return AuthResult{}, err
	}
	dumpAuthPayloadTypes("IKE_AUTH initial response", initialInnerResp)
	eapReq, eapReqRaw, hasEAP, err := firstEAPPacketWithRaw(initialInnerResp)
	if err != nil {
		return AuthResult{}, err
	}
	// ePDG 可能直接在首条响应里拒绝（无 EAP payload，仅错误 NOTIFY）——
	// 这正是 86 字节响应的场景，必须把拒绝理由带出来。
	if !hasEAP {
		if notifyErr := authNotifyError(initialInnerResp); notifyErr != nil {
			return AuthResult{}, notifyErr
		}
	}
	out := AuthResult{
		InitialRequestBytes:  append([]byte(nil), initialReqBytes...),
		InitialResponseBytes: append([]byte(nil), initialRespBytes...),
		InitialResponseInner: clonePayloads(initialInnerResp),
		NextMessageID:        messageID + 1,
	}
	_ = initialResp
	if !hasEAP {
		return out, nil
	}
	out.EAPRequest = &eapReq
	if eapReq.Code != eapaka.CodeRequest || eapReq.Subtype != eapaka.SubtypeIdentity {
		return out, nil
	}
	identity := strings.TrimSpace(cfg.EAPIdentity)
	if identity == "" {
		identity = strings.TrimSpace(string(cfg.InitiatorID.Data))
	}
	if identity == "" {
		return AuthResult{}, fmt.Errorf("%w: eap identity is empty", ErrInvalidAuthConfig)
	}
	identityPacket, err := (eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: eapReq.Identifier,
		Type:       eapReq.Type,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{eapaka.IdentityAttribute(identity)},
	}).MarshalBinary()
	if err != nil {
		return AuthResult{}, err
	}
	// ePDG 在首条响应里请求 DEVICE_IDENTITY 时，按 TS 24.302 §7.2.6 在下一条
	// 消息（EAP-Response/Identity）里附带应答（vowifi_gateway create_IKE_AUTH_2）。
	out.DeviceIdentityAnswered = answerDeviceIdentityRequest(initialInnerResp, cfg.DeviceIdentity)
	identityIV, err := authIV(cfg.Random, keys.Profile, cfg.EAPIdentityIV)
	if err != nil {
		return AuthResult{}, err
	}
	identityPayloads := []Payload{EAPPayload(identityPacket)}
	if out.DeviceIdentityAnswered != nil {
		identityPayloads = append(identityPayloads, *out.DeviceIdentityAnswered)
	}
	_, identityReqBytes, err := ProtectMessage(authHeader(cfg.Init, messageID+1, true), keys, true, identityPayloads, identityIV)
	if err != nil {
		return AuthResult{}, err
	}
	identityRespBytes, err := cfg.Transport.ExchangeIKE(ctx, identityReqBytes)
	if err != nil {
		return AuthResult{}, err
	}
	_, identityInnerResp, err := unprotectAuthResponse(identityRespBytes, cfg.Init, keys, messageID+1)
	if err != nil {
		return AuthResult{}, err
	}
	dumpAuthPayloadTypes("IKE_AUTH identity response", identityInnerResp)
	// 回完身份后 ePDG 若直接拒绝（无后续 EAP），同样要把 NOTIFY 理由带出来。
	if _, ok, err := firstEAPPacket(identityInnerResp); err != nil {
		return AuthResult{}, err
	} else if !ok {
		if notifyErr := authNotifyError(identityInnerResp); notifyErr != nil {
			return AuthResult{}, notifyErr
		}
	}
	out.IdentityRequestBytes = append([]byte(nil), identityReqBytes...)
	out.IdentityResponseBytes = append([]byte(nil), identityRespBytes...)
	out.IdentityResponseInner = clonePayloads(identityInnerResp)
	out.IdentityTranscript = cloneByteSlices([][]byte{eapReqRaw, identityPacket})
	out.NextMessageID = messageID + 2
	if nextEAP, ok, err := firstEAPPacket(identityInnerResp); err != nil {
		return AuthResult{}, err
	} else if ok {
		out.EAPAfterIdentity = &nextEAP
	}
	return out, nil
}

func RunIKE_AUTH_Full(ctx context.Context, cfg FullAuthConfig) (FullAuthResult, error) {
	localChildSPI, err := fullAuthLocalChildSPI(cfg)
	if err != nil {
		return FullAuthResult{}, err
	}
	auth, err := RunIKE_AUTH_EAPIdentity(ctx, AuthConfig{
		Transport:        cfg.Transport,
		Init:             cfg.Init,
		Keys:             cfg.Keys,
		InitiatorID:      cfg.InitiatorID,
		ResponderID:      cfg.ResponderID,
		DeviceIdentity:   cfg.DeviceIdentity,
		EAPIdentity:      cfg.EAPIdentity,
		ChildSA:          cfg.ChildSA,
		ChildSPI:         localChildSPI,
		TSi:              cfg.TSi,
		TSr:              cfg.TSr,
		Configuration:    cfg.Configuration,
		Random:           cfg.Random,
		InitialIV:        cfg.InitialIV,
		EAPIdentityIV:    cfg.EAPIdentityIV,
		InitialMessageID: cfg.InitialMessageID,
	})
	if err != nil {
		return FullAuthResult{}, err
	}
	finalInner, finalBytes := authFinalResponse(auth)
	out := FullAuthResult{
		Auth:               auth,
		EAPKeys:            cfg.EAPKeys,
		NextMessageID:      auth.NextMessageID,
		FinalResponseBytes: append([]byte(nil), finalBytes...),
		FinalResponseInner: clonePayloads(finalInner),
	}
	if child, ok, err := parseChildSAIfPresent(cfg.Init, finalInner, localChildSPI, out.NextMessageID); err != nil {
		return FullAuthResult{}, err
	} else if ok {
		out.ChildSA = &child
		return out, nil
	}
	next := authNextEAP(auth)
	identity := strings.TrimSpace(cfg.EAPIdentity)
	if identity == "" {
		identity = strings.TrimSpace(string(cfg.InitiatorID.Data))
	}
	identityTranscript := cloneByteSlices(auth.IdentityTranscript)
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	for i := 0; i < maxFullAuthEAPExchanges; i++ {
		if next == nil {
			return out, fmt.Errorf("%w: IKE_AUTH did not complete EAP", ErrInvalidAuthResponse)
		}
		out.EAPLast = cloneEAPPacketPtr(next)
		if next.Code == eapaka.CodeSuccess {
			return completeIKEAuthWithAUTH(ctx, cfg, out, keys, localChildSPI)
		}
		if next.Code == eapaka.CodeFailure {
			return out, fmt.Errorf("%w: EAP failure", ErrInvalidAuthResponse)
		}
		if next.Code != eapaka.CodeRequest {
			return out, fmt.Errorf("%w: unexpected EAP code %d", ErrInvalidAuthResponse, next.Code)
		}
		if next.Subtype == eapaka.SubtypeIdentity {
			_, requestRaw, _, err := firstEAPPacketWithRaw(out.FinalResponseInner)
			if err != nil {
				return FullAuthResult{}, err
			}
			exchange, err := runIKEAuthIdentityExchange(ctx, identityExchangeConfig{
				Transport:  cfg.Transport,
				Init:       cfg.Init,
				Keys:       cfg.Keys,
				Random:     cfg.Random,
				Request:    *next,
				RequestRaw: requestRaw,
				Identity:   identity,
				MessageID:  out.NextMessageID,
			})
			if err != nil {
				return FullAuthResult{}, err
			}
			out.IdentityExchanges = append(out.IdentityExchanges, exchange)
			identityTranscript = append(identityTranscript, exchange.Transcript...)
			out.NextMessageID = exchange.NextMessageID
			out.FinalResponseBytes = append([]byte(nil), exchange.ResponseBytes...)
			out.FinalResponseInner = clonePayloads(exchange.ResponseInner)
			if child, ok, err := parseChildSAIfPresent(cfg.Init, out.FinalResponseInner, localChildSPI, out.NextMessageID); err != nil {
				return FullAuthResult{}, err
			} else if ok {
				out.ChildSA = &child
				return out, nil
			}
			next = exchange.EAPNext
			continue
		}
		challengeIdentity := identity
		if next.Subtype == eapaka.SubtypeReauthentication && strings.TrimSpace(cfg.EAPReauthIdentity) != "" {
			challengeIdentity = strings.TrimSpace(cfg.EAPReauthIdentity)
		}
		challenge, err := RunIKE_AUTH_AKAChallenge(ctx, AKAChallengeConfig{
			Transport:          cfg.Transport,
			Init:               cfg.Init,
			Keys:               cfg.Keys,
			SIM:                cfg.SIM,
			EAPKeys:            out.EAPKeys,
			Identity:           challengeIdentity,
			Request:            *next,
			IdentityTranscript: identityTranscript,
			ChildSPI:           localChildSPI,
			MessageID:          out.NextMessageID,
			Random:             cfg.Random,
			EAPReauthIV:        cfg.EAPReauthIV,
			EAPReauthCounter:   cfg.EAPReauthCounter,
			EAPReauthCounterOK: cfg.EAPReauthCounterOK,
		})
		if err != nil {
			return FullAuthResult{}, err
		}
		out.AKAChallenges = append(out.AKAChallenges, challenge)
		out.NextMessageID = challenge.NextMessageID
		out.FinalResponseBytes = append([]byte(nil), challenge.FinalResponseBytes...)
		out.FinalResponseInner = clonePayloads(challenge.FinalResponseInner)
		out.EAPNotifications = append(out.EAPNotifications, challenge.EAPNotifications...)
		out.EAPClientError = out.EAPClientError || challenge.EAPClientError
		if challenge.EAPNextPseudonym != "" {
			out.EAPNextPseudonym = challenge.EAPNextPseudonym
		}
		if challenge.EAPNextReauthID != "" {
			out.EAPNextReauthID = challenge.EAPNextReauthID
		}
		out.EAPReauthenticated = out.EAPReauthenticated || challenge.EAPReauthenticated
		if challenge.EAPReauthCounter != 0 {
			out.EAPReauthCounter = challenge.EAPReauthCounter
		}
		out.EAPReauthCounterTooSmall = out.EAPReauthCounterTooSmall || challenge.EAPReauthCounterTooSmall
		out.SyncFailure = out.SyncFailure || challenge.SyncFailure
		out.AuthFailure = out.AuthFailure || challenge.AuthFailure
		if challenge.KDFNegotiated {
			out.KDFNegotiations++
		}
		if len(challenge.EAPKeys.KAut) > 0 {
			out.EAPKeys = challenge.EAPKeys
		}
		if challenge.ChildSA != nil {
			child := *challenge.ChildSA
			out.ChildSA = &child
			if challenge.EAPNext != nil {
				out.EAPLast = cloneEAPPacketPtr(challenge.EAPNext)
			}
			// ePDG 把 EAP-Success 与 CP/SA 合并在最后一条响应时，CHILD_SA 已就绪，
			// 但 RFC 7296 §2.16 的第四条 AUTH 消息仍必须补发（部分 ePDG 不等它就
			// 下发流量，也有严格实现等它才激活 SA）。补发失败不推翻已建立的 SA。
			if out.EAPLast != nil && out.EAPLast.Code == eapaka.CodeSuccess && !out.IKEAuthCompleted {
				completed, authErr := completeIKEAuthWithAUTH(ctx, cfg, out, keys, localChildSPI)
				if authErr == nil {
					return completed, nil
				}
				fmt.Fprintf(os.Stderr, "[swu] post-success AUTH exchange failed (%v), keeping CHILD_SA from EAP-Success response\n", authErr)
			}
			return out, nil
		}
		next = challenge.EAPNext
	}
	return out, fmt.Errorf("%w: too many IKE_AUTH EAP exchanges", ErrInvalidAuthResponse)
}

func RunIKE_AUTH_AKAChallenge(ctx context.Context, cfg AKAChallengeConfig) (AKAChallengeResult, error) {
	if cfg.Transport == nil {
		return AKAChallengeResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return AKAChallengeResult{}, err
	}
	if cfg.MessageID == 0 {
		return AKAChallengeResult{}, fmt.Errorf("%w: message_id is zero", ErrInvalidAuthConfig)
	}
	var eapResp eapaka.Packet
	var eapKeys eapaka.Keys
	var syncFailure bool
	var authFailure bool
	var kdfNegotiated bool
	var clientError bool
	var reauthenticated bool
	var reauthCounter uint16
	var reauthCounterTooSmall bool
	var notifications []eapaka.Packet
	var encryptedAttributes []eapaka.Attribute
	var identityState eapaka.EncryptedIdentityState
	if cfg.Request.Code == eapaka.CodeRequest && cfg.Request.Subtype == eapaka.SubtypeReauthentication && len(cfg.EAPKeys.KAut) > 0 {
		parsed, err := eapaka.ParseReauthenticationRequest(cfg.Request, cfg.EAPKeys)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		reauthCounter = parsed.Counter
		encryptedAttributes = parsed.EncryptedAttributes
		identityState = parsed.IdentityState
		eapIV, err := eapReauthIV(cfg.Random, cfg.EAPReauthIV)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		if cfg.EAPReauthCounterOK && parsed.Counter <= cfg.EAPReauthCounter {
			eapResp, err = eapaka.BuildReauthenticationCounterTooSmallResponse(cfg.Request, cfg.EAPKeys, eapIV)
			if err != nil {
				return AKAChallengeResult{}, err
			}
			eapKeys = cfg.EAPKeys
			reauthCounterTooSmall = true
		} else {
			identity := strings.TrimSpace(cfg.Identity)
			if identity == "" {
				return AKAChallengeResult{}, fmt.Errorf("%w: reauthentication identity is empty", ErrInvalidAuthConfig)
			}
			eapResp, eapKeys, err = eapaka.BuildReauthenticationResponse(identity, cfg.Request, cfg.EAPKeys, eapIV)
			if err != nil {
				return AKAChallengeResult{}, err
			}
			reauthenticated = true
		}
	} else if response, handled, err := buildAKAControlResponse(cfg.Request, cfg.EAPKeys); err != nil {
		return AKAChallengeResult{}, err
	} else if handled {
		eapResp = response
		clientError = response.Subtype == eapaka.SubtypeClientError
		if response.Subtype == eapaka.SubtypeNotification {
			notifications = append(notifications, cloneEAPPacket(cfg.Request))
		}
	} else if response, negotiated, err := eapaka.BuildAKAPrimeKDFNegotiationResponse(cfg.Request); err != nil {
		return AKAChallengeResult{}, err
	} else if negotiated {
		eapResp = response
		kdfNegotiated = true
	} else {
		if cfg.SIM == nil {
			return AKAChallengeResult{}, fmt.Errorf("%w: SIM provider is nil", ErrInvalidAuthConfig)
		}
		rand16, autn16, err := eapaka.ChallengeRANDAndAUTN(cfg.Request)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		aka, err := cfg.SIM.CalculateAKA(rand16, autn16)
		if err != nil {
			switch {
			case errors.Is(err, sim.ErrSyncFailure) && len(aka.AUTS) > 0:
				eapResp, err = eapaka.BuildSynchronizationFailureResponse(cfg.Request, aka.AUTS)
				syncFailure = true
			case errors.Is(err, sim.ErrAuthFailure):
				eapResp, err = eapaka.BuildAuthenticationRejectResponse(cfg.Request)
				authFailure = true
			}
			if err != nil {
				return AKAChallengeResult{}, err
			}
		} else {
			identity := strings.TrimSpace(cfg.Identity)
			if identity == "" {
				return AKAChallengeResult{}, fmt.Errorf("%w: identity is empty", ErrInvalidAuthConfig)
			}
			eapResp, eapKeys, err = eapaka.BuildChallengeResponseWithCheckcode(identity, cfg.Request, aka, cfg.IdentityTranscript)
			if err != nil {
				return AKAChallengeResult{}, err
			}
			if attrs, _, err := eapaka.DecryptChallengeEncryptedAttributes(cfg.Request, eapKeys); err != nil {
				return AKAChallengeResult{}, err
			} else if len(attrs) > 0 {
				encryptedAttributes = attrs
				identityState, err = eapaka.IdentityStateFromAttributes(attrs)
				if err != nil {
					return AKAChallengeResult{}, err
				}
			}
		}
	}
	eapRaw, err := eapResp.MarshalBinary()
	if err != nil {
		return AKAChallengeResult{}, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, cfg.IV)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, cfg.MessageID, true), keys, true, []Payload{EAPPayload(eapRaw)}, iv)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, cfg.MessageID)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	controlKeys := eapKeys
	if len(controlKeys.KAut) == 0 {
		controlKeys = cfg.EAPKeys
	}
	resultEAPKeys := eapKeys
	if len(resultEAPKeys.KAut) == 0 {
		resultEAPKeys = cfg.EAPKeys
	}
	followups, err := runAKAControlFollowups(ctx, cfg, keys, inner, cfg.MessageID+1, controlKeys)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	notifications = append(notifications, followups.Notifications...)
	finalRespBytes := respBytes
	finalInner := inner
	nextMessageID := cfg.MessageID + 1
	if len(followups.ResponseBytes) > 0 {
		finalRespBytes = followups.ResponseBytes[len(followups.ResponseBytes)-1]
		finalInner = followups.FinalInner
		nextMessageID = followups.NextMessageID
		clientError = clientError || followups.ClientError
	}
	out := AKAChallengeResult{
		RequestBytes:             append([]byte(nil), reqBytes...),
		ResponseBytes:            append([]byte(nil), respBytes...),
		ResponseInner:            clonePayloads(inner),
		EAPResponse:              eapResp,
		EAPKeys:                  resultEAPKeys,
		EAPEncryptedAttributes:   cloneEAPAttributes(encryptedAttributes),
		EAPNextPseudonym:         identityState.NextPseudonym,
		EAPNextReauthID:          identityState.NextReauthID,
		EAPReauthenticated:       reauthenticated,
		EAPReauthCounter:         reauthCounter,
		EAPReauthCounterTooSmall: reauthCounterTooSmall,
		EAPNotifications:         cloneEAPPackets(notifications),
		EAPClientError:           clientError,
		SyncFailure:              syncFailure,
		AuthFailure:              authFailure,
		KDFNegotiated:            kdfNegotiated,
		NextMessageID:            nextMessageID,
		FollowupRequestBytes:     cloneByteSlices(followups.RequestBytes),
		FollowupResponseBytes:    cloneByteSlices(followups.ResponseBytes),
		FinalResponseBytes:       append([]byte(nil), finalRespBytes...),
		FinalResponseInner:       clonePayloads(finalInner),
	}
	if next, ok, err := firstEAPPacket(finalInner); err != nil {
		return AKAChallengeResult{}, err
	} else if ok {
		out.EAPNext = &next
	}
	if hasPayload(finalInner, PayloadSA) {
		child, err := ParseChildSAResult(cfg.Init, finalInner, cfg.ChildSPI)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		child.NextMessageID = nextMessageID
		out.ChildSA = &child
	}
	return out, nil
}

type akaControlFollowups struct {
	RequestBytes  [][]byte
	ResponseBytes [][]byte
	FinalInner    []Payload
	NextMessageID uint32
	Notifications []eapaka.Packet
	ClientError   bool
}

func runAKAControlFollowups(ctx context.Context, cfg AKAChallengeConfig, keys IKEKeys, initialInner []Payload, messageID uint32, eapKeys eapaka.Keys) (akaControlFollowups, error) {
	out := akaControlFollowups{
		FinalInner:    clonePayloads(initialInner),
		NextMessageID: messageID,
	}
	for i := 0; i < maxAKAControlFollowups; i++ {
		next, ok, err := firstEAPPacket(out.FinalInner)
		if err != nil {
			return akaControlFollowups{}, err
		}
		if !ok {
			return out, nil
		}
		response, handled, err := buildAKAControlResponse(next, eapKeys)
		if err != nil {
			return akaControlFollowups{}, err
		}
		if !handled {
			return out, nil
		}
		if response.Subtype == eapaka.SubtypeNotification {
			out.Notifications = append(out.Notifications, cloneEAPPacket(next))
		}
		if response.Subtype == eapaka.SubtypeClientError {
			out.ClientError = true
		}
		raw, err := response.MarshalBinary()
		if err != nil {
			return akaControlFollowups{}, err
		}
		iv, err := authIV(cfg.Random, keys.Profile, nil)
		if err != nil {
			return akaControlFollowups{}, err
		}
		_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, out.NextMessageID, true), keys, true, []Payload{EAPPayload(raw)}, iv)
		if err != nil {
			return akaControlFollowups{}, err
		}
		respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
		if err != nil {
			return akaControlFollowups{}, err
		}
		_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, out.NextMessageID)
		if err != nil {
			return akaControlFollowups{}, err
		}
		out.RequestBytes = append(out.RequestBytes, append([]byte(nil), reqBytes...))
		out.ResponseBytes = append(out.ResponseBytes, append([]byte(nil), respBytes...))
		out.FinalInner = clonePayloads(inner)
		out.NextMessageID++
	}
	next, ok, err := firstEAPPacket(out.FinalInner)
	if err != nil {
		return akaControlFollowups{}, err
	}
	if ok {
		if _, handled, err := buildAKAControlResponse(next, eapKeys); err != nil {
			return akaControlFollowups{}, err
		} else if handled {
			return akaControlFollowups{}, fmt.Errorf("%w: too many EAP-AKA control followups", ErrInvalidAuthResponse)
		}
	}
	return out, nil
}

func buildAKAControlResponse(request eapaka.Packet, keys eapaka.Keys) (eapaka.Packet, bool, error) {
	if response, handled, err := eapaka.BuildNotificationResponse(request); err != nil {
		if errors.Is(err, eapaka.ErrInvalidKeyMaterial) && len(keys.KAut) > 0 {
			return eapaka.BuildAuthenticatedNotificationResponse(request, keys.KAut)
		}
		return eapaka.Packet{}, handled, err
	} else if handled {
		return response, true, nil
	}
	if request.Code == eapaka.CodeRequest && request.Subtype != eapaka.SubtypeChallenge && request.Subtype != eapaka.SubtypeIdentity {
		response, err := eapaka.BuildClientErrorResponse(request, eapaka.ClientErrorUnableToProcessPacket)
		return response, true, err
	}
	return eapaka.Packet{}, false, nil
}

type identityExchangeConfig struct {
	Transport  InitTransport
	Init       InitResult
	Keys       IKEKeys
	Random     io.Reader
	Request    eapaka.Packet
	RequestRaw []byte
	Identity   string
	MessageID  uint32
}

func runIKEAuthIdentityExchange(ctx context.Context, cfg identityExchangeConfig) (EAPIdentityExchange, error) {
	if cfg.Transport == nil {
		return EAPIdentityExchange{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	if cfg.MessageID == 0 {
		return EAPIdentityExchange{}, fmt.Errorf("%w: message_id is zero", ErrInvalidAuthConfig)
	}
	if cfg.Request.Code != eapaka.CodeRequest || cfg.Request.Subtype != eapaka.SubtypeIdentity {
		return EAPIdentityExchange{}, fmt.Errorf("%w: not an EAP identity request", ErrInvalidAuthConfig)
	}
	identity := strings.TrimSpace(cfg.Identity)
	if identity == "" {
		return EAPIdentityExchange{}, fmt.Errorf("%w: eap identity is empty", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return EAPIdentityExchange{}, err
	}
	requestRaw := append([]byte(nil), cfg.RequestRaw...)
	if len(requestRaw) == 0 {
		encoded, err := cfg.Request.MarshalBinary()
		if err != nil {
			return EAPIdentityExchange{}, err
		}
		requestRaw = encoded
	}
	response := eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: cfg.Request.Identifier,
		Type:       cfg.Request.Type,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{eapaka.IdentityAttribute(identity)},
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, nil)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, cfg.MessageID, true), keys, true, []Payload{EAPPayload(raw)}, iv)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, cfg.MessageID)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	out := EAPIdentityExchange{
		Request:       cloneEAPPacket(cfg.Request),
		Response:      cloneEAPPacket(response),
		RequestBytes:  append([]byte(nil), reqBytes...),
		ResponseBytes: append([]byte(nil), respBytes...),
		ResponseInner: clonePayloads(inner),
		Transcript:    cloneByteSlices([][]byte{requestRaw, raw}),
		NextMessageID: cfg.MessageID + 1,
	}
	if next, ok, err := firstEAPPacket(inner); err != nil {
		return EAPIdentityExchange{}, err
	} else if ok {
		out.EAPNext = &next
	}
	return out, nil
}

func BuildIKEAuthInitialPayloads(cfg AuthConfig) ([]Payload, error) {
	idPayload, err := IdentityPayload(PayloadIDi, cfg.InitiatorID)
	if err != nil {
		return nil, err
	}
	payloads := []Payload{idPayload}
	// IDr：对齐 vowifi_gateway（swu_ike.py L3492-3495），默认发裸 APN 的 ID_FQDN。
	if cfg.ResponderID != nil {
		idrPayload, err := IdentityPayload(PayloadIDr, *cfg.ResponderID)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, idrPayload)
	}
	childSA := cfg.ChildSA
	if len(childSA.Proposals) == 0 {
		spi := append([]byte(nil), cfg.ChildSPI...)
		if len(spi) == 0 {
			random := cfg.Random
			if random == nil {
				random = rand.Reader
			}
			var err error
			spi, err = randomBytes(random, 4)
			if err != nil {
				return nil, err
			}
		}
		if len(spi) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidAuthConfig, len(spi))
		}
		childSA = DefaultESPProposal(spi)
	}
	saPayload, err := SecurityAssociationPayload(childSA)
	if err != nil {
		return nil, err
	}
	tsi := cfg.TSi
	if len(tsi.Selectors) == 0 {
		tsi = IPv4AnyTrafficSelectors()
	}
	tsiPayload, err := TrafficSelectorsPayload(PayloadTSi, tsi)
	if err != nil {
		return nil, err
	}
	tsr := cfg.TSr
	if len(tsr.Selectors) == 0 {
		tsr = IPv4AnyTrafficSelectors()
	}
	tsrPayload, err := TrafficSelectorsPayload(PayloadTSr, tsr)
	if err != nil {
		return nil, err
	}
	cfgPayload, err := ConfigurationPayload(firstConfiguration(cfg.Configuration, SWuConfigurationRequest()))
	if err != nil {
		return nil, err
	}
	payloads = append(payloads, cfgPayload, saPayload, tsiPayload, tsrPayload)
	// INITIAL_CONTACT：让 ePDG 清掉本 IDi 的旧 SA（vowifi_gateway 行为）。
	payloads = append(payloads, InitialContactNotify())
	// MOBIKE_SUPPORTED：能力声明（对齐 VoCat/Android；ePDG 回应与否都无害）。
	payloads = append(payloads, MOBIKESupportedNotify())
	// DEVICE_IDENTITY 不主动发：vowifi_gateway 只在 ePDG 请求后在 EAP 响应里应答，
	// 主动塞进首条 IKE_AUTH 会被部分 ePDG 视为非法 notify 而静默丢包。
	// EAP_ONLY_AUTHENTICATION（RFC 5998）：EAP 模式必选收尾通知。
	payloads = append(payloads, EAPOnlyAuthenticationNotify())
	if os.Getenv("SWU_DEBUG_AUTH") != "" {
		saBody, _ := childSA.MarshalBinary()
		fmt.Fprintf(os.Stderr, "[swu] CHILD_SA proposal (%d proposals, %d bytes): %x\n", len(childSA.Proposals), len(saBody), saBody)
		var sizes []int
		for _, p := range payloads {
			sizes = append(sizes, len(p.Body)+4)
		}
		fmt.Fprintf(os.Stderr, "[swu] IKE_AUTH payload sizes: %v (total %d)\n", sizes, sum(sizes))
	}
	return payloads, nil
}

func sum(a []int) int {
	s := 0
	for _, v := range a {
		s += v
	}
	return s
}

func authHeader(init InitResult, messageID uint32, fromInitiator bool) Header {
	flags := uint8(0)
	if fromInitiator {
		flags |= FlagInitiator
	} else {
		flags |= FlagResponse
	}
	return Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ExchangeIKE_AUTH,
		Flags:        flags,
		MessageID:    messageID,
	}
}

// computeInitiatorAUTH 计算 RFC 7296 §2.15 的 EAP 模式 AUTH payload：
//
//	AUTH = prf(prf(MSK, "Key Pad for IKEv2"), <msg octets>)
//	<msg octets> = IKE_SA_INIT 请求原始字节 ‖ Nr ‖ prf(SK_pi, IDi')
//
// IDi' 是 IDi payload 的编码体（含类型字节 + 3 保留字节）。
// 方法字节 = 2（SHARED_KEY_MESSAGE_INTEGRITY_CODE）。
func computeInitiatorAUTH(init InitResult, keys IKEKeys, id Identity, msk []byte) (Payload, error) {
	if len(msk) == 0 {
		return Payload{}, fmt.Errorf("%w: MSK is empty for AUTH computation", ErrInvalidAuthConfig)
	}
	if len(keys.SKPi) == 0 {
		return Payload{}, fmt.Errorf("%w: SK_pi is empty for AUTH computation", ErrInvalidAuthConfig)
	}
	if len(init.RequestBytes) == 0 || len(init.NonceR) == 0 {
		return Payload{}, fmt.Errorf("%w: SA_INIT transcript unavailable for AUTH computation", ErrInvalidAuthConfig)
	}
	idEncoded, err := id.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	prfHash := keys.Profile.PRF
	signedIDi, err := PRF(prfHash, keys.SKPi, idEncoded)
	if err != nil {
		return Payload{}, err
	}
	keyPad := []byte("Key Pad for IKEv2")
	authKey, err := PRF(prfHash, msk, keyPad)
	if err != nil {
		return Payload{}, err
	}
	msgOctets := make([]byte, 0, len(init.RequestBytes)+len(init.NonceR)+len(signedIDi))
	msgOctets = append(msgOctets, init.RequestBytes...)
	msgOctets = append(msgOctets, init.NonceR...)
	msgOctets = append(msgOctets, signedIDi...)
	authData, err := PRF(prfHash, authKey, msgOctets)
	if err != nil {
		return Payload{}, err
	}
	body := make([]byte, 4, 4+len(authData))
	body[0] = 2 // SHARED_KEY_MESSAGE_INTEGRITY_CODE
	body = append(body, authData...)
	return Payload{Type: PayloadAUTH, Body: body}, nil
}

func unprotectAuthResponse(raw []byte, init InitResult, keys IKEKeys, messageID uint32) (Message, []Payload, error) {
	msg, inner, err := UnprotectMessage(raw, keys, false)
	if err != nil {
		if os.Getenv("SWU_DEBUG_AUTH") != "" || os.Getenv("SWU_DEBUG_IKE") != "" {
			dumpLen := len(raw)
			if dumpLen > 96 {
				dumpLen = 96
			}
			fmt.Fprintf(os.Stderr, "[swu] unprotectAuthResponse failed (want msgid=%d, got %d bytes): %x\n", messageID, len(raw), raw[:dumpLen])
		}
		return Message{}, nil, err
	}
	h := msg.Header
	if h.InitiatorSPI != init.InitiatorSPI || h.ResponderSPI != init.ResponderSPI ||
		h.ExchangeType != ExchangeIKE_AUTH || h.MessageID != messageID || h.Flags&FlagResponse == 0 {
		if os.Getenv("SWU_DEBUG_AUTH") != "" || os.Getenv("SWU_DEBUG_IKE") != "" {
			fmt.Fprintf(os.Stderr, "[swu] IKE_AUTH response header mismatch: got SPIi=%x SPIr=%x exch=%d mid=%d flags=%#x, want SPIi=%x mid=%d\n",
				h.InitiatorSPI, h.ResponderSPI, h.ExchangeType, h.MessageID, h.Flags, init.InitiatorSPI, messageID)
		}
		return Message{}, nil, fmt.Errorf("%w: unexpected IKE_AUTH response header", ErrInvalidAuthResponse)
	}
	return msg, inner, nil
}

// authNotifyError 扫描 IKE_AUTH 响应内层 payload 里的错误 NOTIFY，
// 让 ePDG 的拒绝理由（AUTHENTICATION_FAILED / FAILED_CP_REQUIRED / 3GPP 9000 段 /
// Vodafone 16375 等）直接浮出，而不是笼统的 "did not complete EAP"。
func authNotifyError(inner []Payload) error {
	for _, p := range inner {
		if p.Type != PayloadNotify {
			continue
		}
		notify, err := ParseNotify(p.Body)
		if err != nil {
			return err
		}
		if err := NotifyErrorFor(notify); err != nil {
			fmt.Fprintf(os.Stderr, "[swu] IKE_AUTH rejected by notify %s (type=%d data=%x)\n",
				NotifyTypeName(notify.NotifyType), notify.NotifyType, notify.NotificationData)
			return err
		}
	}
	return nil
}

// authDeviceIdentityRequest 检查 ePDG 是否在响应里请求了 DEVICE_IDENTITY。
func authDeviceIdentityRequest(inner []Payload) (byte, bool) {
	for _, p := range inner {
		if p.Type != PayloadNotify {
			continue
		}
		notify, err := ParseNotify(p.Body)
		if err != nil || notify.NotifyType != NotifyDeviceIdentity {
			continue
		}
		reqType, _, err := ParseDeviceIdentityRequest(notify)
		if err == nil {
			return reqType, true
		}
		return DeviceIdentityTypeIMEI, true
	}
	return 0, false
}

// deviceIdentityForRequest 按请求类型选出 IMEI/IMEISV 值。
func deviceIdentityForRequest(imei, imeisv string, reqType byte) (DeviceIdentity, error) {
	imei = strings.TrimSpace(imei)
	imeisv = strings.TrimSpace(imeisv)
	if reqType == DeviceIdentityTypeIMEISV {
		if imeisv == "" && len(imei) == 15 {
			imeisv = imei[:14] + "0" + imei[14:] // IMEI + 2 位软件版本兜底
			if len(imeisv) != 16 {
				imeisv = imei + "00"
			}
		}
		if len(imeisv) != 16 {
			return DeviceIdentity{}, fmt.Errorf("%w: IMEISV unavailable for DEVICE_IDENTITY", ErrInvalidAuthConfig)
		}
		return DeviceIdentity{IdentityType: DeviceIdentityTypeIMEISV, Value: imeisv}, nil
	}
	if len(imei) != 15 {
		return DeviceIdentity{}, fmt.Errorf("%w: IMEI unavailable for DEVICE_IDENTITY", ErrInvalidAuthConfig)
	}
	return DeviceIdentity{IdentityType: DeviceIdentityTypeIMEI, Value: imei}, nil
}

// answerDeviceIdentityRequest 在 ePDG 请求 DEVICE_IDENTITY 且本地有可用
// IMEI/IMEISV 时构造应答 notify payload；未请求或不可用时返回 nil（不发送）。
func answerDeviceIdentityRequest(inner []Payload, identity *DeviceIdentity) *Payload {
	if identity == nil {
		return nil
	}
	reqType, requested := authDeviceIdentityRequest(inner)
	if !requested {
		return nil
	}
	dev, err := deviceIdentityForRequest(identity.Value, "", reqType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[swu] DEVICE_IDENTITY request with type %d cannot be answered: %v\n", reqType, err)
		return nil
	}
	payload, err := DeviceIdentityNotify(dev)
	if err != nil {
		return nil
	}
	return &payload
}

func firstEAPPacket(payloads []Payload) (eapaka.Packet, bool, error) {
	pkt, _, ok, err := firstEAPPacketWithRaw(payloads)
	return pkt, ok, err
}

func firstEAPPacketWithRaw(payloads []Payload) (eapaka.Packet, []byte, bool, error) {
	for _, p := range payloads {
		if p.Type != PayloadEAP {
			continue
		}
		pkt, err := eapaka.ParsePacket(p.Body)
		if err != nil {
			return eapaka.Packet{}, nil, false, err
		}
		return pkt, append([]byte(nil), p.Body...), true, nil
	}
	return eapaka.Packet{}, nil, false, nil
}

func authFinalResponse(auth AuthResult) ([]Payload, []byte) {
	if len(auth.IdentityResponseInner) > 0 || len(auth.IdentityResponseBytes) > 0 {
		return clonePayloads(auth.IdentityResponseInner), append([]byte(nil), auth.IdentityResponseBytes...)
	}
	return clonePayloads(auth.InitialResponseInner), append([]byte(nil), auth.InitialResponseBytes...)
}

func authNextEAP(auth AuthResult) *eapaka.Packet {
	if auth.EAPAfterIdentity != nil {
		return cloneEAPPacketPtr(auth.EAPAfterIdentity)
	}
	if auth.EAPRequest != nil {
		if auth.EAPRequest.Code == eapaka.CodeRequest && auth.EAPRequest.Subtype == eapaka.SubtypeIdentity && len(auth.IdentityResponseBytes) > 0 {
			return nil
		}
		return cloneEAPPacketPtr(auth.EAPRequest)
	}
	return nil
}

func parseChildSAIfPresent(init InitResult, inner []Payload, localSPI []byte, nextMessageID uint32) (ChildSAResult, bool, error) {
	if !hasPayload(inner, PayloadSA) {
		return ChildSAResult{}, false, nil
	}
	child, err := ParseChildSAResult(init, inner, localSPI)
	if err != nil {
		return ChildSAResult{}, false, err
	}
	child.NextMessageID = nextMessageID
	return child, true, nil
}

// completeIKEAuthWithAUTH 完成 RFC 7296 §2.16 EAP 流程的第四条消息：
// 发起方发送仅含 AUTH payload 的 IKE_AUTH 请求，ePDG 应回 CP/SA（CHILD_SA 协商结果）。
// AUTH = prf(prf(MSK, "Key Pad for IKEv2"), IKE_SA_INIT 请求 ‖ Nr ‖ prf(SK_PI, IDi'))。
func completeIKEAuthWithAUTH(ctx context.Context, cfg FullAuthConfig, out FullAuthResult, keys IKEKeys, localChildSPI []byte) (FullAuthResult, error) {
	authPayload, err := computeInitiatorAUTH(cfg.Init, keys, cfg.InitiatorID, out.EAPKeys.MSK)
	if err != nil {
		return FullAuthResult{}, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, nil)
	if err != nil {
		return FullAuthResult{}, err
	}
	authMessageID := out.NextMessageID
	_, authReqBytes, err := ProtectMessage(authHeader(cfg.Init, authMessageID, true), keys, true, []Payload{authPayload}, iv)
	if err != nil {
		return FullAuthResult{}, err
	}
	authRespBytes, err := cfg.Transport.ExchangeIKE(ctx, authReqBytes)
	if err != nil {
		return FullAuthResult{}, fmt.Errorf("IKE_AUTH final exchange failed: %w", err)
	}
	_, authInner, err := unprotectAuthResponse(authRespBytes, cfg.Init, keys, authMessageID)
	if err != nil {
		return FullAuthResult{}, err
	}
	dumpAuthPayloadTypes("IKE_AUTH final AUTH response", authInner)
	if notifyErr := authNotifyError(authInner); notifyErr != nil {
		return FullAuthResult{}, notifyErr
	}
	out.IKEAuthCompleted = true
	out.AuthRequestBytes = append([]byte(nil), authReqBytes...)
	out.AuthResponseBytes = append([]byte(nil), authRespBytes...)
	out.FinalResponseBytes = append([]byte(nil), authRespBytes...)
	out.FinalResponseInner = clonePayloads(authInner)
	out.NextMessageID = authMessageID + 1
	if child, ok, err := parseChildSAIfPresent(cfg.Init, authInner, localChildSPI, out.NextMessageID); err != nil {
		return FullAuthResult{}, err
	} else if ok {
		out.ChildSA = &child
		return out, nil
	}
	return out, fmt.Errorf("%w: EAP success without CHILD_SA", ErrInvalidAuthResponse)
}

func fullAuthLocalChildSPI(cfg FullAuthConfig) ([]byte, error) {
	if len(cfg.ChildSA.Proposals) > 0 && len(cfg.ChildSA.Proposals[0].SPI) > 0 {
		return append([]byte(nil), cfg.ChildSA.Proposals[0].SPI...), nil
	}
	if len(cfg.ChildSPI) > 0 {
		if len(cfg.ChildSPI) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidAuthConfig, len(cfg.ChildSPI))
		}
		return append([]byte(nil), cfg.ChildSPI...), nil
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, 4)
}

func authIV(random io.Reader, profile KeyMaterialProfile, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != profile.EncryptionBlockSize {
			return nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidAuthConfig, len(override), profile.EncryptionBlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	return RandomIV(random, profile)
}

func eapReauthIV(random io.Reader, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != aes.BlockSize {
			return nil, fmt.Errorf("%w: EAP reauthentication IV length %d != %d", ErrInvalidAuthConfig, len(override), aes.BlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, aes.BlockSize)
}

func firstConfiguration(value, fallback Configuration) Configuration {
	if value.Type != 0 || len(value.Attributes) > 0 {
		return value
	}
	return fallback
}

func clonePayloads(in []Payload) []Payload {
	out := make([]Payload, len(in))
	for i, p := range in {
		out[i] = Payload{
			Type:        p.Type,
			NextPayload: p.NextPayload,
			Critical:    p.Critical,
			Body:        append([]byte(nil), p.Body...),
		}
	}
	return out
}

func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, item := range in {
		out[i] = append([]byte(nil), item...)
	}
	return out
}

func cloneEAPPackets(in []eapaka.Packet) []eapaka.Packet {
	out := make([]eapaka.Packet, len(in))
	for i, packet := range in {
		out[i] = cloneEAPPacket(packet)
	}
	return out
}

func cloneEAPPacketPtr(packet *eapaka.Packet) *eapaka.Packet {
	if packet == nil {
		return nil
	}
	out := cloneEAPPacket(*packet)
	return &out
}

func cloneEAPPacket(packet eapaka.Packet) eapaka.Packet {
	out := packet
	out.Attributes = cloneEAPAttributes(packet.Attributes)
	out.Data = append([]byte(nil), packet.Data...)
	return out
}

func cloneEAPAttributes(in []eapaka.Attribute) []eapaka.Attribute {
	out := make([]eapaka.Attribute, len(in))
	for i, attr := range in {
		out[i] = eapaka.Attribute{
			Type: attr.Type,
			Data: append([]byte(nil), attr.Data...),
		}
	}
	return out
}

func hasPayload(payloads []Payload, payloadType uint8) bool {
	for _, p := range payloads {
		if p.Type == payloadType {
			return true
		}
	}
	return false
}

func payloadTypesHex(payloads []Payload) []byte {
	out := make([]byte, len(payloads))
	for i, p := range payloads {
		out[i] = p.Type
	}
	return out
}
