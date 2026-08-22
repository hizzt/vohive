package ikev2

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	ProtocolIKE uint8 = 1
	ProtocolAH  uint8 = 2
	ProtocolESP uint8 = 3
)

const (
	NotifyUnsupportedCriticalPayload  uint16 = 1
	NotifyInvalidIKESPI               uint16 = 4
	NotifyInvalidMajorVersion         uint16 = 5
	NotifyInvalidSyntax               uint16 = 7
	NotifyInvalidMessageID            uint16 = 9
	NotifyInvalidSPI                  uint16 = 11
	NotifyNoProposalChosen            uint16 = 14
	NotifyInvalidKEPayload            uint16 = 17
	NotifyAuthenticationFailed        uint16 = 24
	NotifySinglePairRequired          uint16 = 34
	NotifyNoAdditionalSAs             uint16 = 35
	NotifyInternalAddressFailure      uint16 = 36
	NotifyFailedCPRequired            uint16 = 37
	NotifyTSUnacceptable              uint16 = 38
	NotifyInvalidSelectors            uint16 = 39
	NotifyUnacceptableAddresses       uint16 = 40
	NotifyUnexpectedNATDetected       uint16 = 41
	NotifyNATDetectionSourceIP        uint16 = 16388
	NotifyNATDetectionDestinationIP   uint16 = 16389
	NotifyCookie                      uint16 = 16390
	NotifyRekeySA                     uint16 = 16393
	NotifyMOBIKESupported             uint16 = 16396
	NotifyAdditionalIPv4Address       uint16 = 16397
	NotifyAdditionalIPv6Address       uint16 = 16398
	NotifyNoAdditionalAddresses       uint16 = 16399
	NotifyUpdateSAAddresses           uint16 = 16400
	NotifyCookie2                     uint16 = 16401
	NotifyNoNATsAllowed               uint16 = 16402
	NotifyInitialContact              uint16 = 16384
	NotifyEAPOnlyAuthentication       uint16 = 16417
	NotifyIKEv2FragmentationSupported uint16 = 16430
	// 3GPP TS 24.302 §8.1.2 Table 8.1.2.3-1 私有状态通知（区间 40961-55911）
	NotifyDeviceIdentity   uint16 = 41101
	NotifyPCSCFRestoration uint16 = 41304
	// 3GPP TS 24.302 §7.2.2.2 附着拒绝（错误区间 9000-9099，其余 3GPP 私有错误散布在 <16384）
	Notify3GGPGenericAttachRejection uint16 = 9000
)

const (
	MaxIKECookieLength        = 64
	DHGroup2048BitMODP uint16 = 14
	DHGroup1024BitMODP uint16 = 2
	DHGroup256BitECP   uint16 = 19
	DHGroup384BitECP   uint16 = 20
	DHGroup521BitECP   uint16 = 21
	DHGroupCurve25519  uint16 = 31
)

var (
	ErrInvalidNotify                    = errors.New("invalid ikev2 notify payload")
	ErrIKEv2NotifyError                 = errors.New("ikev2 notify error")
	ErrNotifyUnsupportedCriticalPayload = errors.New("ikev2 unsupported critical payload notify")
	ErrNotifyInvalidIKESPI              = errors.New("ikev2 invalid ike spi notify")
	ErrNotifyInvalidMajorVersion        = errors.New("ikev2 invalid major version notify")
	ErrNotifyInvalidSyntax              = errors.New("ikev2 invalid syntax notify")
	ErrNotifyInvalidMessageID           = errors.New("ikev2 invalid message id notify")
	ErrNotifyInvalidSPI                 = errors.New("ikev2 invalid spi notify")
	ErrNotifyNoProposalChosen           = errors.New("ikev2 no proposal chosen notify")
	ErrNotifyInvalidKEPayload           = errors.New("ikev2 invalid ke payload notify")
	ErrNotifyAuthenticationFailed       = errors.New("ikev2 authentication failed notify")
	ErrNotifySinglePairRequired         = errors.New("ikev2 single pair required notify")
	ErrNotifyNoAdditionalSAs            = errors.New("ikev2 no additional sas notify")
	ErrNotifyInternalAddressFailure     = errors.New("ikev2 internal address failure notify")
	ErrNotifyFailedCPRequired           = errors.New("ikev2 failed cp required notify")
	ErrNotifyTSUnacceptable             = errors.New("ikev2 ts unacceptable notify")
	ErrNotifyInvalidSelectors           = errors.New("ikev2 invalid selectors notify")
	ErrNotifyUnacceptableAddresses      = errors.New("ikev2 unacceptable addresses notify")
	ErrNotifyUnexpectedNATDetected      = errors.New("ikev2 unexpected nat detected notify")
	ErrNotifyCookieChallenge            = errors.New("ikev2 cookie challenge notify")
	ErrInvalidDelete                    = errors.New("invalid ikev2 delete payload")
	ErrInvalidAddress                   = errors.New("invalid ikev2 address")
)

type Notify struct {
	ProtocolID       uint8
	NotifyType       uint16
	SPI              []byte
	NotificationData []byte
}

type InvalidSelectorReport struct {
	ProtocolID   uint8
	SPI          []byte
	PacketPrefix []byte
}

type NotifyError struct {
	Notify Notify
	Err    error
}

func (e *NotifyError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s", ErrIKEv2NotifyError, NotifyTypeName(e.Notify.NotifyType))
}

func (e *NotifyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *NotifyError) Is(target error) bool {
	return target == ErrIKEv2NotifyError || target == e.Err
}

// InvalidKEPayloadAlternativeGroup returns the responder's suggested DH group
// when this notification is INVALID_KE_PAYLOAD.
func (n Notify) InvalidKEPayloadAlternativeGroup() (uint16, bool, error) {
	if n.NotifyType != NotifyInvalidKEPayload {
		return 0, false, nil
	}
	if len(n.NotificationData) != 2 {
		return 0, true, fmt.Errorf("%w: INVALID_KE_PAYLOAD alternative group length %d", ErrInvalidNotify, len(n.NotificationData))
	}
	return binary.BigEndian.Uint16(n.NotificationData), true, nil
}

// InvalidKEPayloadAlternativeGroup returns the suggested DH group carried by an
// INVALID_KE_PAYLOAD notify error.
func (e *NotifyError) InvalidKEPayloadAlternativeGroup() (uint16, bool, error) {
	if e == nil {
		return 0, false, nil
	}
	return e.Notify.InvalidKEPayloadAlternativeGroup()
}

// InvalidKEPayloadAlternativeGroupFromError extracts an INVALID_KE_PAYLOAD
// suggested DH group from a wrapped NotifyError.
func InvalidKEPayloadAlternativeGroupFromError(err error) (uint16, bool, error) {
	if err == nil {
		return 0, false, nil
	}
	var notifyErr *NotifyError
	if !errors.As(err, &notifyErr) {
		return 0, false, nil
	}
	return notifyErr.InvalidKEPayloadAlternativeGroup()
}

func (n Notify) InvalidSelectorReport() (InvalidSelectorReport, bool, error) {
	if n.NotifyType != NotifyInvalidSelectors {
		return InvalidSelectorReport{}, false, nil
	}
	if n.ProtocolID != ProtocolAH && n.ProtocolID != ProtocolESP {
		return InvalidSelectorReport{}, true, fmt.Errorf("%w: INVALID_SELECTORS protocol %d", ErrInvalidNotify, n.ProtocolID)
	}
	if len(n.SPI) != 4 {
		return InvalidSelectorReport{}, true, fmt.Errorf("%w: INVALID_SELECTORS spi length %d", ErrInvalidNotify, len(n.SPI))
	}
	if len(n.NotificationData) == 0 {
		return InvalidSelectorReport{}, true, fmt.Errorf("%w: INVALID_SELECTORS missing packet prefix", ErrInvalidNotify)
	}
	return InvalidSelectorReport{
		ProtocolID:   n.ProtocolID,
		SPI:          append([]byte(nil), n.SPI...),
		PacketPrefix: append([]byte(nil), n.NotificationData...),
	}, true, nil
}

func (e *NotifyError) InvalidSelectorReport() (InvalidSelectorReport, bool, error) {
	if e == nil {
		return InvalidSelectorReport{}, false, nil
	}
	return e.Notify.InvalidSelectorReport()
}

func InvalidSelectorReportFromError(err error) (InvalidSelectorReport, bool, error) {
	if err == nil {
		return InvalidSelectorReport{}, false, nil
	}
	var notifyErr *NotifyError
	if !errors.As(err, &notifyErr) {
		return InvalidSelectorReport{}, false, nil
	}
	return notifyErr.InvalidSelectorReport()
}

func (n Notify) Cookie() ([]byte, bool, error) {
	if n.NotifyType != NotifyCookie {
		return nil, false, nil
	}
	if len(n.SPI) != 0 {
		return nil, true, fmt.Errorf("%w: COOKIE spi length %d", ErrInvalidNotify, len(n.SPI))
	}
	if len(n.NotificationData) == 0 || len(n.NotificationData) > MaxIKECookieLength {
		return nil, true, fmt.Errorf("%w: COOKIE length %d", ErrInvalidNotify, len(n.NotificationData))
	}
	return append([]byte(nil), n.NotificationData...), true, nil
}

func (n Notify) MarshalBinary() ([]byte, error) {
	if len(n.SPI) > 0xff {
		return nil, fmt.Errorf("%w: spi too long", ErrInvalidNotify)
	}
	out := make([]byte, 4, 4+len(n.SPI)+len(n.NotificationData))
	out[0] = n.ProtocolID
	out[1] = byte(len(n.SPI))
	binary.BigEndian.PutUint16(out[2:4], n.NotifyType)
	out = append(out, n.SPI...)
	out = append(out, n.NotificationData...)
	return out, nil
}

func ParseNotify(data []byte) (Notify, error) {
	if len(data) < 4 {
		return Notify{}, ErrInvalidNotify
	}
	spiSize := int(data[1])
	if len(data) < 4+spiSize {
		return Notify{}, ErrInvalidNotify
	}
	return Notify{
		ProtocolID:       data[0],
		NotifyType:       binary.BigEndian.Uint16(data[2:4]),
		SPI:              append([]byte(nil), data[4:4+spiSize]...),
		NotificationData: append([]byte(nil), data[4+spiSize:]...),
	}, nil
}

func NotifyPayload(n Notify) (Payload, error) {
	body, err := n.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

func NotifyErrorFor(n Notify) error {
	err := notifyErrorClass(n.NotifyType)
	if err == nil {
		return nil
	}
	return &NotifyError{Notify: cloneNotify(n), Err: err}
}

func FirstNotifyError(payloads []Payload) error {
	for _, payload := range payloads {
		if payload.Type != PayloadNotify {
			continue
		}
		notify, err := ParseNotify(payload.Body)
		if err != nil {
			return err
		}
		if err := NotifyErrorFor(notify); err != nil {
			return err
		}
	}
	return nil
}

func NotifyTypeName(notifyType uint16) string {
	switch notifyType {
	case NotifyUnsupportedCriticalPayload:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case NotifyInvalidIKESPI:
		return "INVALID_IKE_SPI"
	case NotifyInvalidMajorVersion:
		return "INVALID_MAJOR_VERSION"
	case NotifyInvalidSyntax:
		return "INVALID_SYNTAX"
	case NotifyInvalidMessageID:
		return "INVALID_MESSAGE_ID"
	case NotifyInvalidSPI:
		return "INVALID_SPI"
	case NotifyNoProposalChosen:
		return "NO_PROPOSAL_CHOSEN"
	case NotifyInvalidKEPayload:
		return "INVALID_KE_PAYLOAD"
	case NotifyAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case NotifySinglePairRequired:
		return "SINGLE_PAIR_REQUIRED"
	case NotifyNoAdditionalSAs:
		return "NO_ADDITIONAL_SAS"
	case NotifyInternalAddressFailure:
		return "INTERNAL_ADDRESS_FAILURE"
	case NotifyFailedCPRequired:
		return "FAILED_CP_REQUIRED"
	case NotifyTSUnacceptable:
		return "TS_UNACCEPTABLE"
	case NotifyInvalidSelectors:
		return "INVALID_SELECTORS"
	case NotifyUnacceptableAddresses:
		return "UNACCEPTABLE_ADDRESSES"
	case NotifyUnexpectedNATDetected:
		return "UNEXPECTED_NAT_DETECTED"
	case NotifyNATDetectionSourceIP:
		return "NAT_DETECTION_SOURCE_IP"
	case NotifyNATDetectionDestinationIP:
		return "NAT_DETECTION_DESTINATION_IP"
	case NotifyCookie:
		return "COOKIE"
	case NotifyRekeySA:
		return "REKEY_SA"
	case NotifyMOBIKESupported:
		return "MOBIKE_SUPPORTED"
	case NotifyAdditionalIPv4Address:
		return "ADDITIONAL_IP4_ADDRESS"
	case NotifyAdditionalIPv6Address:
		return "ADDITIONAL_IP6_ADDRESS"
	case NotifyNoAdditionalAddresses:
		return "NO_ADDITIONAL_ADDRESSES"
	case NotifyUpdateSAAddresses:
		return "UPDATE_SA_ADDRESSES"
	case NotifyCookie2:
		return "COOKIE2"
	case NotifyNoNATsAllowed:
		return "NO_NATS_ALLOWED"
	case NotifyInitialContact:
		return "INITIAL_CONTACT"
	case NotifyEAPOnlyAuthentication:
		return "EAP_ONLY_AUTHENTICATION"
	case NotifyIKEv2FragmentationSupported:
		return "IKEV2_FRAGMENTATION_SUPPORTED"
	case NotifyDeviceIdentity:
		return "DEVICE_IDENTITY"
	case NotifyPCSCFRestoration:
		return "P-CSCF_RESTORATION"
	default:
		if name, ok := notify3GGPName(notifyType); ok {
			return name
		}
		return fmt.Sprintf("notify %d", notifyType)
	}
}

// notify3GGPName 覆盖 TS 24.302 §7.2.2.2/§8.1.2 的常用 3GPP 通知编号。
func notify3GGPName(notifyType uint16) (string, bool) {
	names := map[uint16]string{
		9000:  "3GPP_GENERIC_ATTACH_REJECTION",
		9001:  "3GPP_ILLEGAL_UE",
		9002:  "3GPP_ILLEGAL_ME",
		9003:  "3GPP_3GPP_AUTH_PROTOCOL_ERROR",
		9004:  "3GPP_SERVICE_NOT_ALLOWED",
		9005:  "3GPP_SERVICE_SUBSCRIPTION_EXPIRED",
		9006:  "3GPP_PLMN_NOT_ALLOWED",
		10500: "3GPP_NETWORK_FAILURE",
		11001: "3GPP_NO_APN_SUBSCRIPTION",
		11011: "3GPP_PDN_LIMIT_EXCEEDED",
		41101: "DEVICE_IDENTITY",
		41304: "P-CSCF_RESTORATION",
		16375: "3GPP_PRIVATE_16375 (Vodafone UK IPv4-only IMS hint)",
	}
	if name, ok := names[notifyType]; ok {
		return name, true
	}
	if notifyType >= 9000 && notifyType <= 9099 {
		return fmt.Sprintf("3GPP_ATTACH_REJECT_%d", notifyType), true
	}
	if notifyType >= 16375 && notifyType < 16384 {
		return fmt.Sprintf("3GPP_PRIVATE_%d", notifyType), true
	}
	return "", false
}

func notifyErrorClass(notifyType uint16) error {
	switch notifyType {
	case NotifyCookie:
		// COOKIE 不是错误，但必须包成 NotifyError 抛出，
		// CookieChallengeFromError 才能从错误链里解出 cookie 供上层重发。
		return ErrNotifyCookieChallenge
	case NotifyUnsupportedCriticalPayload:
		return ErrNotifyUnsupportedCriticalPayload
	case NotifyInvalidIKESPI:
		return ErrNotifyInvalidIKESPI
	case NotifyInvalidMajorVersion:
		return ErrNotifyInvalidMajorVersion
	case NotifyInvalidSyntax:
		return ErrNotifyInvalidSyntax
	case NotifyInvalidMessageID:
		return ErrNotifyInvalidMessageID
	case NotifyInvalidSPI:
		return ErrNotifyInvalidSPI
	case NotifyNoProposalChosen:
		return ErrNotifyNoProposalChosen
	case NotifyInvalidKEPayload:
		return ErrNotifyInvalidKEPayload
	case NotifyAuthenticationFailed:
		return ErrNotifyAuthenticationFailed
	case NotifySinglePairRequired:
		return ErrNotifySinglePairRequired
	case NotifyNoAdditionalSAs:
		return ErrNotifyNoAdditionalSAs
	case NotifyInternalAddressFailure:
		return ErrNotifyInternalAddressFailure
	case NotifyFailedCPRequired:
		return ErrNotifyFailedCPRequired
	case NotifyTSUnacceptable:
		return ErrNotifyTSUnacceptable
	case NotifyInvalidSelectors:
		return ErrNotifyInvalidSelectors
	case NotifyUnacceptableAddresses:
		return ErrNotifyUnacceptableAddresses
	case NotifyUnexpectedNATDetected:
		return ErrNotifyUnexpectedNATDetected
	default:
		if notifyType < 16384 {
			// TS 24.302 的 3GPP 错误（9000 段）与运营商私有错误（如 Vodafone 16375）
			// 都落在错误区间，统一归类为通知错误，让 IKE_AUTH 阶段能看到拒绝理由。
			return ErrIKEv2NotifyError
		}
		return nil
	}
}

// Is3GGPAttachRejectNotify 判断是否 TS 24.302 §7.2.2.2 的附着拒绝通知。
func Is3GGPAttachRejectNotify(notifyType uint16) bool {
	if notifyType >= 9000 && notifyType <= 9099 {
		return true
	}
	switch notifyType {
	case 10500, 11001, 11011, 16375:
		return true
	}
	return false
}

type Delete struct {
	ProtocolID uint8
	SPIs       [][]byte
}

func (d Delete) MarshalBinary() ([]byte, error) {
	if err := validateDelete(d); err != nil {
		return nil, err
	}
	spiSize := 0
	if len(d.SPIs) > 0 {
		spiSize = len(d.SPIs[0])
	}
	out := make([]byte, 4, 4+spiSize*len(d.SPIs))
	out[0] = d.ProtocolID
	out[1] = byte(spiSize)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(d.SPIs)))
	for _, spi := range d.SPIs {
		out = append(out, spi...)
	}
	return out, nil
}

func ParseDelete(data []byte) (Delete, error) {
	if len(data) < 4 {
		return Delete{}, ErrInvalidDelete
	}
	spiSize := int(data[1])
	spiCount := int(binary.BigEndian.Uint16(data[2:4]))
	want := 4 + spiSize*spiCount
	if want != len(data) {
		return Delete{}, fmt.Errorf("%w: length %d != %d", ErrInvalidDelete, len(data), want)
	}
	d := Delete{
		ProtocolID: data[0],
		SPIs:       make([][]byte, 0, spiCount),
	}
	rest := data[4:]
	for i := 0; i < spiCount; i++ {
		d.SPIs = append(d.SPIs, append([]byte(nil), rest[:spiSize]...))
		rest = rest[spiSize:]
	}
	if err := validateDelete(d); err != nil {
		return Delete{}, err
	}
	return d, nil
}

func DeletePayload(d Delete) (Payload, error) {
	body, err := d.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadDelete, Body: body}, nil
}

func IKEDeletePayload() Payload {
	return Payload{Type: PayloadDelete, Body: []byte{ProtocolIKE, 0, 0, 0}}
}

func ESPDeletePayload(spis ...[]byte) (Payload, error) {
	copied := make([][]byte, 0, len(spis))
	for _, spi := range spis {
		copied = append(copied, append([]byte(nil), spi...))
	}
	return DeletePayload(Delete{ProtocolID: ProtocolESP, SPIs: copied})
}

func ChildSADeletePayload(child ChildSAResult) (Payload, error) {
	if len(child.LocalSPI) == 0 {
		return Payload{}, fmt.Errorf("%w: missing local child SPI", ErrInvalidDelete)
	}
	return ESPDeletePayload(child.LocalSPI)
}

func TeardownDeletePayloads(child ChildSAResult, includeIKESA bool) ([]Payload, error) {
	var out []Payload
	if len(child.LocalSPI) > 0 {
		payload, err := ChildSADeletePayload(child)
		if err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	if includeIKESA {
		out = append(out, IKEDeletePayload())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no SAs selected", ErrInvalidDelete)
	}
	return out, nil
}

func validateDelete(d Delete) error {
	switch d.ProtocolID {
	case ProtocolIKE:
		if len(d.SPIs) != 0 {
			return fmt.Errorf("%w: IKE delete must not include SPIs", ErrInvalidDelete)
		}
		return nil
	case ProtocolAH, ProtocolESP:
	default:
		return fmt.Errorf("%w: protocol %d", ErrInvalidDelete, d.ProtocolID)
	}
	if len(d.SPIs) == 0 {
		return fmt.Errorf("%w: no SPIs", ErrInvalidDelete)
	}
	if len(d.SPIs) > 0xffff {
		return fmt.Errorf("%w: too many SPIs", ErrInvalidDelete)
	}
	spiSize := len(d.SPIs[0])
	if spiSize != 4 {
		return fmt.Errorf("%w: SPI size %d", ErrInvalidDelete, spiSize)
	}
	for _, spi := range d.SPIs {
		if len(spi) != spiSize {
			return fmt.Errorf("%w: mixed SPI sizes", ErrInvalidDelete)
		}
	}
	return nil
}

type KeyExchange struct {
	DHGroup uint16
	KeyData []byte
}

func (k KeyExchange) MarshalBinary() []byte {
	out := make([]byte, 4, 4+len(k.KeyData))
	binary.BigEndian.PutUint16(out[0:2], k.DHGroup)
	out = append(out, k.KeyData...)
	return out
}

func ParseKeyExchange(data []byte) (KeyExchange, error) {
	if len(data) < 4 {
		return KeyExchange{}, ErrShortPayload
	}
	return KeyExchange{
		DHGroup: binary.BigEndian.Uint16(data[0:2]),
		KeyData: append([]byte(nil), data[4:]...),
	}, nil
}

func KeyExchangePayload(group uint16, keyData []byte) Payload {
	return Payload{Type: PayloadKE, Body: (KeyExchange{DHGroup: group, KeyData: append([]byte(nil), keyData...)}).MarshalBinary()}
}

func NoncePayload(nonce []byte) Payload {
	return Payload{Type: PayloadNonce, Body: append([]byte(nil), nonce...)}
}

func EAPPayload(packet []byte) Payload {
	return Payload{Type: PayloadEAP, Body: append([]byte(nil), packet...)}
}

func NATDetectionHash(spiI, spiR uint64, ip net.IP, port uint16) ([]byte, error) {
	normalized := ip.To4()
	if normalized == nil {
		normalized = ip.To16()
	}
	if normalized == nil {
		return nil, ErrInvalidAddress
	}
	data := make([]byte, 0, 16+len(normalized)+2)
	data = appendUint64(data, spiI)
	data = appendUint64(data, spiR)
	data = append(data, normalized...)
	data = append(data, byte(port>>8), byte(port))
	sum := sha1.Sum(data)
	return sum[:], nil
}

func NATDetectionNotify(notifyType uint16, spiI, spiR uint64, ip net.IP, port uint16) (Payload, error) {
	if notifyType != NotifyNATDetectionSourceIP && notifyType != NotifyNATDetectionDestinationIP {
		return Payload{}, fmt.Errorf("%w: unsupported NAT detection type %d", ErrInvalidNotify, notifyType)
	}
	hash, err := NATDetectionHash(spiI, spiR, ip, port)
	if err != nil {
		return Payload{}, err
	}
	return NotifyPayload(Notify{
		ProtocolID:       ProtocolIKE,
		NotifyType:       notifyType,
		NotificationData: hash,
	})
}

func MOBIKESupportedNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyMOBIKESupported}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func UpdateSAAddressesNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyUpdateSAAddresses}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func NoAdditionalAddressesNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyNoAdditionalAddresses}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func AdditionalIPAddressNotify(ip net.IP) (Payload, error) {
	if v4 := ip.To4(); v4 != nil {
		return NotifyWithZeroSPI(NotifyAdditionalIPv4Address, v4), nil
	}
	if v6 := ip.To16(); v6 != nil {
		return NotifyWithZeroSPI(NotifyAdditionalIPv6Address, v6), nil
	}
	return Payload{}, ErrInvalidAddress
}

func Cookie2Notify(cookie []byte) (Payload, error) {
	if len(cookie) < 8 || len(cookie) > 64 {
		return Payload{}, fmt.Errorf("%w: COOKIE2 length %d", ErrInvalidNotify, len(cookie))
	}
	body, err := (Notify{NotifyType: NotifyCookie2, NotificationData: append([]byte(nil), cookie...)}).MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

func CookieNotify(cookie []byte) (Payload, error) {
	notify := Notify{NotifyType: NotifyCookie, NotificationData: append([]byte(nil), cookie...)}
	if _, _, err := notify.Cookie(); err != nil {
		return Payload{}, err
	}
	body, err := notify.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

func NotifyWithZeroSPI(notifyType uint16, data []byte) Payload {
	body, _ := (Notify{NotifyType: notifyType, NotificationData: append([]byte(nil), data...)}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func FirstNotify(payloads []Payload, notifyType uint16) (Notify, bool, error) {
	for _, payload := range payloads {
		if payload.Type != PayloadNotify {
			continue
		}
		notify, err := ParseNotify(payload.Body)
		if err != nil {
			return Notify{}, false, err
		}
		if notify.NotifyType == notifyType {
			return notify, true, nil
		}
	}
	return Notify{}, false, nil
}

func cloneNotify(n Notify) Notify {
	return Notify{
		ProtocolID:       n.ProtocolID,
		NotifyType:       n.NotifyType,
		SPI:              append([]byte(nil), n.SPI...),
		NotificationData: append([]byte(nil), n.NotificationData...),
	}
}

func appendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

// --- 3GPP TS 24.302 IKEv2 通知 ---

// DeviceIdentity 是 TS 24.302 §8.2.5.2 定义的设备身份（IMEI/IMEISV）。
type DeviceIdentity struct {
	IdentityType byte   // 0x01 = IMEI, 0x02 = IMEISV
	Value        string // 十进制数字字符串
}

const (
	DeviceIdentityTypeIMEI   byte = 0x01
	DeviceIdentityTypeIMEISV byte = 0x02
)

// BCD 编码：低半字节=偶数位数字，高半字节=奇数位数字，不足补 0xF。
func encodeDeviceIdentityBCD(value string) []byte {
	out := make([]byte, 0, (len(value)+1)/2)
	for i := 0; i < len(value); i += 2 {
		lo := byte(0x0F)
		if i < len(value) {
			lo = value[i] - '0'
		}
		hi := byte(0x0F)
		if i+1 < len(value) {
			hi = value[i+1] - '0'
		}
		out = append(out, hi<<4|lo)
	}
	return out
}

func decodeDeviceIdentityBCD(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		lo := b & 0x0F
		hi := b >> 4
		if lo < 10 {
			sb.WriteByte('0' + lo)
		}
		if hi < 10 {
			sb.WriteByte('0' + hi)
		}
	}
	return sb.String()
}

// MarshalBinary 编码为 ePDG 期望的通知数据：[2 字节总长度][1 字节类型][BCD]。
func (d DeviceIdentity) MarshalBinary() ([]byte, error) {
	value := strings.TrimSpace(d.Value)
	if value == "" {
		return nil, fmt.Errorf("%w: empty device identity value", ErrInvalidNotify)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return nil, fmt.Errorf("%w: non-digit device identity %q", ErrInvalidNotify, value)
		}
	}
	switch d.IdentityType {
	case DeviceIdentityTypeIMEI:
		if len(value) != 15 {
			return nil, fmt.Errorf("%w: IMEI length %d", ErrInvalidNotify, len(value))
		}
	case DeviceIdentityTypeIMEISV:
		if len(value) != 16 {
			return nil, fmt.Errorf("%w: IMEISV length %d", ErrInvalidNotify, len(value))
		}
	default:
		return nil, fmt.Errorf("%w: unknown device identity type %d", ErrInvalidNotify, d.IdentityType)
	}
	bcd := encodeDeviceIdentityBCD(value)
	out := make([]byte, 0, 3+len(bcd))
	out = append(out, byte((3+len(bcd))>>8), byte(3+len(bcd)))
	out = append(out, d.IdentityType)
	out = append(out, bcd...)
	return out, nil
}

// ParseDeviceIdentity 从 ePDG 的 DEVICE_IDENTITY 请求通知数据解析。
// 请求侧数据：[1 字节请求类型][1 字节保留]（类型即期望的 Identity-Type）。
func ParseDeviceIdentityRequest(n Notify) (byte, bool, error) {
	if n.NotifyType != NotifyDeviceIdentity {
		return 0, false, nil
	}
	if len(n.NotificationData) < 1 {
		return 0, true, fmt.Errorf("%w: DEVICE_IDENTITY request data too short", ErrInvalidNotify)
	}
	return n.NotificationData[0], true, nil
}

// DeviceIdentityNotify 构造 DEVICE_IDENTITY 应答通知。
func DeviceIdentityNotify(d DeviceIdentity) (Payload, error) {
	data, err := d.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return NotifyPayload(Notify{
		ProtocolID:       ProtocolIKE,
		NotifyType:       NotifyDeviceIdentity,
		NotificationData: data,
	})
}

func InitialContactNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyInitialContact}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func EAPOnlyAuthenticationNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyEAPOnlyAuthentication}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

// IKEv2FragmentationSupportedNotify 是 RFC 7383 的 USE_FRAG（P1 用，先占位常量化）。
func IKEv2FragmentationSupportedNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyIKEv2FragmentationSupported}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}
