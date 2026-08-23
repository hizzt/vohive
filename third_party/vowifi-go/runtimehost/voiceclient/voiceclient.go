package voiceclient

import (
	"net"
	cryptorand "crypto/rand"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

var ErrInvalidChallenge = errors.New("invalid SIP digest challenge")
var ErrInvalidAuthenticationInfo = errors.New("invalid SIP digest authentication-info")
var ErrRegistrationRejected = errors.New("IMS registration rejected")

type IMSProfile struct {
	IMPI      string
	IMPU      string
	Domain    string
	LocalIP   string
	UserAgent string
	// IMSI 用于派生 EAP root NAI（0<IMSI>@nai.epc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org）。
	// 1239t/v155 默认 REGISTER 的 digest username 用的是 EAP NAI 而非裸 IMSI/IMPI。
	IMSI string
	MCC  string
	MNC  string
	// IMEI 用于派生 GSMA sip.instance（urn:gsma:imei:TAC-SNR-SV）。v155 逆串
	// 存在 "<urn:gsma:imei:%s-%s-%s>" 模板 + sip_instance_imei 模板开关：
	// 运营商 S-CSCF 按 IMEI instance 做 UE 合法性校验（非 UUID instance）。
	IMEI string
}

type DigestChallenge struct {
	Scheme    string
	Realm     string
	Nonce     string
	Algorithm string
	QOP       string
	Opaque    string
	Stale     bool
}

type DigestAuthInput struct {
	Method   string
	URI      string
	Username string
	Password string
	CNonce   string
	NC       int
	Body     []byte
	AUTS     []byte
	// AKA CK/IK：AKA 成功时由 digestAuthInputForChallenge 填充，供
	// OnSecurityKeys 派生 IMS ipsec-3gpp ESP 密钥（TS 33.203）。
	AKACK []byte
	AKAIK []byte
}

type DigestAuthState struct {
	challenge  DigestChallenge
	input      DigestAuthInput
	headerName string
	nextNC     int
	lastHeader string
}

type RegistrationBinding struct {
	ContactURI        string
	PublicIdentity    string
	AssociatedURIs    []string
	ServiceRoutes     []string
	Paths             []string
	SecurityClient    string
	SecurityServer    []string
	SecurityVerify    []string
	SecurityAgreement SecurityAgreement
	Expires           int
	RegistrarContact  string
}

type RegisterMessage struct {
	URI     string
	Headers map[string]string
	Body    []byte
}

type RegisterResponse struct {
	StatusCode int
	Reason     string
	Headers    map[string][]string
	Body       []byte
}

type SIPRegisterTransport interface {
	RoundTripRegister(context.Context, RegisterMessage) (RegisterResponse, error)
}

type RegisterSession struct {
	Transport      SIPRegisterTransport
	AKAProvider    sim.AKAProvider
	Profile        IMSProfile
	RegistrarURI   string
	ContactURI     string
	RouteURI       string
	// InitialAuthorization 首个 REGISTER 的 Authorization 头模式：
	// ""（无）/ "aka_empty"（Digest 占位 nonce="" response="" AKAv1-MD5）。
	// 参考实现（imscore）default 变体以 aka_empty 打头——部分 P-CSCF 只回
	// 带占位 Authorization 的首个 REGISTER。
	InitialAuthorization string
	CallID               string
	CNonce               string
	Expires              int
	SecurityClient       SecurityAgreement
	SecurityRandom       io.Reader
	// OnSecurityKeys 在每次 AKA 成功（拿到 CK/IK 且未处同步失败）后、发送受保护
	// REGISTER 前同步调用——上层在此 Install IMS ipsec-3gpp ESP transform
	// （Security-Client/Server 机制对 + CK/IK 即 TS 33.203 全部协商要素）。
	OnSecurityKeys func(client SecurityAgreement, server SecurityAgreement, ck []byte, ik []byte)
}

type RegisterResult struct {
	Registered     bool
	StatusCode     int
	Reason         string
	Attempts       int
	Challenge      DigestChallenge
	Binding        RegistrationBinding
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
	NextCSeq       int
}

type DeregisterRequest struct {
	Binding        RegistrationBinding
	CallID         string
	CSeq           int
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
}

type DeregisterResult struct {
	Deregistered bool
	StatusCode   int
	Reason       string
	Attempts     int
}

type RefreshRequest struct {
	Binding        RegistrationBinding
	CallID         string
	CSeq           int
	Expires        int
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
}

type RefreshResult struct {
	Refreshed      bool
	StatusCode     int
	Reason         string
	Attempts       int
	Binding        RegistrationBinding
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
	NextCSeq       int
}

func ParseWWWAuthenticate(header string) (DigestChallenge, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	ch := DigestChallenge{Scheme: strings.TrimSpace(scheme)}
	if !strings.EqualFold(ch.Scheme, "Digest") {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	for _, part := range splitAuthParams(rest) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = unquote(strings.TrimSpace(value))
		switch key {
		case "realm":
			ch.Realm = value
		case "nonce":
			ch.Nonce = value
		case "algorithm":
			ch.Algorithm = value
		case "qop":
			ch.QOP = firstQOP(value)
		case "opaque":
			ch.Opaque = value
		case "stale":
			ch.Stale = strings.EqualFold(value, "true")
		}
	}
	if ch.Realm == "" || ch.Nonce == "" {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	if ch.Algorithm == "" {
		ch.Algorithm = "MD5"
	}
	return ch, nil
}

func ExtractAKAChallengeNonce(nonce string) (rand16, autn16 []byte, ok bool) {
	raw, ok := decodeNonceBytes(nonce)
	if !ok || len(raw) < 32 {
		return nil, nil, false
	}
	return append([]byte(nil), raw[:16]...), append([]byte(nil), raw[16:32]...), true
}

func BuildDigestAuthorization(ch DigestChallenge, in DigestAuthInput) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	uri := strings.TrimSpace(in.URI)
	username := strings.TrimSpace(in.Username)
	if method == "" || uri == "" || username == "" || ch.Realm == "" || ch.Nonce == "" {
		return "", ErrInvalidChallenge
	}
	algorithm := strings.TrimSpace(ch.Algorithm)
	if algorithm == "" {
		algorithm = "MD5"
	}
	if !strings.EqualFold(algorithm, "MD5") && !strings.EqualFold(algorithm, "AKAv1-MD5") && !strings.EqualFold(algorithm, "AKAv2-MD5") {
		return "", fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}

	password := in.Password
	if len(in.AUTS) > 0 {
		password = ""
	}
	ha1 := md5Hex(username + ":" + ch.Realm + ":" + password)
	qop := firstQOP(ch.QOP)
	ha2 := ""
	switch qop {
	case "":
		ha2 = md5Hex(method + ":" + uri)
	case "auth":
		ha2 = md5Hex(method + ":" + uri)
	case "auth-int":
		ha2 = md5Hex(method + ":" + uri + ":" + md5HexBytes(in.Body))
	default:
		return "", fmt.Errorf("unsupported digest qop %q", qop)
	}
	response := ""
	nc := in.NC
	if nc <= 0 {
		nc = 1
	}
	ncText := fmt.Sprintf("%08x", nc)
	cnonce := strings.TrimSpace(in.CNonce)
	if qop != "" {
		if cnonce == "" {
			return "", errors.New("cnonce required when qop is present")
		}
		response = md5Hex(ha1 + ":" + ch.Nonce + ":" + ncText + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = md5Hex(ha1 + ":" + ch.Nonce + ":" + ha2)
	}

	parts := []string{
		`Digest username="` + quote(username) + `"`,
		`realm="` + quote(ch.Realm) + `"`,
		`nonce="` + quote(ch.Nonce) + `"`,
		`uri="` + quote(uri) + `"`,
		`response="` + response + `"`,
		`algorithm=` + algorithm,
	}
	if ch.Opaque != "" {
		parts = append(parts, `opaque="`+quote(ch.Opaque)+`"`)
	}
	if qop != "" {
		parts = append(parts, `qop=`+qop, `nc=`+ncText, `cnonce="`+quote(cnonce)+`"`)
	}
	if len(in.AUTS) > 0 {
		parts = append(parts, `auts="`+base64.StdEncoding.EncodeToString(in.AUTS)+`"`)
	}
	return strings.Join(parts, ", "), nil
}

func (s DigestAuthState) Usable() bool {
	return strings.TrimSpace(s.challenge.Realm) != "" &&
		strings.TrimSpace(s.challenge.Nonce) != "" &&
		strings.TrimSpace(s.input.Username) != "" &&
		len(s.input.AUTS) == 0
}

func (s DigestAuthState) Build(method, uri string) (string, DigestAuthState, error) {
	if !s.Usable() {
		return "", s, ErrInvalidChallenge
	}
	next := s.clone()
	input := next.input
	if strings.TrimSpace(method) != "" {
		input.Method = strings.ToUpper(strings.TrimSpace(method))
	}
	if strings.TrimSpace(uri) != "" {
		input.URI = strings.TrimSpace(uri)
	}
	nc := next.nextNC
	if nc <= 0 {
		nc = input.NC
	}
	if nc <= 0 {
		nc = 1
	}
	input.NC = nc
	authz, err := BuildDigestAuthorization(next.challenge, input)
	if err != nil {
		return "", s, err
	}
	next.input = input
	next.input.AUTS = append([]byte(nil), input.AUTS...)
	next.nextNC = nc + 1
	next.lastHeader = authz
	return authz, next, nil
}

func (s DigestAuthState) clone() DigestAuthState {
	s.input = cloneDigestAuthInput(s.input)
	return s
}

func newDigestAuthState(headerName string, ch DigestChallenge, input DigestAuthInput, authz string) DigestAuthState {
	nextNC := input.NC + 1
	if nextNC <= 1 {
		nextNC = 2
	}
	return DigestAuthState{
		challenge:  ch,
		input:      cloneDigestAuthInput(input),
		headerName: firstNonEmpty(headerName, "Authorization"),
		nextNC:     nextNC,
		lastHeader: strings.TrimSpace(authz),
	}
}

func cloneDigestAuthInput(input DigestAuthInput) DigestAuthInput {
	input.Body = append([]byte(nil), input.Body...)
	input.AUTS = append([]byte(nil), input.AUTS...)
	return input
}

func BuildAKADigestPassword(algorithm string, aka sim.AKAResult) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "AKAV1-MD5":
		if len(aka.RES) == 0 {
			return "", errors.New("AKA RES is empty")
		}
		return string(aka.RES), nil
	case "AKAV2-MD5":
		if len(aka.RES) == 0 || len(aka.CK) == 0 || len(aka.IK) == 0 {
			return "", errors.New("AKA RES/CK/IK required for AKAv2-MD5")
		}
		key := make([]byte, 0, len(aka.RES)+len(aka.IK)+len(aka.CK))
		key = append(key, aka.RES...)
		key = append(key, aka.IK...)
		key = append(key, aka.CK...)
		mac := hmac.New(md5.New, key)
		_, _ = mac.Write([]byte("http-digest-akav2-password"))
		return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
	default:
		return "", fmt.Errorf("unsupported AKA digest algorithm %q", algorithm)
	}
}

func BuildRegisterHeaders(profile IMSProfile, contactURI, callID, cseq string) map[string]string {
	domain := strings.TrimSpace(profile.Domain)
	impu := strings.TrimSpace(profile.IMPU)
	if impu == "" && domain != "" {
		impu = "sip:" + strings.TrimSpace(profile.IMPI) + "@" + domain
	}
	headers := map[string]string{
		"To":                   "<" + impu + ">",
		"From":                 "<" + impu + ">;tag=" + GenerateSIPTag(),
		"Contact":              buildRegisterContactHeader(profile, contactURI),
		"Call-ID":              strings.TrimSpace(callID),
		"CSeq":                 strings.TrimSpace(cseq) + " REGISTER",
		"Max-Forwards":         "70",
		"User-Agent":           firstNonEmpty(profile.UserAgent, "SimAdmin VoWiFi"),
		"Allow":                "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS",
		"Supported":            "path,sec-agree,gruu",
		// Vodafone UK P-CSCF 对缺 Require: sec-agree 的 REGISTER 回 421 Extension Required
		// 并在响应里明示 Require: sec-agree（0823r 实测）——必须带。
		"Require":              "sec-agree",
		"Proxy-Require":        "sec-agree",
		"P-Preferred-Identity": "<" + impu + ">",
		// VoCat（Vodafone UK 生产验证）PANI 形态："IEEE-802.11;country=GB"——
		// 由 SIM MCC 组合 country；v155 逆串另有 "IEEE-802.11; i-wlan-node-id=000000000000"
		// 变体。country 码是 Vodafone P-CSCF 鉴权判定的关键字段。
		"P-Access-Network-Info": buildPANIHeader(profile),
		"P-Visited-Network-ID":  "\"" + domain + "\"",
		"Security-Client":       BuildSecurityClientMultiMechanismHeader(DefaultSecurityClientAgreement(nil)),
	}
	if domain != "" {
		// 1239t IncludeAcceptContact 是两条 Accept-Contact（smsip + mmtel ICSI）；
		// 本结构 map 单值，按 RFC 3261 逗号合并语义等价。
		headers["Accept-Contact"] = "*;+g.3gpp.smsip, *;+g.3gpp.icsi-ref=\"" + imsMmtelICSIRefURNEscaped + "\""
	}
	return headers
}

func (s RegisterSession) Register(ctx context.Context) (RegisterResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Transport == nil {
		return RegisterResult{}, errors.New("nil SIP register transport")
	}
	registrarURI := strings.TrimSpace(s.RegistrarURI)
	contactURI := strings.TrimSpace(s.ContactURI)
	if registrarURI == "" || contactURI == "" {
		return RegisterResult{}, errors.New("registrar URI and contact URI are required")
	}
	callID := firstNonEmpty(s.CallID, "vowifi-go-register")
	expires := s.Expires
	if expires <= 0 {
		expires = 3600
	}
	securityClient := s.securityClientAgreement()
	securityClientHeader := BuildSecurityClientHeader(securityClient)

	attempts := 0
	cseq := 1
	sendRegister := func(cseq int, authHeaderName, authz string, challengeHeaders map[string][]string) (RegisterResponse, error) {
		msg := RegisterMessage{
			URI:     registrarURI,
			Headers: BuildRegisterHeaders(s.Profile, contactURI, callID, strconv.Itoa(cseq)),
		}
		msg.Headers["Expires"] = strconv.Itoa(expires)
		msg.Headers["Security-Client"] = securityClientHeader
		// 服务端 401 挑战携带的 Security-Server 生效后，Route 按 P-CSCF 要求
		// 指向其保护端口（port-s）；首轮无挑战信息时用初始 RouteURI（P-CSCF:5060）。
		if route := routeHeaderForChallenge(s.RouteURI, challengeHeaders); route != "" {
			msg.Headers["Route"] = route
		}
		if strings.TrimSpace(authHeaderName) != "" && strings.TrimSpace(authz) != "" {
			msg.Headers[authHeaderName] = authz
		} else if attempts == 0 && strings.EqualFold(strings.TrimSpace(s.InitialAuthorization), "aka_empty") {
			// aka_empty 变体（imscore 先例）：带占位 Digest 的首 REGISTER。
			msg.Headers["Authorization"] = BuildInitialAKAEmptyAuthorization(s.Profile, registrarURI)
		}
		if securityVerify := securityVerifyFromChallenge(challengeHeaders); securityVerify != "" {
			msg.Headers["Security-Verify"] = securityVerify
		}
		attempts++
		return s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	}
	retryMinExpires := func(resp RegisterResponse, authHeaderName, authz string, challengeHeaders map[string][]string, authInput *DigestAuthInput, ch DigestChallenge) (RegisterResponse, string, bool, error) {
		if resp.StatusCode != 423 {
			return resp, authz, false, nil
		}
		minExpires := minExpiresHeader(resp.Headers)
		if minExpires <= expires {
			return resp, authz, false, nil
		}
		expires = minExpires
		nextAuthz := authz
		if authInput != nil {
			authInput.NC++
			var err error
			nextAuthz, err = BuildDigestAuthorization(ch, *authInput)
			if err != nil {
				return resp, authz, true, err
			}
		}
		cseq++
		nextResp, err := sendRegister(cseq, authHeaderName, nextAuthz, challengeHeaders)
		return nextResp, nextAuthz, true, err
	}

	resp, err := sendRegister(cseq, "", "", nil)
	if err != nil {
		return RegisterResult{}, err
	}
	resp, _, _, err = retryMinExpires(resp, "", "", nil, nil, DigestChallenge{})
	if err != nil {
		return RegisterResult{Attempts: attempts}, err
	}
	if isSIPSuccess(resp.StatusCode) {
		return RegisterResult{
			Registered: true,
			StatusCode: resp.StatusCode,
			Reason:     resp.Reason,
			Attempts:   attempts,
			Binding:    buildRegistrationBinding(s.Profile, contactURI, resp, expires, securityClient, nil),
			NextCSeq:   cseq + 1,
		}, nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp.StatusCode, resp.Reason)
	}

	headerName := "WWW-Authenticate"
	authHeader := firstHeader(resp.Headers, headerName)
	authzHeader := "Authorization"
	if authHeader == "" {
		headerName = "Proxy-Authenticate"
		authHeader = firstHeader(resp.Headers, headerName)
		authzHeader = "Proxy-Authorization"
	}
	ch, err := SelectDigestChallenge(resp.Headers, headerName)
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	securityHeaders := resp.Headers

	authzInput, syncFailure, err := s.digestAuthInputForChallenge(ch, registrarURI)
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, Challenge: ch}, err
	}
	currentAuthInput := authzInput
	authz, err := BuildDigestAuthorization(ch, authzInput)
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, Challenge: ch}, err
	}

	// 受保护 REGISTER（TS 33.203）：401 的 Security-Server 宣告 port-s 后，
	// 鉴权 REGISTER 必须从 port-c 源端口发往 P-CSCF 的 port-s（1239t
	// dialSecureRegisterConn 同构）。Route 集保持首轮原样。
	// 仅 AKA 成功（CK/IK 已出）才切受保护端口——AUTS 重同步轮的 CSeq2
	// 走原明文连接（P-CSCF 对未完成安全协商的明文请求在 5060 应答；
	// 过早拨 port-s 实测无 ESP 可封装，连接失败回退明文被拒 same-nonce）。
	if len(authzInput.AKACK) > 0 && len(authzInput.AKAIK) > 0 {
		s.notifySecurityKeys(securityHeaders, authzInput)
		if flow, ok := s.Transport.(*WireSIPFlow); ok {
			if target := protectedTargetFromChallenge(s.RouteURI, securityHeaders); target != "" {
				flow.OverrideTarget = target
			}
		}
	}
	cseq++
	resp2, err := sendRegister(cseq, authzHeader, authz, resp.Headers)
	if err != nil {
		return RegisterResult{Attempts: attempts, Challenge: ch}, err
	}
	resp2, authz, _, err = retryMinExpires(resp2, authzHeader, authz, resp.Headers, &authzInput, ch)
	if err != nil {
		return RegisterResult{Attempts: attempts, Challenge: ch, AuthHeader: authz}, err
	}
	currentAuthInput = authzInput
	if syncFailure {
		if isSIPSuccess(resp2.StatusCode) {
			authState := newDigestAuthState(authzHeader, ch, currentAuthInput, authz)
			authState, err = updateDigestAuthStateFromInfo(authState, resp2.Headers, authzHeader, resp2.Body)
			result := RegisterResult{
				Registered:     true,
				StatusCode:     resp2.StatusCode,
				Reason:         resp2.Reason,
				Attempts:       attempts,
				Challenge:      ch,
				Binding:        buildRegistrationBinding(s.Profile, contactURI, resp2, expires, securityClient, securityHeaders),
				AuthHeader:     authz,
				AuthHeaderName: authzHeader,
				AuthState:      authState,
				NextCSeq:       cseq + 1,
			}
			if err != nil {
				result.Registered = false
				return result, err
			}
			return result, nil
		}
		if resp2.StatusCode != 401 && resp2.StatusCode != 407 {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, Challenge: ch, AuthHeader: authz}, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
		}
		nextHeaderName := "WWW-Authenticate"
		nextAuthzHeader := "Authorization"
		if firstHeader(resp2.Headers, nextHeaderName) == "" {
			nextHeaderName = "Proxy-Authenticate"
			nextAuthzHeader = "Proxy-Authorization"
		}
		nextChallenge, err := SelectDigestChallenge(resp2.Headers, nextHeaderName)
		if err != nil {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, Challenge: ch, AuthHeader: authz}, err
		}
		nextAuthInput, nextSyncFailure, err := s.digestAuthInputForChallenge(nextChallenge, registrarURI)
		if err != nil {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, Challenge: nextChallenge, AuthHeader: authz}, err
		}
		if nextSyncFailure {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, Challenge: nextChallenge, AuthHeader: authz}, sim.ErrSyncFailure
		}
		authz, err = BuildDigestAuthorization(nextChallenge, nextAuthInput)
		if err != nil {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, Challenge: nextChallenge, AuthHeader: authz}, err
		}
		// 重同步后的 AKA 成功——CK/IK 是本套 SA 的最终密钥材料。
		s.notifySecurityKeys(resp2.Headers, nextAuthInput)
		if len(nextAuthInput.AKACK) > 0 && len(nextAuthInput.AKAIK) > 0 {
			if flow, ok := s.Transport.(*WireSIPFlow); ok {
				if target := protectedTargetFromChallenge(s.RouteURI, resp2.Headers); target != "" {
					flow.OverrideTarget = target
				}
			}
		}
		ch = nextChallenge
		authzHeader = nextAuthzHeader
		currentAuthInput = nextAuthInput
		nextChallengeHeaders := resp2.Headers
		securityHeaders = nextChallengeHeaders
		cseq++
		resp2, err = sendRegister(cseq, authzHeader, authz, nextChallengeHeaders)
		if err != nil {
			return RegisterResult{Attempts: attempts, Challenge: ch, AuthHeader: authz}, err
		}
		resp2, authz, _, err = retryMinExpires(resp2, authzHeader, authz, nextChallengeHeaders, &nextAuthInput, ch)
		if err != nil {
			return RegisterResult{Attempts: attempts, Challenge: ch, AuthHeader: authz}, err
		}
		currentAuthInput = nextAuthInput
	}
	result := RegisterResult{
		Registered:     isSIPSuccess(resp2.StatusCode),
		StatusCode:     resp2.StatusCode,
		Reason:         resp2.Reason,
		Attempts:       attempts,
		Challenge:      ch,
		Binding:        buildRegistrationBinding(s.Profile, contactURI, resp2, expires, securityClient, securityHeaders),
		AuthHeader:     authz,
		AuthHeaderName: authzHeader,
		AuthState:      newDigestAuthState(authzHeader, ch, currentAuthInput, authz),
		NextCSeq:       cseq + 1,
	}
	if !result.Registered {
		return result, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
	}
	result.AuthState, err = updateDigestAuthStateFromInfo(result.AuthState, resp2.Headers, authzHeader, resp2.Body)
	if err != nil {
		result.Registered = false
		return result, err
	}
	return result, nil
}

func (s RegisterSession) Deregister(ctx context.Context, req DeregisterRequest) (DeregisterResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Transport == nil {
		return DeregisterResult{}, errors.New("nil SIP register transport")
	}
	registrarURI := strings.TrimSpace(s.RegistrarURI)
	contactURI := firstNonEmpty(req.Binding.ContactURI, s.ContactURI)
	if registrarURI == "" || contactURI == "" {
		return DeregisterResult{}, errors.New("registrar URI and contact URI are required")
	}
	callID := firstNonEmpty(req.CallID, s.CallID, "vowifi-go-register")
	cseq := req.CSeq
	if cseq <= 0 {
		cseq = 1
	}
	attempts := 0
	sendDeregister := func(cseq int, authHeaderName, authz string, challengeHeaders map[string][]string) (RegisterResponse, error) {
		msg := RegisterMessage{
			URI:     registrarURI,
			Headers: BuildRegisterHeaders(s.Profile, contactURI, callID, strconv.Itoa(cseq)),
		}
		msg.Headers["Expires"] = "0"
		msg.Headers["Contact"] = deregisterContactHeader(msg.Headers["Contact"])
		if securityClient := strings.TrimSpace(req.Binding.SecurityClient); securityClient != "" {
			msg.Headers["Security-Client"] = securityClient
		}
		if strings.TrimSpace(authHeaderName) != "" && strings.TrimSpace(authz) != "" {
			msg.Headers[authHeaderName] = authz
		}
		if securityVerify := securityVerifyFromChallenge(challengeHeaders); securityVerify != "" {
			msg.Headers["Security-Verify"] = securityVerify
		} else if len(req.Binding.SecurityVerify) > 0 {
			msg.Headers["Security-Verify"] = strings.Join(trimHeaderValues(req.Binding.SecurityVerify), ", ")
		}
		attempts++
		return s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	}
	authHeaderName, authz, _, err := nextDigestAuthorization(req.AuthState, "REGISTER", registrarURI, req.AuthHeaderName, req.AuthHeader)
	if err != nil {
		return DeregisterResult{Attempts: attempts}, err
	}
	resp, err := sendDeregister(cseq, authHeaderName, authz, nil)
	if err != nil {
		return DeregisterResult{Attempts: attempts}, err
	}
	if isSIPSuccess(resp.StatusCode) {
		return DeregisterResult{Deregistered: true, StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		result := DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}
		return result, fmt.Errorf("%w: deregister %d %s", ErrRegistrationRejected, resp.StatusCode, resp.Reason)
	}
	challengeHeader := "WWW-Authenticate"
	authHeaderName = "Authorization"
	if firstHeader(resp.Headers, challengeHeader) == "" {
		challengeHeader = "Proxy-Authenticate"
		authHeaderName = "Proxy-Authorization"
	}
	ch, err := SelectDigestChallenge(resp.Headers, challengeHeader)
	if err != nil {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	authInput, syncFailure, err := s.digestAuthInputForChallenge(ch, registrarURI)
	if err != nil {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	if syncFailure {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, sim.ErrSyncFailure
	}
	authz, err = BuildDigestAuthorization(ch, authInput)
	if err != nil {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	cseq++
	resp2, err := sendDeregister(cseq, authHeaderName, authz, resp.Headers)
	if err != nil {
		return DeregisterResult{Attempts: attempts}, err
	}
	result := DeregisterResult{Deregistered: isSIPSuccess(resp2.StatusCode), StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts}
	if !result.Deregistered {
		return result, fmt.Errorf("%w: deregister %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
	}
	return result, nil
}

func (s RegisterSession) Refresh(ctx context.Context, req RefreshRequest) (RefreshResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Transport == nil {
		return RefreshResult{}, errors.New("nil SIP register transport")
	}
	registrarURI := strings.TrimSpace(s.RegistrarURI)
	contactURI := firstNonEmpty(req.Binding.ContactURI, s.ContactURI)
	if registrarURI == "" || contactURI == "" {
		return RefreshResult{}, errors.New("registrar URI and contact URI are required")
	}
	callID := firstNonEmpty(req.CallID, s.CallID, "vowifi-go-register")
	cseq := req.CSeq
	if cseq <= 0 {
		cseq = 1
	}
	expires := req.Expires
	if expires <= 0 {
		expires = req.Binding.Expires
	}
	if expires <= 0 {
		expires = s.Expires
	}
	if expires <= 0 {
		expires = 3600
	}
	attempts := 0
	sendRefresh := func(cseq int, authHeaderName, authz string, challengeHeaders map[string][]string) (RegisterResponse, error) {
		msg := RegisterMessage{
			URI:     registrarURI,
			Headers: BuildRegisterHeaders(s.Profile, contactURI, callID, strconv.Itoa(cseq)),
		}
		msg.Headers["Expires"] = strconv.Itoa(expires)
		if securityClient := strings.TrimSpace(req.Binding.SecurityClient); securityClient != "" {
			msg.Headers["Security-Client"] = securityClient
		}
		if strings.TrimSpace(authHeaderName) != "" && strings.TrimSpace(authz) != "" {
			msg.Headers[authHeaderName] = authz
		}
		if securityVerify := securityVerifyFromChallenge(challengeHeaders); securityVerify != "" {
			msg.Headers["Security-Verify"] = securityVerify
		} else if len(req.Binding.SecurityVerify) > 0 {
			msg.Headers["Security-Verify"] = strings.Join(trimHeaderValues(req.Binding.SecurityVerify), ", ")
		}
		attempts++
		return s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	}
	authHeaderName, authz, authState, err := nextDigestAuthorization(req.AuthState, "REGISTER", registrarURI, req.AuthHeaderName, req.AuthHeader)
	if err != nil {
		return RefreshResult{Attempts: attempts}, err
	}
	resp, err := sendRefresh(cseq, authHeaderName, authz, nil)
	if err != nil {
		return RefreshResult{Attempts: attempts}, err
	}
	if isSIPSuccess(resp.StatusCode) {
		binding := mergeRefreshBinding(req.Binding, buildRegistrationBinding(s.Profile, contactURI, resp, expires, securityClientFromBinding(req.Binding), nil))
		authState, err = updateDigestAuthStateFromInfo(authState, resp.Headers, authHeaderName, resp.Body)
		result := RefreshResult{
			Refreshed:      true,
			StatusCode:     resp.StatusCode,
			Reason:         resp.Reason,
			Attempts:       attempts,
			Binding:        binding,
			AuthHeader:     authz,
			AuthHeaderName: authHeaderName,
			AuthState:      authState,
			NextCSeq:       cseq + 1,
		}
		if err != nil {
			result.Refreshed = false
			return result, err
		}
		return result, nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		result := RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}
		return result, fmt.Errorf("%w: refresh %d %s", ErrRegistrationRejected, resp.StatusCode, resp.Reason)
	}
	challengeHeader := "WWW-Authenticate"
	authHeaderName = "Authorization"
	if firstHeader(resp.Headers, challengeHeader) == "" {
		challengeHeader = "Proxy-Authenticate"
		authHeaderName = "Proxy-Authorization"
	}
	ch, err := SelectDigestChallenge(resp.Headers, challengeHeader)
	if err != nil {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	authInput, syncFailure, err := s.digestAuthInputForChallenge(ch, registrarURI)
	if err != nil {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	if syncFailure {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, sim.ErrSyncFailure
	}
	authz, err = BuildDigestAuthorization(ch, authInput)
	if err != nil {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	authState = newDigestAuthState(authHeaderName, ch, authInput, authz)
	cseq++
	resp2, err := sendRefresh(cseq, authHeaderName, authz, resp.Headers)
	if err != nil {
		return RefreshResult{Attempts: attempts}, err
	}
	resultBinding := mergeRefreshBinding(req.Binding, buildRegistrationBinding(s.Profile, contactURI, resp2, expires, securityClientFromBinding(req.Binding), resp.Headers))
	result := RefreshResult{
		Refreshed:      isSIPSuccess(resp2.StatusCode),
		StatusCode:     resp2.StatusCode,
		Reason:         resp2.Reason,
		Attempts:       attempts,
		Binding:        resultBinding,
		AuthHeader:     authz,
		AuthHeaderName: authHeaderName,
		AuthState:      authState,
		NextCSeq:       cseq + 1,
	}
	if !result.Refreshed {
		return result, fmt.Errorf("%w: refresh %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
	}
	result.AuthState, err = updateDigestAuthStateFromInfo(result.AuthState, resp2.Headers, authHeaderName, resp2.Body)
	if err != nil {
		result.Refreshed = false
		return result, err
	}
	return result, nil
}

func (s RegisterSession) securityClientAgreement() SecurityAgreement {
	if isZeroSecurityAgreement(s.SecurityClient) {
		return DefaultSecurityClientAgreement(s.SecurityRandom)
	}
	return completeSecurityAgreement(s.SecurityClient)
}

func nextDigestAuthorization(state DigestAuthState, method, uri, fallbackName, fallbackHeader string) (string, string, DigestAuthState, error) {
	headerName := firstNonEmpty(state.headerName, fallbackName, "Authorization")
	if state.Usable() {
		authz, next, err := state.Build(method, uri)
		if err != nil {
			return headerName, "", state, err
		}
		return firstNonEmpty(next.headerName, headerName), authz, next, nil
	}
	return firstNonEmpty(fallbackName, headerName), strings.TrimSpace(fallbackHeader), state.clone(), nil
}

func updateDigestAuthStateFromInfo(state DigestAuthState, headers map[string][]string, authHeaderName string, body []byte) (DigestAuthState, error) {
	if !state.Usable() {
		return state, nil
	}
	params := digestInfoParams(headers, authHeaderName)
	if rspauth := strings.TrimSpace(params["rspauth"]); rspauth != "" {
		expected, err := digestRspauth(state, firstNonEmpty(params["qop"], state.challenge.QOP), body)
		if err != nil {
			return state, err
		}
		if !strings.EqualFold(rspauth, expected) {
			return state, fmt.Errorf("%w: rspauth mismatch", ErrInvalidAuthenticationInfo)
		}
	}
	nextNonce := strings.TrimSpace(params["nextnonce"])
	if nextNonce == "" || nextNonce == state.challenge.Nonce {
		return state, nil
	}
	next := state.clone()
	next.challenge.Nonce = nextNonce
	next.input.NC = 1
	next.nextNC = 1
	next.lastHeader = ""
	return next, nil
}

func digestInfoNextNonce(headers map[string][]string, authHeaderName string) string {
	return digestInfoParams(headers, authHeaderName)["nextnonce"]
}

func digestInfoParams(headers map[string][]string, authHeaderName string) map[string]string {
	params := make(map[string]string)
	for _, name := range digestInfoHeaderNames(authHeaderName) {
		for _, header := range rawHeaderValues(headers, name) {
			for _, part := range splitAuthParams(header) {
				key, value, ok := strings.Cut(part, "=")
				if !ok {
					continue
				}
				key = strings.ToLower(strings.TrimSpace(key))
				value = unquote(strings.TrimSpace(value))
				if key != "" && value != "" {
					params[key] = value
				}
			}
		}
		if len(params) > 0 {
			return params
		}
	}
	return params
}

func digestInfoHeaderNames(authHeaderName string) []string {
	if strings.EqualFold(strings.TrimSpace(authHeaderName), "Proxy-Authorization") {
		return []string{"Proxy-Authentication-Info", "Authentication-Info"}
	}
	return []string{"Authentication-Info", "Proxy-Authentication-Info"}
}

func digestRspauth(state DigestAuthState, qop string, body []byte) (string, error) {
	input := state.input
	qop = firstQOP(qop)
	ha1 := md5Hex(input.Username + ":" + state.challenge.Realm + ":" + input.Password)
	ha2 := ""
	switch qop {
	case "":
		ha2 = md5Hex(":" + input.URI)
	case "auth":
		ha2 = md5Hex(":" + input.URI)
	case "auth-int":
		ha2 = md5Hex(":" + input.URI + ":" + md5HexBytes(body))
	default:
		return "", fmt.Errorf("%w: unsupported rspauth qop %q", ErrInvalidAuthenticationInfo, qop)
	}
	nc := input.NC
	if nc <= 0 {
		nc = 1
	}
	if qop == "" {
		return md5Hex(ha1 + ":" + state.challenge.Nonce + ":" + ha2), nil
	}
	cnonce := strings.TrimSpace(input.CNonce)
	if cnonce == "" {
		return "", fmt.Errorf("%w: cnonce required", ErrInvalidAuthenticationInfo)
	}
	return md5Hex(ha1 + ":" + state.challenge.Nonce + ":" + fmt.Sprintf("%08x", nc) + ":" + cnonce + ":" + qop + ":" + ha2), nil
}

func securityClientFromBinding(binding RegistrationBinding) SecurityAgreement {
	if agreement, ok := parseSecurityAgreement(binding.SecurityClient); ok {
		return agreement
	}
	return SecurityAgreement{}
}

func mergeRefreshBinding(previous, next RegistrationBinding) RegistrationBinding {
	if strings.TrimSpace(next.ContactURI) == "" {
		next.ContactURI = previous.ContactURI
	}
	if strings.TrimSpace(next.PublicIdentity) == "" {
		next.PublicIdentity = previous.PublicIdentity
	}
	if len(next.AssociatedURIs) == 0 {
		next.AssociatedURIs = append([]string(nil), previous.AssociatedURIs...)
	}
	if len(next.ServiceRoutes) == 0 {
		next.ServiceRoutes = append([]string(nil), previous.ServiceRoutes...)
	}
	if len(next.Paths) == 0 {
		next.Paths = append([]string(nil), previous.Paths...)
	}
	if strings.TrimSpace(next.SecurityClient) == "" {
		next.SecurityClient = previous.SecurityClient
	}
	if len(next.SecurityServer) == 0 {
		next.SecurityServer = append([]string(nil), previous.SecurityServer...)
	}
	if len(next.SecurityVerify) == 0 {
		next.SecurityVerify = append([]string(nil), previous.SecurityVerify...)
	}
	if isZeroSecurityAgreement(next.SecurityAgreement) {
		next.SecurityAgreement = previous.SecurityAgreement
	}
	if next.Expires <= 0 {
		next.Expires = previous.Expires
	}
	if strings.TrimSpace(next.RegistrarContact) == "" {
		next.RegistrarContact = previous.RegistrarContact
	}
	return next
}

func (s RegisterSession) digestAuthInputForChallenge(ch DigestChallenge, registrarURI string) (DigestAuthInput, bool, error) {
	input := DigestAuthInput{
		Method: "REGISTER",
		URI:    registrarURI,
		// digest username 与首个 REGISTER 占位同源：标准 IMPI 优先（Vodafone UK
		// S-CSCF HSS 用户键），EAP NAI 兜底。
		Username: firstNonEmpty(s.Profile.IMPI, BuildEAPRootNAI(s.Profile), s.Profile.IMPU),
		CNonce:   firstNonEmpty(s.CNonce, "vowifi-go"),
		NC:       1,
	}
	if !isAKADigestAlgorithm(ch.Algorithm) {
		return input, false, nil
	}
	rand16, autn16, ok := ExtractAKAChallengeNonce(ch.Nonce)
	if !ok {
		return input, false, ErrInvalidChallenge
	}
	if s.AKAProvider == nil {
		return input, false, errors.New("AKA provider required for IMS digest AKA")
	}
	aka, err := s.AKAProvider.CalculateAKA(rand16, autn16)
	if errors.Is(err, sim.ErrSyncFailure) {
		if len(aka.AUTS) == 0 {
			return input, false, err
		}
		input.AUTS = append([]byte(nil), aka.AUTS...)
		return input, true, nil
	}
	if err != nil {
		return input, false, err
	}
	// APDU 后端（0xDC）以「nil 错误 + 非空 AUTS」表达同步失败——按 AUTS 在场判
	// 定，否则走到 BuildAKADigestPassword 才以 "AKA RES is empty" 失败。
	if len(aka.AUTS) > 0 {
		input.AUTS = append([]byte(nil), aka.AUTS...)
		return input, true, nil
	}
	password, err := BuildAKADigestPassword(ch.Algorithm, aka)
	if err != nil {
		return input, false, err
	}
	input.Password = password
	input.AKACK = append([]byte(nil), aka.CK...)
	input.AKAIK = append([]byte(nil), aka.IK...)
	return input, false, nil
}

// notifySecurityKeys 在 AKA 成功（DigestAuthInput 带 CK/IK）后把安全协商
// 完整要素上抛给 OnSecurityKeys：UE 侧 Security-Client 机制 + P-CSCF 的
// Security-Server 机制 + CK/IK。注册失败/无回调/同步失败轮次静默跳过。
func (s RegisterSession) notifySecurityKeys(challengeHeaders map[string][]string, input DigestAuthInput) {
	if s.OnSecurityKeys == nil || len(input.AKACK) == 0 || len(input.AKAIK) == 0 {
		return
	}
	serverValues := trimHeaderValues(headerListValues(challengeHeaders, "Security-Server"))
	serverAgreements := ParseSecurityAgreements(serverValues)
	if len(serverAgreements) == 0 {
		return
	}
	// P-CSCF 选择以首条 Security-Server 机制为准（实测 Vodafone UK 单条）。
	s.OnSecurityKeys(s.SecurityClient, serverAgreements[0], input.AKACK, input.AKAIK)
}

func SelectDigestChallenge(headers map[string][]string, name string) (DigestChallenge, error) {
	var best DigestChallenge
	bestScore := -1
	var firstErr error
	for _, header := range rawHeaderValues(headers, name) {
		ch, err := ParseWWWAuthenticate(header)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !digestChallengeSupported(ch) {
			if firstErr == nil {
				firstErr = unsupportedDigestChallengeError(ch)
			}
			continue
		}
		score := digestAlgorithmScore(ch.Algorithm)
		if score > bestScore {
			best = ch
			bestScore = score
		}
	}
	if bestScore >= 0 {
		return best, nil
	}
	if firstErr != nil {
		return DigestChallenge{}, firstErr
	}
	return DigestChallenge{}, ErrInvalidChallenge
}

func digestChallengeSupported(ch DigestChallenge) bool {
	return digestAlgorithmScore(ch.Algorithm) > 0 && digestQOPSupported(ch.QOP)
}

func digestQOPSupported(qop string) bool {
	qop = strings.TrimSpace(qop)
	if qop == "" {
		return true
	}
	switch firstQOP(qop) {
	case "auth", "auth-int":
		return true
	default:
		return false
	}
}

func unsupportedDigestChallengeError(ch DigestChallenge) error {
	if digestAlgorithmScore(ch.Algorithm) <= 0 {
		return fmt.Errorf("unsupported digest algorithm %q", ch.Algorithm)
	}
	return fmt.Errorf("unsupported digest qop %q", ch.QOP)
}

func BuildRegistrationBinding(profile IMSProfile, contactURI string, resp RegisterResponse, requestedExpires int) RegistrationBinding {
	return buildRegistrationBinding(profile, contactURI, resp, requestedExpires, SecurityAgreement{}, nil)
}

func buildRegistrationBinding(profile IMSProfile, contactURI string, resp RegisterResponse, requestedExpires int, securityClient SecurityAgreement, securityFallback map[string][]string) RegistrationBinding {
	associated := normalizeAddressValues(headerListValues(resp.Headers, "P-Associated-URI"))
	securityServer := trimHeaderValues(headerListValues(resp.Headers, "Security-Server"))
	if len(securityServer) == 0 && securityFallback != nil {
		securityServer = trimHeaderValues(headerListValues(securityFallback, "Security-Server"))
	}
	securityVerify := append([]string(nil), securityServer...)
	securityClientHeader := ""
	if !isZeroSecurityAgreement(securityClient) {
		securityClientHeader = BuildSecurityClientHeader(securityClient)
	}
	registrarContact := registrationContactHeader(resp.Headers, contactURI)
	binding := RegistrationBinding{
		ContactURI:       strings.TrimSpace(contactURI),
		PublicIdentity:   defaultPublicIdentity(profile, associated),
		AssociatedURIs:   associated,
		ServiceRoutes:    trimHeaderValues(headerListValues(resp.Headers, "Service-Route")),
		Paths:            trimHeaderValues(headerListValues(resp.Headers, "Path")),
		SecurityClient:   securityClientHeader,
		SecurityServer:   securityServer,
		SecurityVerify:   securityVerify,
		Expires:          registrationExpires(resp.Headers, contactURI, requestedExpires),
		RegistrarContact: registrarContact,
	}
	if selected, ok := SelectSecurityAgreement(binding.SecurityServer, securityClient); ok {
		binding.SecurityAgreement = selected
	}
	if len(binding.AssociatedURIs) == 0 && binding.PublicIdentity != "" {
		binding.AssociatedURIs = []string{binding.PublicIdentity}
	}
	return binding
}

func splitAuthParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == ',' && !inQuote:
			if part := strings.TrimSpace(cur.String()); part != "" {
				out = append(out, part)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func firstQOP(qop string) string {
	for _, part := range strings.Split(qop, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "auth" {
			return p
		}
	}
	for _, part := range strings.Split(qop, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "auth-int" {
			return p
		}
	}
	return strings.ToLower(strings.TrimSpace(qop))
}

func firstHeader(headers map[string][]string, name string) string {
	return firstTrimmed(rawHeaderValues(headers, name)...)
}

func isSIPSuccess(code int) bool {
	return code >= 200 && code < 300
}

func cloneRegisterMessage(msg RegisterMessage) RegisterMessage {
	out := RegisterMessage{
		URI:     msg.URI,
		Headers: make(map[string]string, len(msg.Headers)),
		Body:    append([]byte(nil), msg.Body...),
	}
	for k, v := range msg.Headers {
		out.Headers[k] = v
	}
	return out
}

func deregisterContactHeader(contact string) string {
	contact = strings.TrimSpace(contact)
	if contact == "" {
		return ""
	}
	parts := splitSemicolonParams(contact)
	if len(parts) == 0 {
		return contact + ";expires=0"
	}
	var out []string
	replaced := false
	for i, part := range parts {
		if i > 0 {
			key, _, ok := strings.Cut(part, "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "expires") {
				out = append(out, "expires=0")
				replaced = true
				continue
			}
		}
		out = append(out, part)
	}
	if !replaced {
		out = append(out, "expires=0")
	}
	return strings.Join(out, ";")
}

func decodeNonceBytes(nonce string) ([]byte, bool) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return nil, false
	}
	clean := strings.NewReplacer(":", "", "-", "", " ", "").Replace(nonce)
	if raw, err := hex.DecodeString(clean); err == nil {
		return raw, true
	}
	if raw, err := base64.StdEncoding.DecodeString(nonce); err == nil {
		return raw, true
	}
	if raw, err := base64.RawStdEncoding.DecodeString(nonce); err == nil {
		return raw, true
	}
	return nil, false
}

func isAKADigestAlgorithm(algorithm string) bool {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	return alg == "AKAV1-MD5" || alg == "AKAV2-MD5"
}

func digestAlgorithmScore(algorithm string) int {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "AKAV2-MD5":
		return 30
	case "AKAV1-MD5":
		return 20
	case "MD5":
		return 10
	default:
		return 0
	}
}

func rawHeaderValues(headers map[string][]string, name string) []string {
	var out []string
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					out = append(out, strings.TrimSpace(value))
				}
			}
		}
	}
	return out
}

func headerListValues(headers map[string][]string, name string) []string {
	var out []string
	for _, value := range rawHeaderValues(headers, name) {
		out = append(out, splitSIPHeaderValues(value)...)
	}
	return out
}

func splitSIPHeaderValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	angleDepth := 0
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == '<' && !inQuote:
			angleDepth++
			cur.WriteRune(r)
		case r == '>' && !inQuote:
			if angleDepth > 0 {
				angleDepth--
			}
			cur.WriteRune(r)
		case r == ',' && !inQuote && angleDepth == 0:
			if part := strings.TrimSpace(cur.String()); part != "" {
				out = append(out, part)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func normalizeAddressValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if uri := extractAddressURI(value); uri != "" {
			out = append(out, uri)
		}
	}
	return out
}

func trimHeaderValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func extractAddressURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start+1:], '>'); end >= 0 {
			return strings.TrimSpace(value[start+1 : start+1+end])
		}
	}
	if fields := strings.Fields(value); len(fields) > 0 {
		value = fields[0]
	}
	return strings.TrimSpace(strings.Trim(value, "<>"))
}

func defaultPublicIdentity(profile IMSProfile, associated []string) string {
	if len(associated) > 0 {
		return associated[0]
	}
	if impu := strings.TrimSpace(profile.IMPU); impu != "" {
		return impu
	}
	if strings.TrimSpace(profile.IMPI) != "" && strings.TrimSpace(profile.Domain) != "" {
		return "sip:" + strings.TrimSpace(profile.IMPI) + "@" + strings.TrimSpace(profile.Domain)
	}
	return strings.TrimSpace(profile.IMPI)
}

func registrationExpires(headers map[string][]string, contactURI string, fallback int) int {
	if contact, ok := matchingRegistrationContactHeader(headers, contactURI); ok {
		if n, ok := headerParamInt(contact, "expires"); ok {
			return n
		}
	}
	for _, value := range rawHeaderValues(headers, "Expires") {
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return n
		}
	}
	if fallback > 0 {
		return fallback
	}
	return 0
}

func registrationContactHeader(headers map[string][]string, contactURI string) string {
	contacts := trimHeaderValues(headerListValues(headers, "Contact"))
	if len(contacts) == 0 {
		return ""
	}
	if contact, ok := matchingRegistrationContactHeader(headers, contactURI); ok {
		return contact
	}
	return contacts[0]
}

func matchingRegistrationContactHeader(headers map[string][]string, contactURI string) (string, bool) {
	contacts := trimHeaderValues(headerListValues(headers, "Contact"))
	if len(contacts) == 0 {
		return "", false
	}
	target := normalizeSIPURIForContactMatch(contactURI)
	if target == "" {
		return contacts[0], true
	}
	for _, contact := range contacts {
		if normalizeSIPURIForContactMatch(extractAddressURI(contact)) == target {
			return contact, true
		}
	}
	return "", false
}

func normalizeSIPURIForContactMatch(uri string) string {
	uri = strings.TrimSpace(strings.Trim(uri, "<>"))
	if uri == "" || uri == "*" {
		return ""
	}
	if semi := strings.IndexByte(uri, ';'); semi >= 0 {
		uri = uri[:semi]
	}
	return strings.ToLower(strings.TrimSpace(uri))
}

func minExpiresHeader(headers map[string][]string) int {
	for _, value := range rawHeaderValues(headers, "Min-Expires") {
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func headerParamInt(value, name string) (int, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.ToLower(strings.TrimSpace(key)) != name {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(raw, `"`))
		return n, err == nil
	}
	return 0, false
}

func securityVerifyFromChallenge(headers map[string][]string) string {
	values := trimHeaderValues(headerListValues(headers, "Security-Server"))
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ", ")
}

// protectedTargetFromChallenge 从 401 的 Security-Server port-s 与初始 RouteURI
// 构造受保护 REGISTER 的直连目标（P-CSCF host:port-s）。
func protectedTargetFromChallenge(routeURI string, challengeHeaders map[string][]string) string {
	portS := ""
	for _, v := range trimHeaderValues(headerListValues(challengeHeaders, "Security-Server")) {
		for _, part := range strings.Split(v, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "port-s=") {
				portS = strings.TrimSpace(part[len("port-s="):])
			}
		}
	}
	if portS == "" {
		return ""
	}
	uri := strings.TrimSpace(routeURI)
	if uri == "" {
		return ""
	}
	uri = strings.TrimPrefix(uri, "sip:")
	host := uri
	if i := strings.IndexAny(host, ":;"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, portS)
}

// routeHeaderForChallenge 计算当前 REGISTER 的 Route 头。401 挑战后
// Security-Server 宣告 port-s（保护端口），后续 REGISTER/请求须路由到该端口
// （TS 33.203 逐跳保护语义）；首轮用初始 RouteURI（P-CSCF:5060）。
func routeHeaderForChallenge(routeURI string, challengeHeaders map[string][]string) string {
	values := trimHeaderValues(headerListValues(challengeHeaders, "Security-Server"))
	if len(values) == 0 {
		if strings.TrimSpace(routeURI) == "" {
			return ""
		}
		return "<" + strings.TrimSpace(routeURI) + ">"
	}
	portS := ""
	for _, v := range values {
		for _, part := range strings.Split(v, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "port-s=") {
				portS = strings.TrimSpace(part[len("port-s="):])
			}
		}
	}
	if strings.TrimSpace(routeURI) == "" {
		return ""
	}
	// 1239t runSecureAuthenticatedRegister：受保护重试的 Route 集保持首轮原样
	// （"Security agreement changes the transport ports, not the REGISTER route set"），
	// 不把 port-s 拼进 Route（Vodafone P-CSCF 对双端口 URI 回 400 Bad header field: route）。
	_ = portS
	return "<" + strings.TrimSpace(routeURI) + ">"
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func md5HexBytes(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if out, err := strconv.Unquote(s); err == nil {
			return out
		}
		return s[1 : len(s)-1]
	}
	return s
}

func quote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func firstTrimmed(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

// imsMmtelICSIRefURNEscaped 与 1239t policy.IMSMmtelICSIRef 一致（冒号已 %3A 转义）。
const imsMmtelICSIRefURNEscaped = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"

// stableSIPInstanceURN 在进程内保持一个稳定的 sip.instance（RFC 5626 GRUU 语义：
// 同一 UE 的所有 REGISTER 必须带同一 instance-id）。1239t resolveStableSIPInstance 同理。
var stableSIPInstanceURN = NewSIPInstanceURN()

// buildPANIHeader 构造 P-Access-Network-Info：IEEE-802.11;country=<ISO>（VoCat
// compose_pani_from_sip 同构——MCC→ISO 3166 alpha-2 表内取值，未命中省略 country）。
func buildPANIHeader(profile IMSProfile) string {
	if c := mccToISOAlpha2(profile.MCC); c != "" {
		return "IEEE-802.11;country=" + c
	}
	return "IEEE-802.11"
}

// mccToISOAlpha2 最小 MCC→ISO 表（覆盖本项目在用运营商）。
func mccToISOAlpha2(mcc string) string {
	switch strings.TrimSpace(mcc) {
	case "234", "235":
		return "GB"
	case "310", "311", "312", "313", "314", "315", "316":
		return "US"
	case "262":
		return "DE"
	case "204":
		return "NL"
	case "460":
		return "CN"
	case "454":
		return "HK"
	case "466":
		return "TW"
	case "302":
		return "CA"
	case "530":
		return "NZ"
	case "228":
		return "CH"
	}
	return ""
}

// BuildGSMAIMEIInstanceURN 由 15 位 IMEI 构造 GSMA instance（TAC8-SNR6-SV1 三段）。
func BuildGSMAIMEIInstanceURN(imei string) string {
	imei = strings.TrimSpace(imei)
	if len(imei) != 15 {
		return ""
	}
	return "urn:gsma:imei:" + imei[:8] + "-" + imei[8:14] + "-" + imei[14:]
}

// buildRegisterContactHeader：优先 GSMA IMEI instance（v155 sip_instance_imei 模式），
// 否则退回进程稳定 UUID instance。参数顺序对齐 1239t default(giffgaff)
// ContactParamOrder：access_type → audio → smsip → icsi_ref → sip_instance，尾挂 ;expires。
func buildRegisterContactHeader(profile IMSProfile, contactURI string) string {
	instance := BuildGSMAIMEIInstanceURN(profile.IMEI)
	if instance == "" {
		instance = stableSIPInstanceURN
	}
	b := strings.Builder{}
	b.WriteString("<")
	b.WriteString(strings.TrimSpace(contactURI))
	b.WriteString(">")
	b.WriteString(";+g.3gpp.accesstype=\"IEEE-802.11\"")
	b.WriteString(";audio")
	b.WriteString(";+g.3gpp.smsip")
	b.WriteString(";+g.3gpp.icsi-ref=\"" + imsMmtelICSIRefURNEscaped + "\"")
	b.WriteString(";+sip.instance=\"<" + instance + ">\"")
	b.WriteString(";expires=3600")
	return b.String()
}

// buildDefaultContactHeader 对齐 1239t default(giffgaff) ContactParamOrder：
// access_type → audio → smsip → icsi_ref → sip_instance，尾挂 ;expires=<n>。
func buildDefaultContactHeader(contactURI string) string {
	b := strings.Builder{}
	b.WriteString("<")
	b.WriteString(strings.TrimSpace(contactURI))
	b.WriteString(">")
	b.WriteString(";+g.3gpp.accesstype=\"IEEE-802.11\"")
	b.WriteString(";audio")
	b.WriteString(";+g.3gpp.smsip")
	b.WriteString(";+g.3gpp.icsi-ref=\"" + imsMmtelICSIRefURNEscaped + "\"")
	b.WriteString(";+sip.instance=\"<" + stableSIPInstanceURN + ">\"")
	b.WriteString(";expires=3600")
	return b.String()
}

// NewSIPInstanceURN 生成 SIP 实例标识（RFC 5626）：UUID v4 的 urn 表示。
// P-CSCF 会校验 +sip.instance 参数格式——非 UUID 形态（如 "vowifi-go"）实测
// 触发 400 Bad Request。
func NewSIPInstanceURN() string {
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return "urn:uuid:00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// GenerateSIPTag 生成 From 头的随机 tag（RFC 3261 19.3：至少 32bit 随机）。
func GenerateSIPTag() string {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return "vowifi-go"
	}
	return hex.EncodeToString(b[:])
}

// BuildInitialAKAEmptyAuthorization 构造 aka_empty 占位 Authorization 头
// （参考 imscore buildInitialAuthorization）：username=IMPI、uri=注册域、
// nonce/response 留空、algorithm=AKAv1-MD5。
func BuildInitialAKAEmptyAuthorization(profile IMSProfile, requestURI string) string {
	// digest username 形状试验序（Vodafone UK S-CSCF 按 HSS 查用户）：
	// A) 裸 IMSI → 403（0823n 实测）
	// B) EAP root NAI（0<IMSI>@nai.epc…，1239t default）→ 403（0823p 实测）
	// C) 标准 IMPI（<IMSI>@<home domain>，1239t imsi_home_domain 形状）→ 本版
	username := strings.TrimSpace(profile.IMPI)
	if username == "" {
		username = BuildEAPRootNAI(profile)
	}
	if username == "" {
		username = strings.TrimSpace(profile.IMPU)
	}
	realm := strings.TrimSpace(profile.Domain)
	uri := strings.TrimSpace(requestURI)
	if uri == "" {
		uri = "sip:" + realm
	}
	// 参数顺序与 v155/1239t 的 default 分支逐字一致（uri 在前）：某些 P-CSCF
	// 对首个 REGISTER 的 Authorization 参数顺序敏感。
	return fmt.Sprintf("Digest uri=%q,username=%q,algorithm=AKAv1-MD5,response=\"\",realm=%q,nonce=\"\"",
		uri, username, realm)
}

// BuildEAPRootNAI 构造 EAP 永久身份（TS 23.003 §19.3.2）：0<IMSI>@nai.epc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org。
// 与 engine/swu.eapIdentityForTunnel 同构；IMS digest 的 username 与 EAP 层身份保持一致（1239t host.go
// imsPrivateID = eapIdentity 的默认路径）。
func BuildEAPRootNAI(profile IMSProfile) string {
	imsi := strings.TrimSpace(profile.IMSI)
	mcc := strings.TrimSpace(profile.MCC)
	mnc := strings.TrimSpace(profile.MNC)
	if imsi == "" || mcc == "" || mnc == "" {
		return ""
	}
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return "0" + imsi + "@nai.epc.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
}
