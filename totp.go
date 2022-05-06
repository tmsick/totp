package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	minDigits     = 6
	maxDigits     = 10
	defaultDigits = 6
	minPeriod     = 1
	maxPeriod     = 90
	defaultPeriod = 30
)

type algorithm func() hash.Hash

type Token struct {
	label     string
	secret    []byte
	issuer    string
	algorithm algorithm
	digits    int
	period    int
}

var (
	algorithmSHA1    algorithm = sha1.New
	algorithmSHA256  algorithm = sha256.New
	algorithmSHA512  algorithm = sha512.New
	algorithmDefault algorithm = algorithmSHA1
)

func NewToken(uri string) (*Token, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse URI %q", uri)
	}
	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("Scheme have to be \"otpauth\". Got %q. URI: %q", u.Scheme, uri)
	}
	if u.Host != "totp" {
		return nil, fmt.Errorf("Host have to be \"totp\". Got %q. URI: %q", u.Host, uri)
	}

	// Initialize Token
	token := &Token{
		algorithm: algorithmDefault,
		digits:    defaultDigits,
		period:    defaultPeriod,
	}

	// Process secret [REQUIRED]
	if u.Query().Has("secret") {
		rawSecret := u.Query().Get("secret")
		upperSecret := strings.ToUpper(rawSecret)
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(upperSecret)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode secret value %q as Base32 string. URI: %q", rawSecret, uri)
		}
		token.secret = secret
	} else {
		return nil, fmt.Errorf("Secret is required in query parameter. URI: %q", uri)
	}

	// Process issuer [OPTIONAL]
	if u.Query().Has("issuer") {
		token.issuer = u.Query().Get("issuer")
	}

	// Process algorithm [OPTIONAL]
	if u.Query().Has("algorithm") {
		rawAlgorithm := u.Query().Get("algorithm")
		switch rawAlgorithm {
		case "SHA1":
			token.algorithm = algorithmSHA1
		case "SHA256":
			token.algorithm = algorithmSHA256
		case "SHA512":
			token.algorithm = algorithmSHA512
		default:
			return nil, fmt.Errorf("Algorithm have to be one of \"SHA1\", \"SHA256\", or \"SHA512\". Got %q. URI: %q", rawAlgorithm, uri)
		}
	}

	// Process digits [OPTIONAL]
	if u.Query().Has("digits") {
		rawDigits := u.Query().Get("digits")
		digits, err := strconv.Atoi(rawDigits)
		if err != nil {
			return nil, fmt.Errorf("Digits %q cannot be converted into an integer. URI: %q", rawDigits, uri)
		}
		if digits < minDigits || digits > maxDigits {
			return nil, fmt.Errorf("Digits have to be in the range of [%v, %v]. Got %v. URI: %q", minDigits, maxDigits, digits, uri)
		}
		token.digits = digits
	}

	// Process period
	if u.Query().Has("period") {
		rawPeriod := u.Query().Get("period")
		period, err := strconv.Atoi(rawPeriod)
		if err != nil {
			return nil, fmt.Errorf("Period %q cannot be converted into an integer. URI: %q", rawPeriod, uri)
		}
		if period < minPeriod || period > maxPeriod {
			return nil, fmt.Errorf("Period have to be in the range of [%v, %v]. Got %v. URI: %q", minPeriod, maxPeriod, period, uri)
		}
		token.period = period
	}

	return token, nil
}

func (token Token) Generate(t time.Time) string {
	// `token.period` is guaranteed to be positive.
	u := t.Unix() / int64(token.period)

	// According to RFC 4226 (p.5), `msg` is a 8-byte-long bytearray.
	//
	// > Symbol  Represents
	// > -------------------------------------------------------------------
	// > C       8-byte counter value, the moving factor.  This counter
	// >         MUST be synchronized between the HOTP generator (client)
	// >         and the HOTP validator (server).
	msg := make([]byte, 8)
	msg[0] = byte((u & 0x_7f_00_00_00_00_00_00_00) >> 0o70)
	msg[1] = byte((u & 0x_00_ff_00_00_00_00_00_00) >> 0o60)
	msg[2] = byte((u & 0x_00_00_ff_00_00_00_00_00) >> 0o50)
	msg[3] = byte((u & 0x_00_00_00_ff_00_00_00_00) >> 0o40)
	msg[4] = byte((u & 0x_00_00_00_00_ff_00_00_00) >> 0o30)
	msg[5] = byte((u & 0x_00_00_00_00_00_ff_00_00) >> 0o20)
	msg[6] = byte((u & 0x_00_00_00_00_00_00_ff_00) >> 0o10)
	msg[7] = byte((u & 0x_00_00_00_00_00_00_00_ff) >> 0o00)

	return hotp(msg, token.secret, token.algorithm, token.digits)
}

func hotp(msg []byte, secret []byte, algorithm func() hash.Hash, digits int) string {
	// Generate an HMAC-SHA1, -SHA256, or -SHA512 value with `msg` and `secret`.
	h := hmac.New(algorithm, secret)
	// `h.Write()` never returns an error and it's OK to ignore the return value.
	// ref: https://pkg.go.dev/hash
	h.Write(msg)
	mac := h.Sum(nil)

	// Start Dynamic Truncation (DT) defined in RFC 4226 (p.7).
	i := int(mac[len(mac)-1]) & 0x0f

	// It is safe to naively access `mac[i+0]`...`mac[i+3]` because `i` is in the range of [0, 15]
	// and `mac` has the result of HMAC-SHA1, -SHA256, or -SHA512, whose length is at least 20
	// bytes, 32 bytes, or 64 bytes respectively.
	n := 0
	n += int(mac[i+0]) & 0x7f << 0o30
	n += int(mac[i+1]) & 0xff << 0o20
	n += int(mac[i+2]) & 0xff << 0o10
	n += int(mac[i+3]) & 0xff << 0o00

	// `digits` is small enough. It is guaranteed to be in the range of [minDigits, maxDigits].
	n %= int(math.Pow10(digits))

	// Prepare template string like "%06d".
	tpl := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(tpl, n)
}
