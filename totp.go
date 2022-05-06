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
	minPeriod     = 1
	defaultDigits = 6
	defaultPeriod = 30
)

var (
	defaultAlgorithm = sha1.New
)

type Token struct {
	label     string
	secret    []byte
	issuer    string
	algorithm func() hash.Hash
	digits    int
	period    int
}

func NewToken(uri string) (*Token, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse uri: %q", uri)
	}
	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("scheme must be \"otpauth\". uri: %q", uri)
	}
	if u.Host != "totp" {
		return nil, fmt.Errorf("host must be \"totp\". uri: %q", uri)
	}
	if !u.Query().Has("secret") {
		return nil, fmt.Errorf("uri must have secret in query. uri: %q", uri)
	}

	// Init &Token
	token := &Token{
		algorithm: defaultAlgorithm,
		digits:    defaultDigits,
		period:    defaultPeriod,
	}
	for key, values := range u.Query() {
		for _, value := range values {
			switch key {
			case "secret":
				token.secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(value))
				if err != nil {
					return nil, fmt.Errorf("got invalid secret. %q cannot be decoded as a base32 string", value)
				}
			case "issuer":
				token.issuer = value
			case "algorithm":
				switch value {
				case "SHA1":
					token.algorithm = sha1.New
				case "SHA256":
					token.algorithm = sha256.New
				case "SHA512":
					token.algorithm = sha512.New
				default:
					return nil, fmt.Errorf("got invalid algorithm %q. valid values are: SHA1, SHA256, and SHA512", value)
				}
			case "digits":
				digits, _err := strconv.Atoi(value)
				if _err != nil {
					return nil, fmt.Errorf("got invalid digits. %q cannot be converted into an integer", value)
				}
				if digits < minDigits || digits > maxDigits {
					return nil, fmt.Errorf("digits must be in the range of [%v, %v]. got %v", minDigits, maxDigits, digits)
				}
				token.digits = digits
			case "period":
				period, _err := strconv.Atoi(value)
				if _err != nil {
					return nil, fmt.Errorf("got invalid period. %q cannot be converted into an integer", value)
				}
				if period < minPeriod {
					return nil, fmt.Errorf("period must be greater than or equal to %v. got %v", minPeriod, period)
				}
				token.period = period
			}
		}
	}
	return token, nil
}

func (token Token) Generate(t time.Time) string {
	u := t.Unix() / int64(token.period)
	// Message is eight-byte long byte array as determined in the spec
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
	h := hmac.New(algorithm, secret)
	h.Write(msg)
	mac := h.Sum(nil)
	i := int(mac[len(mac)-1]) & 0x0f
	n := 0
	n += int(mac[i+0]) & 0x7f << 0o30
	n += int(mac[i+1]) & 0xff << 0o20
	n += int(mac[i+2]) & 0xff << 0o10
	n += int(mac[i+3]) & 0xff << 0o00
	// Digits is guaranteed to be in the range of [minDigits, maxDigits]
	n %= int(math.Pow10(digits))
	// Prepare template string like "%06d"
	tpl := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(tpl, n)
}
