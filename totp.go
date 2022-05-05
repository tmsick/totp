package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	minDigits     = 6
	minPeriod     = 1
	defaultDigits = 6
	defaultPeriod = 30
)

type Token struct {
	Label     string
	Secret    []byte
	Issuer    string
	Algorithm func() hash.Hash
	Digits    int
	Period    int
}

func NewToken(uri string) (token Token, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return
	}
	if u.Scheme != "otpauth" {
		err = errors.New("scheme must be `otpauth'")
		return
	}
	if u.Host != "totp" {
		err = errors.New("host must be `totp'")
		return
	}
	if !u.Query().Has("secret") {
		err = errors.New("uri must have secret in query")
		return
	}

	// Set default values
	token.Algorithm = sha1.New
	token.Digits = defaultDigits
	token.Period = defaultPeriod

	for key, values := range u.Query() {
		for _, value := range values {
			switch key {
			case "secret":
				token.Secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(value))
				if err != nil {
					err = fmt.Errorf("got invalid secret. %q cannot be decoded as a base32 string", value)
					return
				}
			case "issuer":
				token.Issuer = value
			case "algorithm":
				switch value {
				case "SHA1":
					token.Algorithm = sha1.New
				case "SHA256":
					token.Algorithm = sha256.New
				case "SHA512":
					token.Algorithm = sha512.New
				default:
					err = errors.New("got invalid algorithm. valid values are: SHA1, SHA256, and SHA512")
					return
				}
			case "digits":
				digits, _err := strconv.Atoi(value)
				if _err != nil {
					err = fmt.Errorf("got invalid digits. %q cannot be converted into an integer", value)
					return
				}
				if digits < minDigits {
					err = fmt.Errorf("digits must be greater than or equal to %v. got %v", minDigits, digits)
					return
				}
				token.Digits = digits
			case "period":
				period, _err := strconv.Atoi(value)
				if _err != nil {
					err = fmt.Errorf("got invalid period. %q cannot be converted into an integer", value)
					return
				}
				if period < minPeriod {
					err = fmt.Errorf("period must be greater than or equal to %v. got %v", minPeriod, period)
					return
				}
				token.Period = period
			}
		}
	}
	return
}

func (token Token) Generate(t time.Time) string {
	u := t.Unix() / int64(token.Period)
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
	return hotp(msg, token.Secret, token.Algorithm, token.Digits)
}

func hotp(msg []byte, secret []byte, algorithm func() hash.Hash, digits int) string {
	h := hmac.New(algorithm, secret)
	h.Write(msg)
	mac := h.Sum(nil)
	i := int(mac[len(mac)-1]) & 0x0f
	n := 0
	n += int(mac[i+0]&0x7f) << 0o30
	n += int(mac[i+1]&0xff) << 0o20
	n += int(mac[i+2]&0xff) << 0o10
	n += int(mac[i+3]&0xff) << 0o00
	s := strconv.Itoa(n)
	for len(s) > digits {
		s = s[1:]
	}
	for len(s) < digits {
		s = "0" + s
	}
	return s
}
