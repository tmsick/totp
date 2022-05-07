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
	digitsDefault = 6
	digitsMax     = 10
	digitsMin     = 6
	periodDefault = 30
	periodMax     = 90
	periodMin     = 1
)

type algorithm struct {
	name string
	proc func() hash.Hash
}

// A Token represents a virtual TOTP token that generates a Time-Based One-Time Password defined in RFC 6238.
type Token struct {
	label     string
	secret    []byte
	issuer    string
	algorithm algorithm
	digits    int
	period    int
}

var (
	algorithmSHA1    algorithm = algorithm{"SHA1", sha1.New}
	algorithmSHA256  algorithm = algorithm{"SHA256", sha256.New}
	algorithmSHA512  algorithm = algorithm{"SHA512", sha512.New}
	algorithmDefault algorithm = algorithmSHA1
)

// NewToken returns a new virtual TOTP token with parameters specified by a Key URI.
// The Key URI format is defined in https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
//
// Users of this library have to specify at least `secret` in query parameter as defined in the spec.
// Other parameters have default values like below:
//   * issuer    = ""
//   * algorithm = "SHA1" (Other available options are "SHA256" and "SHA512")
//   * digits    = 6
//   * period    = 30
//
// `digits` and `period` have a limited range as below:
//   * 6 <= digits <= 10
//   * 1 <= period <= 90
//
// NewToken doesn't panic and merely returns an error should there be any violation in a Key URI passed.
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
	t := &Token{
		algorithm: algorithmDefault,
		digits:    digitsDefault,
		period:    periodDefault,
	}

	// Process label
	// `u.Path` might contain leading or trailing slashes.
	t.label = strings.Trim(u.Path, "/")

	// Process secret [REQUIRED]
	if u.Query().Has("secret") {
		rawSecret := u.Query().Get("secret")
		// Empty string is unfortunately treated as a valid Base32 string by encoding/base32.
		if rawSecret == "" {
			return nil, fmt.Errorf("Secret is empty. URI: %q", uri)
		}
		upperSecret := strings.ToUpper(rawSecret)
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(upperSecret)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode secret value %q as Base32 string. URI: %q", rawSecret, uri)
		}
		t.secret = secret
	} else {
		return nil, fmt.Errorf("Secret is required in query parameter. URI: %q", uri)
	}

	// Process issuer [OPTIONAL]
	if u.Query().Has("issuer") {
		t.issuer = u.Query().Get("issuer")
	}

	// Process algorithm [OPTIONAL]
	if u.Query().Has("algorithm") {
		rawAlgorithm := u.Query().Get("algorithm")
		switch rawAlgorithm {
		case "SHA1":
			t.algorithm = algorithmSHA1
		case "SHA256":
			t.algorithm = algorithmSHA256
		case "SHA512":
			t.algorithm = algorithmSHA512
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
		if digits < digitsMin || digits > digitsMax {
			return nil, fmt.Errorf("Digits have to be in the range of [%v, %v]. Got %v. URI: %q", digitsMin, digitsMax, digits, uri)
		}
		t.digits = digits
	}

	// Process period [OPTIONAL]
	if u.Query().Has("period") {
		rawPeriod := u.Query().Get("period")
		period, err := strconv.Atoi(rawPeriod)
		if err != nil {
			return nil, fmt.Errorf("Period %q cannot be converted into an integer. URI: %q", rawPeriod, uri)
		}
		if period < periodMin || period > periodMax {
			return nil, fmt.Errorf("Period have to be in the range of [%v, %v]. Got %v. URI: %q", periodMin, periodMax, period, uri)
		}
		t.period = period
	}

	return t, nil
}

// Label returns the label part of the Key URI without leading or trailing slashes.
func (t *Token) Label() string {
	return t.label
}

// Issuer returns the issuer value of the Key URI.
func (t *Token) Issuer() string {
	return t.issuer
}

// Algorithm returns the hash function name used to generate TOTPs.
// It should return "SHA1", "SHA256", or "SHA512".
func (t *Token) Algorithm() string {
	return t.algorithm.name
}

// Digits returns the number of digits OTPs have.
func (t *Token) Digits() int {
	return t.digits
}

// Period returns the time duration in seconds a TOTP lives.
func (t *Token) Period() int {
	return t.period
}

// Generate returns a TOTP value calculated with the token's parameters and a specified time.
func (t *Token) Generate(m time.Time) string {
	// `t.period` is guaranteed to be positive.
	u := m.Unix() / int64(t.period)

	// According to RFC 4226, `msg` is a 8-byte-long bytearray.
	// https://tools.ietf.org/html/rfc4226#section-5.1
	msg := make([]byte, 8)
	msg[0] = byte(u & 0x_7f_00_00_00_00_00_00_00 >> 0o70)
	msg[1] = byte(u & 0x_00_ff_00_00_00_00_00_00 >> 0o60)
	msg[2] = byte(u & 0x_00_00_ff_00_00_00_00_00 >> 0o50)
	msg[3] = byte(u & 0x_00_00_00_ff_00_00_00_00 >> 0o40)
	msg[4] = byte(u & 0x_00_00_00_00_ff_00_00_00 >> 0o30)
	msg[5] = byte(u & 0x_00_00_00_00_00_ff_00_00 >> 0o20)
	msg[6] = byte(u & 0x_00_00_00_00_00_00_ff_00 >> 0o10)
	msg[7] = byte(u & 0x_00_00_00_00_00_00_00_ff >> 0o00)

	return hotp(msg, t.secret, t.algorithm.proc, t.digits)
}

func hotp(msg []byte, secret []byte, algorithm func() hash.Hash, digits int) string {
	// Generate an HMAC-SHA1, -SHA256, or -SHA512 value with `msg` and `secret`.
	h := hmac.New(algorithm, secret)
	// `h.Write()` never returns an error and it's OK to ignore the return value.
	// ref: https://pkg.go.dev/hash
	h.Write(msg)
	mac := h.Sum(nil)

	// Start Dynamic Truncation (DT) defined in RFC 4226.
	// https://tools.ietf.org/html/rfc4226#section-5.3
	i := int(mac[len(mac)-1]) & 0x0f

	// It is safe to naively access `mac[i+0]`...`mac[i+3]` because `i` is in the range of [0, 15] and `mac` has the
	// result of HMAC-SHA1, -SHA256, or -SHA512, whose length is at least 20 bytes, 32 bytes, or 64 bytes respectively.
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
