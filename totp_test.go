package totp

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"
)

func TestNewToken(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := []struct {
		uri string
		ok  bool
	}{
		{
			// omits all optional parameters
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v", secret),
			ok:  true,
		},
		{
			// "algorithm" is explicitly specified as "SHA1"
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&algorithm=SHA256", secret),
			ok:  true,
		},
		{
			// "digits" is explicitly specified as "6"
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&digits=8", secret),
			ok:  true,
		},
		{
			// "period" is explicitly specified as "30"
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&period=40", secret),
			ok:  true,
		},
		{
			// lacks required parameter "secret"
			uri: "otpauth://totp/exampleuser",
			ok:  false,
		},
		{
			// schema is not "otpauth"
			uri: fmt.Sprintf("http://totp/exampleuser?secret=%v", secret),
			ok:  false,
		},
		{
			// algorithm is not one of "SHA1", "SHA256", or "SHA512"
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&algorithm=MD5", secret),
			ok:  false,
		},
		{
			// "digits" is not a valid integer
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&digits=foo", secret),
			ok:  false,
		},
		{
			// "digits" is specified to be the smallest value available
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&digits=6", secret),
			ok:  true,
		},
		{
			// "digits" is too small
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&digits=5", secret),
			ok:  false,
		},
		{
			// "period" is specified to be the smallest value available
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&period=1", secret),
			ok:  true,
		},
		{
			// "period" is too small
			uri: fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&period=0", secret),
			ok:  false,
		},
	}
	for _, c := range cases {
		_, err := NewToken(c.uri)
		if c.ok && err != nil {
			t.Errorf("didn't expect an err but the code returned one. uri: %q", c.uri)
		} else if !c.ok && err == nil {
			t.Errorf("expected an err but the code didn't return one. uri: %q", c.uri)
		}
	}
}

func TestGenerate(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	uri := fmt.Sprintf("otpauth://totp/exampleuser?secret=%v&digits=8", secret)
	cases := []struct {
		time time.Time
		otp  string
	}{
		{
			time: time.Date(1970, time.January, 1, 0, 0, 59, 0, time.UTC),
			otp:  "94287082",
		},
		{
			time: time.Date(2005, time.March, 18, 1, 58, 29, 0, time.UTC),
			otp:  "07081804",
		},
		{
			time: time.Date(2005, time.March, 18, 1, 58, 31, 0, time.UTC),
			otp:  "14050471",
		},
		{
			time: time.Date(2009, time.February, 13, 23, 31, 30, 0, time.UTC),
			otp:  "89005924",
		},
		{
			time: time.Date(2033, time.May, 18, 03, 33, 20, 0, time.UTC),
			otp:  "69279037",
		},
		{
			time: time.Date(2603, time.October, 11, 11, 33, 20, 0, time.UTC),
			otp:  "65353130",
		},
	}
	for _, c := range cases {
		token, err := NewToken(uri)
		if err != nil {
			t.Error(err)
		}
		otp := token.Generate(c.time)
		if otp != c.otp {
			t.Errorf("time: %v, expected: %q, got: %q", c.time, c.otp, otp)
		}
	}
}
