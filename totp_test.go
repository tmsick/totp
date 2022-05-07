package totp

import (
	"fmt"
	"testing"
	"time"
)

func TestURIValidationInNewToken(t *testing.T) {
	cases := []struct {
		desc string
		uri  string
		ok   bool
	}{
		/* General */
		{
			desc: "Invalid URI should be rejected",
			uri:  "otpauth://hotp/exampleservice:exampleuser?secret=\t",
			ok:   false,
		},
		{
			desc: "Invalid scheme (!= \"otpauth\") should be rejected",
			uri:  "http://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			ok:   false,
		},
		{
			desc: "Invalid host (!= \"totp\") should be rejected",
			uri:  "otpauth://hotp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			ok:   false,
		},
		/* Secret */
		{
			desc: "Valid uppercase \"secret\" should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			ok:   true,
		},
		{
			desc: "Valid lowercase \"secret\" should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
			ok:   true,
		},
		{
			desc: "Empty \"secret\" should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=",
			ok:   false,
		},
		{
			desc: "URI without \"secret\" should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser",
			ok:   false,
		},
		{
			desc: "Invalid \"secret\" should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=01010101010101010101010101010101",
			ok:   false,
		},
		/* Label */
		{
			desc: "Empty \"label\" should be accepted",
			uri:  "otpauth://totp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			ok:   true,
		},
		/* Issuer */
		{
			desc: "Empty \"issuer\" should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=",
			ok:   true,
		},
		{
			desc: "Valid \"issuer\" should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=exampleservice",
			ok:   true,
		},
		/* Algorithm */
		{
			desc: "Valid \"algorithm\" (== \"SHA1\") should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1",
			ok:   true,
		},
		{
			desc: "Valid \"algorithm\" (== \"SHA256\") should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256",
			ok:   true,
		},
		{
			desc: "Valid \"algorithm\" (== \"SHA512\") should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA512",
			ok:   true,
		},
		{
			desc: "Empty \"algorithm\" should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=",
			ok:   false,
		},
		{
			desc: "Invalid \"algorithm\" (== \"MD5\") should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
			ok:   false,
		},
		/* Digits */
		{
			desc: "Empty \"digits\" should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=",
			ok:   false,
		},
		{
			desc: "Invalid \"digits\" (== \"foo\") should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=foo",
			ok:   false,
		},
		{
			desc: "Invalid \"digits\" (== 5) should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=5",
			ok:   false,
		},
		{
			desc: "Valid \"digits\" (== 6) should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6",
			ok:   true,
		},
		{
			desc: "Valid \"digits\" (== 8) should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
			ok:   true,
		},
		{
			desc: "Valid \"digits\" (== 10) should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=10",
			ok:   true,
		},
		{
			desc: "Invalid \"digits\" (== 11) should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=11",
			ok:   false,
		},
		/* Period */
		{
			desc: "Empty \"period\" should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=",
			ok:   false,
		},
		{
			desc: "Invalid \"period\" (== \"foo\") should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=foo",
			ok:   false,
		},
		{
			desc: "Invalid \"period\" (== 0) should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0",
			ok:   false,
		},
		{
			desc: "Valid \"period\" (== 1) should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=1",
			ok:   true,
		},
		{
			desc: "Valid \"period\" (== 45) should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=45",
			ok:   true,
		},
		{
			desc: "Valid \"period\" (== 90) should be accepted",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=90",
			ok:   true,
		},
		{
			desc: "Invalid \"period\" (== 91) should be rejected",
			uri:  "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=91",
			ok:   false,
		},
	}

	for _, c := range cases {
		_, err := NewToken(c.uri)
		if c.ok {
			// Didn't expect an error
			if err != nil {
				// ...but got one
				t.Errorf("[CASE] %v", c.desc)
				t.Errorf("Got unexpected error: %v", err)
			}
		} else {
			// Expected an error
			if err == nil {
				// ...but didn't get one
				t.Errorf("[CASE] %v", c.desc)
				t.Error("Expected an error but didn't get one")
			}
		}
	}
}

func TestDefaultValueAllocationInNewToken(t *testing.T) {
	uri := "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	tk, err := NewToken(uri)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
		return
	}

	if tk == nil {
		t.Error("NewToken() didn't return an error but the returned token is nil")
		return
	}

	if tk.Label() != "exampleservice:exampleuser" {
		t.Error("\"label\" has not been set properly in NewToken()")
	}

	if tk.Issuer() != "" {
		t.Error("\"issuer\" has not been set properly in NewToken()")
	}

	if tk.Algorithm() != "SHA1" {
		t.Error("\"algorithm\" has not been set properly in NewToken()")
	}

	if tk.Digits() != 6 {
		t.Error("\"digits\" has not been set properly in NewToken()")
	}

	if tk.Period() != 30 {
		t.Error("\"period\" has not been set properly in NewToken()")
	}
}

func TestGenerate(t *testing.T) {
	uriTpl := "otpauth://totp/exampleservice:exampleuser?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=%v&digits=%v"
	cases := []struct {
		time      string
		otp       string
		algorithm string
		digits    int
	}{
		// 1970-01-01T00:00:59Z
		{"1970-01-01T00:00:59Z", "94287082", "SHA1", 8},
		{"1970-01-01T00:00:59Z", "32247374", "SHA256", 8},
		{"1970-01-01T00:00:59Z", "69342147", "SHA512", 8},
		// 2005-03-18T01:58:29Z
		{"2005-03-18T01:58:29Z", "07081804", "SHA1", 8},
		{"2005-03-18T01:58:29Z", "34756375", "SHA256", 8},
		{"2005-03-18T01:58:29Z", "63049338", "SHA512", 8},
		// 2005-03-18T01:58:31Z
		{"2005-03-18T01:58:31Z", "14050471", "SHA1", 8},
		{"2005-03-18T01:58:31Z", "74584430", "SHA256", 8},
		{"2005-03-18T01:58:31Z", "54380122", "SHA512", 8},
		// 2009-02-13T23:31:30Z
		{"2009-02-13T23:31:30Z", "89005924", "SHA1", 8},
		{"2009-02-13T23:31:30Z", "42829826", "SHA256", 8},
		{"2009-02-13T23:31:30Z", "76671578", "SHA512", 8},
		// 2033-05-18T03:33:20Z
		{"2033-05-18T03:33:20Z", "69279037", "SHA1", 8},
		{"2033-05-18T03:33:20Z", "78428693", "SHA256", 8},
		{"2033-05-18T03:33:20Z", "56464532", "SHA512", 8},
		// 2603-10-11T11:33:20Z
		{"2603-10-11T11:33:20Z", "65353130", "SHA1", 8},
		{"2603-10-11T11:33:20Z", "24142410", "SHA256", 8},
		{"2603-10-11T11:33:20Z", "69481994", "SHA512", 8},
	}
	for i, c := range cases {
		tm, err := time.Parse(time.RFC3339, c.time)
		if err != nil {
			t.Fatalf("Invalid time string as RFC 3339 in testcase: %q", c.time)
		}

		uri := fmt.Sprintf(uriTpl, c.algorithm, c.digits)
		tk, err := NewToken(uri)
		if err != nil {
			t.Errorf("Got unexpected error: %v", err)
			continue
		}

		otp := tk.Generate(tm)
		if otp != c.otp {
			t.Errorf("OTP didn't match for testcase #%v. Expected: %q, Actual: %q", i+1, c.otp, otp)
		}

	}
}
