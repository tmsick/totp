# TOTP

Go implementation of Time-Based One-Time Password Algorithm defined in [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238).

The key URI format used in this library is introduced in https://github.com/google/google-authenticator/wiki/Key-Uri-Format.

## Usage

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/tmsick/totp"
)

func main() {
	// Generate virtual token device based on parameters specified in URI
	uri := "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	token, err := totp.NewToken(uri)
	if err != nil {
		log.Fatal(err)
	}

	// Get current TOTP
	now := time.Now()
	totpstring := token.Generate(now)
	fmt.Println(totpstring)
}
```
