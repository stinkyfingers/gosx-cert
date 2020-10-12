### Summary

`gosx-cert` provides a quick means to add, verify, and remove certificates to your OSX Keychain.

### Quickstart

1. Create a self-signed certificate:

`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365`

1. Godoc: https://godoc.org/github.com/stinkyfingers/gosx-cert

1. Add cert to and remove cert from your keychain:

```
package main

import (
	"fmt"
	"log"
	"os/user"
	"path/filepath"

	cert "github.com/stinkyfingers/gosx-cert"
)

func main() {
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	s := &cert.Settings{
		CertFile:     "cert.pem",
		AllowedError: cert.HOSTNAME_MISMATCH,
		Keychain:     filepath.Join(u.HomeDir, "Library", "Keychains", "login.keychain-db"),
		Policy:       cert.SSL,
	}
	_, err := s.AddTrustedCert()
	if err != nil {
		log.Fatal(err)
	}
	_, err = s.RemoveTrustedCert()
	if err != nil {
		log.Fatal(err)
	}
}
```
