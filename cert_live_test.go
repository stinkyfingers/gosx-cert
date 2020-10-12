// +build darwin

package cert

// TODO

// import (
// 	"os"
// 	"os/user"
// 	"testing"
// )
//
// func TestLiveAdd(t *testing.T) {
// 	if os.Getenv("CERT_ENV") != "live" {
// 		t.Skip("requires live environment; CERT_ENV=live")
// 	}
// 	u, err := user.Current()
// 	if err != nil {
// 		t.Error(err)
// 	}
//
// 	out, err := addTrustedCert("certificate.pem", u.HomeDir)
// 	t.Log(string(out))
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	if out == nil {
// 		t.Error("expected out")
// 	}
// }
//
// func TestLiveVerify(t *testing.T) {
// 	if os.Getenv("CERT_ENV") != "live" {
// 		t.Skip("requires live environment; CERT_ENV=live")
// 	}
// 	s := &Settings{
// 		CertFile: "certificate.pem",
// 	}
// 	out, err := s.VerifyCert()
// 	t.Log(string(out))
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	if out == "" {
// 		t.Error("expected out")
// 	}
// }
