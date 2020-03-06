// +build darwin

package cert

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
)

var (
	certAdder  = addTrustedCert
	certFinder = findTrustedCert

	// ErrNotFoundInKeychain represents a hostkey not found in user keychain
	ErrNotFoundInKeychain = errors.New("item was nout found in keychain")

	// ErrNotImplemented represents an error in Settings implementation
	ErrNotImplemented = errors.New("type has not been implemented")
)

type Settings struct {
	CertFile        string       `security:"c" securitycmd:"verify-cert,add-trusted-cert,remove-trusted-cert"`
	RootCertFile    string       `security:"r" securitycmd:"verify-cert"`
	Policy          Policy       `security:"p" securitycmd:"verify-cert,add-trusted-cert"`
	Keychain        string       `security:"k" securitycmd:"verify-cert,add-trusted-cert"`
	NoKeychains     bool         `security:"n" securitycmd:"verify-cert"`
	LocalOnly       bool         `security:"L" securitycmd:"verify-cert"`
	IsLeaf          bool         `security:"l" securitycmd:"verify-cert"`
	EmailAddress    string       `security:"e" securitycmd:"verify-cert"`
	SSLHost         string       `security:"s" securitycmd:"verify-cert"`
	Quiet           bool         `security:"q" securitycmd:"verify-cert"`
	AddToAdmin      bool         `security:"d" securitycmd:"add-trusted-cert,remove-trusted-cert"`
	ResultType      ResultType   `security:"r" securitycmd:"add-trusted-cert"`
	AppPath         string       `security:"a" securitycmd:"add-trusted-cert"`
	PolicyString    string       `security:"s" securitycmd:"add-trusted-cert"`
	AllowedError    AllowedError `security:"e" securitycmd:"add-trusted-cert"`
	KeyUsage        string       `security:"u" securitycmd:"add-trusted-cert"`
	SettingsFileIn  string       `security:"i" securitycmd:"add-trusted-cert"`
	SettingsFileOut string       `security:"o" securitycmd:"add-trusted-cert"`
	DefaultSetting  bool         `security:"D" securitycmd:"add,remove-trusted-cert"`
}

type ResultType string
type Policy string
type AllowedError string

const (
	TRUST_ROOT    ResultType = "trustRoot"
	TRUST_AS_ROOT ResultType = "trustAsRoot"
	DENY          ResultType = "deny"
	UNSPECIFIED   ResultType = "unspecified"

	SSL           Policy = "ssl"
	SMIME         Policy = "smime"
	CODE_SIGN     Policy = "codeSign"
	IP_SEC        Policy = "IPSec"
	ICHAT         Policy = "iChat"
	BASIC         Policy = "basic"
	SW_UPDATE     Policy = "swUpdate"
	PKG_SIGN      Policy = "pkgSign"
	PKINIT_CLIENT Policy = "pkinitClient"
	PKINIT_SERVER Policy = "pkinitServer"
	EAP           Policy = "eap"

	CERT_EXPIRED      AllowedError = "certExpired"
	HOSTNAME_MISMATCH AllowedError = "hostnameMismatch"
)

// Marshal arranges Settings into command args
func (s *Settings) Marshal(subcommand string) ([]string, error) {
	var flags []string
	var arg string
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < v.NumField(); i++ {
		tagValue, ok := v.Type().Field(i).Tag.Lookup("security")
		if !ok || tagValue == "-" {
			continue
		}
		fieldValue := v.Field(i).Interface()
		fieldType := v.Field(i).Type()

		securitycmd, ok := v.Type().Field(i).Tag.Lookup("securitycmd")
		if !ok {
			continue
		}
		permitted := structFieldsPermitted(securitycmd)
		if _, ok := permitted[subcommand]; !ok {
			continue
		}

		switch fieldType.String() {
		case "cert.ResultType":
			fieldValue = string(fieldValue.(ResultType))
		case "cert.Policy":
			fieldValue = string(fieldValue.(Policy))
		case "cert.AllowedError":
			fieldValue = string(fieldValue.(AllowedError))
		}

		switch fieldType.String() {
		case "cert.ResultType":
			fallthrough
		case "cert.Policy":
			fallthrough
		case "cert.AllowedError":
			fallthrough
		case "string":
			if fieldValue.(string) == "" {
				continue
			}
			if (subcommand == "add-trusted-cert" || subcommand == "remove-trusted-cert") && tagValue == "c" {
				arg = fieldValue.(string)
			} else {
				flags = append(flags, []string{fmt.Sprintf("-%s", tagValue), fieldValue.(string)}...)
			}
		case "bool":
			if fieldValue.(bool) != true {
				continue
			}
			flags = append(flags, fmt.Sprintf("-%s", tagValue))
		default:
			return flags, ErrNotImplemented
		}
	}
	if arg != "" {
		flags = append(flags, arg)
	}
	return flags, nil
}

func structFieldsPermitted(tag string) map[string]bool {
	permitted := map[string]bool{}
	arr := strings.Split(tag, ",")
	for _, label := range arr {
		permitted[label] = true
	}
	return permitted
}

// AddTrustedCert runs security add-trusted-cert
func (s *Settings) AddTrustedCert() (string, error) {
	return s.execute("add-trusted-cert")
}

// RemoveTrustedCert runs security remove-trusted-cert
func (s *Settings) RemoveTrustedCert() (string, error) {
	return s.execute("remove-trusted-cert")
}

// VerifyCert runs security verify-cert
func (s *Settings) VerifyCert() (string, error) {
	return s.execute("verify-cert")
}

func (s *Settings) execute(subcommand string) (string, error) {
	args := []string{subcommand}
	settings, err := s.Marshal(subcommand)
	if err != nil {
		return "", err
	}
	args = append(args, settings...)
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err != nil {
		return "", errors.New(string(out))
	}
	return string(out), nil
}

// TODO cleanup

// AddVerification add the cert to OSX Keychain
func AddVerification(certificate string) error {
	temp, err := ioutil.TempFile("", "")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())

	_, err = temp.Write([]byte(certificate))
	if err != nil {
		return err
	}
	u, err := user.Current()
	if err != nil {
		return err
	}

	err = certFinder(temp.Name(), u.HomeDir)
	if err != nil && err != ErrNotFoundInKeychain {
		return err
	}
	if err == nil {
		return nil
	}

	output, err := certAdder(temp.Name(), u.HomeDir)
	if err != nil {
		return errors.New(string(output))
	}
	return nil
}

func addTrustedCert(tempCertFilename, homedir string) ([]byte, error) {
	keychain := filepath.Join(homedir, "Library", "Keychains", "login.keychain-db")
	return exec.Command("/usr/bin/security", "add-trusted-cert", "-p", "ssl", "-e", "hostnameMismatch", "-k", keychain, tempCertFilename).CombinedOutput()
}

func findTrustedCert(tempCertFilename, homedir string) error {
	cnameOutput, err := exec.Command("/usr/bin/openssl", "x509", "-noout", "-subject", "-in", tempCertFilename).CombinedOutput()
	if err != nil {
		return errors.New(string(cnameOutput))
	}
	cname := strings.Trim(strings.TrimPrefix(string(cnameOutput), "subject= /CN="), "\n")

	keychain := filepath.Join(homedir, "Library", "Keychains", "login.keychain-db")
	findOutput, err := exec.Command("/usr/bin/security", "find-certificate", "-c", cname, "-m", keychain).CombinedOutput()
	if err != nil {
		if strings.Contains(string(findOutput), "The specified item could not be found in the keychain.") {
			return ErrNotFoundInKeychain
		}
		return errors.New(string(findOutput))
	}
	return nil
}
