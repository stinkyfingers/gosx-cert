// +build darwin

package cert

import (
	"reflect"
	"testing"
)

func TestMarshal(t *testing.T) {
	tests := []struct {
		settings   *Settings
		subcommand string
		expected   []string
	}{
		// {
		// 	settings: &Settings{
		// 		CertFile: "test.pem",
		// 	},
		// 	subcommand: "verify-cert",
		// 	expected:   []string{"-c", "test.pem"},
		// },
		// {
		// 	settings: &Settings{
		// 		CertFile:    "test.pem",
		// 		NoKeychains: true,
		// 	},
		// 	subcommand: "verify-cert",
		// 	expected:   []string{"-c", "test.pem", "-n"},
		// },
		{
			settings: &Settings{
				CertFile:     "test.pem",
				NoKeychains:  true,
				AllowedError: "hostnameMismatch",
				Policy:       "ssl",
				ResultType:   TRUST_AS_ROOT,
			},
			subcommand: "add-trusted-cert",
			expected:   []string{"-p", "ssl", "-r", "trustAsRoot", "-e", "hostnameMismatch", "test.pem"},
		},
	}

	for _, test := range tests {
		out, err := test.settings.Marshal(test.subcommand)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(test.expected, out) {
			t.Errorf("expected %v, got %v", test.expected, out)
		}
	}
}

// func TestAddVerification(t *testing.T) {
// 	var expectedHomeDir, expectedTempCertFilename string
// 	certAdder = func(tempCertFilename, homedir string) ([]byte, error) {
// 		expectedHomeDir = homedir
// 		expectedTempCertFilename = tempCertFilename
// 		return nil, nil
// 	}
//
// 	certFinder = func(tempCertFilename, homedir string) error {
// 		return ErrNotFoundInKeychain
// 	}
//
// 	err := AddVerification("testcert")
// 	if err != nil {
// 		t.Error(err)
//
// 	}
// 	u, err := user.Current()
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	if !strings.Contains(expectedHomeDir, u.HomeDir) {
// 		t.Error("expected homedir")
// 	}
// 	if expectedTempCertFilename == "" {
// 		t.Error("expected tempCertFilename to have been populated")
// 	}
// }
//
// func TestAddVerificationHostkeyFound(t *testing.T) {
// 	var expectedHomeDir, expectedTempCertFilename string
// 	certAdder = func(tempCertFilename, homedir string) ([]byte, error) {
// 		expectedHomeDir = homedir
// 		expectedTempCertFilename = tempCertFilename
// 		return nil, nil
// 	}
//
// 	certFinder = func(tempCertFilename, homedir string) error {
// 		return nil
// 	}
//
// 	err := AddVerification("testcert")
// 	if err != nil {
// 		t.Error(err)
//
// 	}
// 	if expectedHomeDir != "" {
// 		t.Error("expected homedir to not have been populated")
// 	}
// 	if expectedTempCertFilename != "" {
// 		t.Error("expected tempCertFilename to not have been populated")
// 	}
// }
