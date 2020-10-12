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
		{
			settings: &Settings{
				CertFile: "test.pem",
			},
			subcommand: "verify-cert",
			expected:   []string{"-c", "test.pem"},
		},
		{
			settings: &Settings{
				CertFile:    "test.pem",
				NoKeychains: true,
			},
			subcommand: "verify-cert",
			expected:   []string{"-c", "test.pem", "-n"},
		},
		{
			settings: &Settings{
				CertFile:     "test.pem",
				NoKeychains:  true,
				AllowedError: HOSTNAME_MISMATCH,
				Policy:       SSL,
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
