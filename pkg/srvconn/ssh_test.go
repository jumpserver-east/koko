package srvconn

import (
	"reflect"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	sshtestdata "golang.org/x/crypto/ssh/testdata"
)

func TestSSHClientConfigAttemptsPasswordFallback(t *testing.T) {
	cfg := &SSHClientOptions{
		Username: "root",
		Password: "secret",
		Timeout:  15,
	}

	attempts := cfg.clientConfigAttempts()
	if got, want := attemptLabels(attempts), []string{"gm", "classic"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("attempt labels = %v, want %v", got, want)
	}
	if got := attempts[0].config.ClientVersion; got != sshClientVersion {
		t.Fatalf("client version = %q, want %q", got, sshClientVersion)
	}
	if got := attempts[0].config.Config.KeyExchanges[0]; got != gossh.KeyExchangeSM2SM3 {
		t.Fatalf("preferred KEX = %q, want %q", got, gossh.KeyExchangeSM2SM3)
	}
}

func TestSSHClientConfigAttemptsClassicOnlyForKeyboardAuth(t *testing.T) {
	cfg := &SSHClientOptions{
		Username: "root",
		Timeout:  15,
		keyboardAuth: func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			return []string{"secret"}, nil
		},
	}

	attempts := cfg.clientConfigAttempts()
	if got, want := attemptLabels(attempts), []string{"classic"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("attempt labels = %v, want %v", got, want)
	}
}

func TestSSHClientConfigAttemptsSkipGMForRSAPrivateKey(t *testing.T) {
	cfg := &SSHClientOptions{
		Username:   "root",
		PrivateKey: string(sshtestdata.PEMBytes["rsa"]),
		Timeout:    15,
	}

	attempts := cfg.clientConfigAttempts()
	if got, want := attemptLabels(attempts), []string{"classic"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("attempt labels = %v, want %v", got, want)
	}
}

func attemptLabels(attempts []sshClientAttempt) []string {
	labels := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		labels = append(labels, attempt.label)
	}
	return labels
}
