package ssh

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestGMPasswordResponseUsesPasswordAndSaltInnerHash(t *testing.T) {
	challenge := []byte("challenge")
	salt := []byte("salt")
	password := "password"

	got := GMPasswordResponse(password, challenge, salt)

	inner := sm3.New()
	inner.Write([]byte(password))
	inner.Write(salt)
	passwordWithSaltHash := inner.Sum(nil)

	outer := sm3.New()
	outer.Write(challenge)
	outer.Write(passwordWithSaltHash)
	want := outer.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("GMPasswordResponse() mismatch: got %x want %x", got, want)
	}

	legacyInner := sm3.Sum([]byte(password))
	legacyOuter := sm3.New()
	legacyOuter.Write(challenge)
	legacyOuter.Write(legacyInner[:])
	legacyOuter.Write(salt)
	legacy := legacyOuter.Sum(nil)

	if bytes.Equal(got, legacy) {
		t.Fatalf("GMPasswordResponse() matched legacy formula: %x", got)
	}
}

func TestGMPasswordResponseMatches(t *testing.T) {
	challenge := []byte("challenge")
	salt := []byte("salt")
	password := "password"

	response := GMPasswordResponse(password, challenge, salt)
	if !GMPasswordResponseMatches(password, response, challenge, salt) {
		t.Fatal("GMPasswordResponseMatches() rejected a valid response")
	}

	tampered := append([]byte(nil), response...)
	tampered[0] ^= 0xff
	if GMPasswordResponseMatches(password, tampered, challenge, salt) {
		t.Fatal("GMPasswordResponseMatches() accepted a tampered response")
	}
}

func TestGMUserAuthChallengeSignatureRoundTrip(t *testing.T) {
	signer, ok := testSigners["ecdsa"].(AlgorithmSigner)
	if !ok {
		t.Fatal("ecdsa test signer does not implement AlgorithmSigner")
	}

	sessionID := []byte("session")
	challenge := []byte("challenge")
	certificate, signature, err := signGMUserAuthChallenge(rand.Reader, signer,
		sessionID, "user", serviceSSH, "password", signer.PublicKey().Type(), challenge)
	if err != nil {
		t.Fatalf("signGMUserAuthChallenge() error: %v", err)
	}

	msg := &gmUserAuthChallengeMsg{
		Challenge:   challenge,
		Certificate: certificate,
		Signature:   signature,
	}
	if err := verifyGMUserAuthChallengeSignature(signer.PublicKey(), sessionID, "user", serviceSSH, "password", msg); err != nil {
		t.Fatalf("verifyGMUserAuthChallengeSignature() error: %v", err)
	}
}

func TestGMUserAuthChallengeSignatureRejectsMismatchedHostKey(t *testing.T) {
	signer, ok := testSigners["ecdsa"].(AlgorithmSigner)
	if !ok {
		t.Fatal("ecdsa test signer does not implement AlgorithmSigner")
	}

	sessionID := []byte("session")
	challenge := []byte("challenge")
	certificate, signature, err := signGMUserAuthChallenge(rand.Reader, signer,
		sessionID, "user", serviceSSH, "password", signer.PublicKey().Type(), challenge)
	if err != nil {
		t.Fatalf("signGMUserAuthChallenge() error: %v", err)
	}

	msg := &gmUserAuthChallengeMsg{
		Challenge:   challenge,
		Certificate: certificate,
		Signature:   signature,
	}
	if err := verifyGMUserAuthChallengeSignature(testPublicKeys["rsa"], sessionID, "user", serviceSSH, "password", msg); err == nil {
		t.Fatal("verifyGMUserAuthChallengeSignature() accepted a mismatched host key")
	}
}

func TestParseGMUserAuthPasswordRespondStrict(t *testing.T) {
	packet := Marshal(&gmUserAuthPasswordRespondMsg{
		UserName:      "user",
		ServiceName:   serviceSSH,
		Method:        "password",
		Response:      []byte("response"),
		AlgorithmName: "sm3",
	})

	got, err := parseGMUserAuthPasswordRespond(packet)
	if err != nil {
		t.Fatalf("parseGMUserAuthPasswordRespond() error: %v", err)
	}
	if got.UserName != "user" || got.AlgorithmName != "sm3" {
		t.Fatalf("unexpected parsed strict packet: %+v", got)
	}
}

func TestParseGMUserAuthPasswordRespondRejectsLegacy(t *testing.T) {
	type legacyGMUserAuthPasswordRespondMsg struct {
		UserName      string `sshtype:"211"`
		ServiceName   string
		Method        string
		Response      []byte
		AlgorithmName string
		Password      string
	}

	packet := Marshal(&legacyGMUserAuthPasswordRespondMsg{
		UserName:      "user",
		ServiceName:   serviceSSH,
		Method:        "password",
		Response:      []byte("response"),
		AlgorithmName: "sm3",
		Password:      "secret",
	})

	if _, err := parseGMUserAuthPasswordRespond(packet); err == nil {
		t.Fatal("parseGMUserAuthPasswordRespond() accepted legacy packet with plaintext password")
	}
}

func TestValidateGMUserAuthPasswordRespondRejectsMismatchedMetadata(t *testing.T) {
	resp := gmParsedPasswordRespond{
		UserName:      "user",
		ServiceName:   serviceSSH,
		Method:        "password",
		Response:      []byte("response"),
		AlgorithmName: "sm3",
	}

	if err := validateGMUserAuthPasswordRespond(resp, "other", serviceSSH); err == nil {
		t.Fatal("validateGMUserAuthPasswordRespond() accepted mismatched user")
	}

	resp.UserName = "user"
	resp.AlgorithmName = "sha256"
	if err := validateGMUserAuthPasswordRespond(resp, "user", serviceSSH); err == nil {
		t.Fatal("validateGMUserAuthPasswordRespond() accepted mismatched algorithm")
	}
}

func TestValidateGMUserAuthRespondRejectsMismatchedMetadata(t *testing.T) {
	resp := &gmUserAuthRespondMsg{
		UserName:      "user",
		ServiceName:   serviceSSH,
		Method:        "public_key",
		Response:      []byte("signature"),
		AlgorithmName: KeyAlgoSM2,
		PublicKeyBlob: []byte("pubkey"),
	}

	if err := validateGMUserAuthRespond(resp, "other", serviceSSH); err == nil {
		t.Fatal("validateGMUserAuthRespond() accepted mismatched user")
	}

	resp.UserName = "user"
	resp.Method = "publickey"
	if err := validateGMUserAuthRespond(resp, "user", serviceSSH); err == nil {
		t.Fatal("validateGMUserAuthRespond() accepted mismatched method")
	}
}
