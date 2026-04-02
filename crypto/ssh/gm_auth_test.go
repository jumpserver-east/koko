package ssh

import (
	"bytes"
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
