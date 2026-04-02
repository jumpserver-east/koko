package ssh

import (
	"crypto/subtle"

	"github.com/emmansun/gmsm/sm3"
)

// GMPasswordResponse computes the GM/T 0129-2023 password auth response:
// SM3(challenge || SM3(password || salt)).
func GMPasswordResponse(password string, challenge, salt []byte) []byte {
	inner := sm3.New()
	inner.Write([]byte(password))
	inner.Write(salt)
	passwordWithSaltHash := inner.Sum(nil)

	outer := sm3.New()
	outer.Write(challenge)
	outer.Write(passwordWithSaltHash)
	return outer.Sum(nil)
}

// GMPasswordResponseMatches verifies whether response equals
// SM3(challenge || SM3(password || salt)).
func GMPasswordResponseMatches(password string, response, challenge, salt []byte) bool {
	expected := GMPasswordResponse(password, challenge, salt)
	return subtle.ConstantTimeCompare(expected, response) == 1
}
