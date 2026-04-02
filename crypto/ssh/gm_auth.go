package ssh

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

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

func signGMUserAuthChallenge(rand io.Reader, signer AlgorithmSigner, sessionID []byte,
	user, service, method, algo string, challenge []byte) (certificate, signature []byte, err error) {
	certificate = signer.PublicKey().Marshal()
	signedData := buildGM0129SignedData(sessionID, user, service, method, algo, challenge, certificate)
	signature, err = signAndMarshal(signer, rand, signedData, algo)
	if err != nil {
		return nil, nil, err
	}
	return certificate, signature, nil
}

func verifyGMUserAuthChallengeSignature(hostKey PublicKey, sessionID []byte,
	user, service, method string, challenge *gmUserAuthChallengeMsg) error {
	if hostKey == nil {
		return errors.New("ssh: verified host key unavailable for GM/T 0129 challenge verification")
	}
	if len(challenge.Certificate) == 0 || len(challenge.Signature) == 0 {
		return errors.New("ssh: GM/T 0129 challenge missing certificate or signature")
	}

	certKey, err := ParsePublicKey(challenge.Certificate)
	if err != nil {
		return fmt.Errorf("ssh: invalid GM/T 0129 challenge certificate: %w", err)
	}
	if !bytes.Equal(certKey.Marshal(), hostKey.Marshal()) {
		return errors.New("ssh: GM/T 0129 challenge certificate does not match verified host key")
	}

	sig, rest, ok := parseSignatureBody(challenge.Signature)
	if !ok || len(rest) > 0 {
		return errors.New("ssh: invalid GM/T 0129 challenge signature")
	}

	signedData := buildGM0129SignedData(sessionID, user, service, method, certKey.Type(), challenge.Challenge, challenge.Certificate)
	if err := certKey.Verify(signedData, sig); err != nil {
		return fmt.Errorf("ssh: GM/T 0129 challenge signature verification failed: %w", err)
	}
	return nil
}

type gmParsedPasswordRespond struct {
	UserName      string
	ServiceName   string
	Method        string
	Response      []byte
	AlgorithmName string
}

func parseGMUserAuthPasswordRespond(packet []byte) (gmParsedPasswordRespond, error) {
	var strict gmUserAuthPasswordRespondMsg
	if err := Unmarshal(packet, &strict); err == nil {
		return gmParsedPasswordRespond{
			UserName:      strict.UserName,
			ServiceName:   strict.ServiceName,
			Method:        strict.Method,
			Response:      strict.Response,
			AlgorithmName: strict.AlgorithmName,
		}, nil
	}

	return gmParsedPasswordRespond{}, errors.New("ssh: invalid GM/T 0129 password respond packet")
}

func validateGMUserAuthPasswordRespond(resp gmParsedPasswordRespond, user, service string) error {
	if resp.UserName != user {
		return fmt.Errorf("ssh: GM/T 0129 password response user mismatch: got %q want %q", resp.UserName, user)
	}
	if resp.ServiceName != service {
		return fmt.Errorf("ssh: GM/T 0129 password response service mismatch: got %q want %q", resp.ServiceName, service)
	}
	if resp.Method != "password" {
		return fmt.Errorf("ssh: GM/T 0129 password response method mismatch: got %q want %q", resp.Method, "password")
	}
	if resp.AlgorithmName != "sm3" {
		return fmt.Errorf("ssh: GM/T 0129 password response algorithm mismatch: got %q want %q", resp.AlgorithmName, "sm3")
	}
	if len(resp.Response) == 0 {
		return errors.New("ssh: GM/T 0129 password response is empty")
	}
	return nil
}

func validateGMUserAuthRespond(resp *gmUserAuthRespondMsg, user, service string) error {
	if resp.UserName != user {
		return fmt.Errorf("ssh: GM/T 0129 public key response user mismatch: got %q want %q", resp.UserName, user)
	}
	if resp.ServiceName != service {
		return fmt.Errorf("ssh: GM/T 0129 public key response service mismatch: got %q want %q", resp.ServiceName, service)
	}
	if resp.Method != "public_key" {
		return fmt.Errorf("ssh: GM/T 0129 public key response method mismatch: got %q want %q", resp.Method, "public_key")
	}
	if resp.AlgorithmName != KeyAlgoSM2 {
		return fmt.Errorf("ssh: GM/T 0129 public key response algorithm mismatch: got %q want %q", resp.AlgorithmName, KeyAlgoSM2)
	}
	if len(resp.Response) == 0 {
		return errors.New("ssh: GM/T 0129 public key response is empty")
	}
	if len(resp.PublicKeyBlob) == 0 {
		return errors.New("ssh: GM/T 0129 public key response public key blob is empty")
	}
	return nil
}
