package ssh

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

func TestMarshalParseGMKexCertificateRoundTrip(t *testing.T) {
	signingPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(signing): %v", err)
	}
	encryptionPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(encryption): %v", err)
	}

	now := time.Unix(1_700_000_000, 0)
	signingCert, err := createGMKexCertificate(rand.Reader, &signingPriv.PublicKey, signingPriv, "test-signing", x509.KeyUsageDigitalSignature, now)
	if err != nil {
		t.Fatalf("createGMKexCertificate(signing): %v", err)
	}
	encryptionCert, err := createGMKexCertificate(rand.Reader, &encryptionPriv.PublicKey, encryptionPriv, "test-encryption", x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment, now)
	if err != nil {
		t.Fatalf("createGMKexCertificate(encryption): %v", err)
	}

	signingPub, err := NewPublicKey(&signingPriv.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey(signing): %v", err)
	}
	encryptionPub, err := NewPublicKey(&encryptionPriv.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey(encryption): %v", err)
	}

	certificate := marshalGMKexCertificate(signingCert, encryptionCert)
	gotSigning, gotEncryption, err := parseGMKexCertificate(certificate)
	if err != nil {
		t.Fatalf("parseGMKexCertificate() error: %v", err)
	}

	if !bytes.Equal(gotSigning.Marshal(), signingPub.Marshal()) {
		t.Fatal("parseGMKexCertificate() returned wrong signing key")
	}
	if !bytes.Equal(gotEncryption.Marshal(), encryptionPub.Marshal()) {
		t.Fatal("parseGMKexCertificate() returned wrong encryption key")
	}
}

func TestParseGMKexCertificateAcceptsLegacySingleKey(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	pub, err := NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey(): %v", err)
	}

	signingKey, encryptionKey, err := parseGMKexCertificate(pub.Marshal())
	if err != nil {
		t.Fatalf("parseGMKexCertificate() error: %v", err)
	}
	if !bytes.Equal(signingKey.Marshal(), pub.Marshal()) {
		t.Fatal("parseGMKexCertificate() returned wrong signing key for legacy single-key input")
	}
	if !bytes.Equal(encryptionKey.Marshal(), pub.Marshal()) {
		t.Fatal("parseGMKexCertificate() returned wrong encryption key for legacy single-key input")
	}
}

func TestParseGMKexCertificateAcceptsSingleCertificate(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	pub, err := NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey(): %v", err)
	}

	certificate, err := createGMKexCertificate(rand.Reader, &priv.PublicKey, priv, "test-single", x509.KeyUsageDigitalSignature, time.Unix(1_700_000_001, 0))
	if err != nil {
		t.Fatalf("createGMKexCertificate(): %v", err)
	}

	signingKey, encryptionKey, err := parseGMKexCertificate(certificate)
	if err != nil {
		t.Fatalf("parseGMKexCertificate() error: %v", err)
	}
	if !bytes.Equal(signingKey.Marshal(), pub.Marshal()) {
		t.Fatal("parseGMKexCertificate() returned wrong signing key for single-certificate input")
	}
	if !bytes.Equal(encryptionKey.Marshal(), pub.Marshal()) {
		t.Fatal("parseGMKexCertificate() returned wrong encryption key for single-certificate input")
	}
}

func TestGMKexHashUsesCertificateBlob(t *testing.T) {
	randomClient := []byte("random-client")
	randomServer := []byte("random-server")
	sessionKey := []byte("01234567890123456789012345678901")

	signingPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(signing): %v", err)
	}
	encryptionPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(encryption): %v", err)
	}

	certificate, err := func() ([]byte, error) {
		now := time.Unix(1_700_000_002, 0)
		signingCert, err := createGMKexCertificate(rand.Reader, &signingPriv.PublicKey, signingPriv, "hash-signing", x509.KeyUsageDigitalSignature, now)
		if err != nil {
			return nil, err
		}
		encryptionCert, err := createGMKexCertificate(rand.Reader, &encryptionPriv.PublicKey, encryptionPriv, "hash-encryption", x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment, now)
		if err != nil {
			return nil, err
		}
		return marshalGMKexCertificate(signingCert, encryptionCert), nil
	}()
	if err != nil {
		t.Fatalf("marshalGMKexCertificate(): %v", err)
	}

	signingPub, err := NewPublicKey(&signingPriv.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey(signing): %v", err)
	}

	h := sm3.New()
	h.Write(randomClient)
	h.Write(randomServer)
	h.Write(certificate)
	h.Write(sessionKey)
	got := h.Sum(nil)

	legacy := sm3.New()
	legacy.Write(randomClient)
	legacy.Write(randomServer)
	legacy.Write(signingPub.Marshal())
	legacy.Write(sessionKey)
	wantDifferent := legacy.Sum(nil)

	if bytes.Equal(got, wantDifferent) {
		t.Fatal("GM/T 0129 KEX hash unexpectedly matched legacy single-key host key blob hash")
	}
}

func TestEncryptGMKexSessionKeyUsesPlainCiphertext(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}

	sessionKey := []byte("01234567890123456789012345678901")
	encK, err := encryptGMKexSessionKey(rand.Reader, &priv.PublicKey, sessionKey)
	if err != nil {
		t.Fatalf("encryptGMKexSessionKey(): %v", err)
	}
	if len(encK) == 0 {
		t.Fatal("encryptGMKexSessionKey() returned empty ciphertext")
	}
	if encK[0] != 0x04 {
		t.Fatalf("encryptGMKexSessionKey() prefix = 0x%02x, want 0x04 plain SM2 ciphertext", encK[0])
	}

	got, err := sm2.Decrypt(priv, encK)
	if err != nil {
		t.Fatalf("Decrypt(): %v", err)
	}
	if !bytes.Equal(got, sessionKey) {
		t.Fatal("Decrypt() returned wrong session key")
	}
}

func TestSignGMKexReplyUsesRawDEROnWire(t *testing.T) {
	signer, algo := kexTestServerSigner(t, KeyExchangeSM2SM3)
	signedData := []byte("gm-kex-reply-signature")

	wireSig, marshaledSig, err := signGMKexReply(rand.Reader, signer, signedData, algo)
	if err != nil {
		t.Fatalf("signGMKexReply(): %v", err)
	}
	if len(wireSig) == 0 {
		t.Fatal("signGMKexReply() returned empty wire signature")
	}
	if _, _, ok := parseSignatureBody(wireSig); ok {
		t.Fatal("wire signature unexpectedly parsed as SSH signature blob")
	}

	sig, rest, ok := parseSignatureBody(marshaledSig)
	if !ok || len(rest) != 0 {
		t.Fatal("marshaled signature did not parse as SSH signature blob")
	}
	if sig.Format != KeyAlgoSM2 {
		t.Fatalf("signature format = %q, want %q", sig.Format, KeyAlgoSM2)
	}
	if !bytes.Equal(sig.Blob, wireSig) {
		t.Fatal("marshaled signature blob does not match wire DER signature")
	}

	if err := signer.PublicKey().Verify(signedData, sig); err != nil {
		t.Fatalf("Verify(): %v", err)
	}
}

func TestGMHostCertificateCallback(t *testing.T) {
	a, b, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe(): %v", err)
	}
	defer a.Close()
	defer b.Close()

	clientConf := &ClientConfig{
		Config: Config{
			KeyExchanges: []string{KeyExchangeSM2SM3},
		},
		HostKeyAlgorithms: []string{KeyAlgoSM2},
		HostKeyCallback:   InsecureIgnoreHostKey(),
	}

	callbackCalled := false
	clientConf.GMHostCertificateCallback = func(hostname string, remote net.Addr, signingCert, encryptionCert *smx509.Certificate) error {
		callbackCalled = true
		if hostname != "gm.example:22" {
			t.Fatalf("hostname = %q, want %q", hostname, "gm.example:22")
		}
		if remote == nil {
			t.Fatal("remote address is nil")
		}
		if signingCert == nil {
			t.Fatal("signing certificate is nil")
		}
		if encryptionCert == nil {
			t.Fatal("encryption certificate is nil")
		}
		signingKey, err := NewPublicKey(signingCert.PublicKey)
		if err != nil {
			t.Fatalf("NewPublicKey(signingCert): %v", err)
		}
		if signingKey.Type() != KeyAlgoSM2 {
			t.Fatalf("signing certificate key type = %q, want %q", signingKey.Type(), KeyAlgoSM2)
		}
		encryptionKey, err := NewPublicKey(encryptionCert.PublicKey)
		if err != nil {
			t.Fatalf("NewPublicKey(encryptionCert): %v", err)
		}
		if encryptionKey.Type() != KeyAlgoSM2 {
			t.Fatalf("encryption certificate key type = %q, want %q", encryptionKey.Type(), KeyAlgoSM2)
		}
		return nil
	}
	clientConf.SetDefaults()

	serverSigner, _ := kexTestServerSigner(t, KeyExchangeSM2SM3)
	serverConf := &ServerConfig{
		Config: Config{
			KeyExchanges: []string{KeyExchangeSM2SM3},
		},
	}
	serverConf.AddHostKey(serverSigner)
	serverConf.SetDefaults()

	v := []byte("version")
	client := newClientTransport(newTransport(a, rand.Reader, true), v, v, clientConf, "gm.example:22", a.RemoteAddr())
	server := newServerTransport(newTransport(b, rand.Reader, false), v, v, serverConf)
	defer client.Close()
	defer server.Close()

	if err := server.waitSession(); err != nil {
		t.Fatalf("server.waitSession(): %v", err)
	}
	if err := client.waitSession(); err != nil {
		t.Fatalf("client.waitSession(): %v", err)
	}
	if !callbackCalled {
		t.Fatal("GMHostCertificateCallback was not called")
	}
}

func TestRegisterGMKexCertificateBundle(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	signer, err := NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(): %v", err)
	}

	bundle, err := NewSelfSignedGMKexCertificateBundle(rand.Reader, signer, "registered-host")
	if err != nil {
		t.Fatalf("NewSelfSignedGMKexCertificateBundle(): %v", err)
	}

	cacheKey := string(signer.PublicKey().Marshal())
	gmKexCertificateCache.Delete(cacheKey)
	t.Cleanup(func() {
		gmKexCertificateCache.Delete(cacheKey)
	})

	if err := RegisterGMKexCertificateBundle(signer.PublicKey(), bundle); err != nil {
		t.Fatalf("RegisterGMKexCertificateBundle(): %v", err)
	}

	got, err := getGMKexCertificateBundle(rand.Reader, algorithmSignerWrapper{signer})
	if err != nil {
		t.Fatalf("getGMKexCertificateBundle(): %v", err)
	}
	if !bytes.Equal(got.CertificateBlob(), bundle.CertificateBlob()) {
		t.Fatal("registered GM/T 0129 certificate bundle was not reused")
	}
}

func TestRegisterGMKexCertificateBundleRejectsMismatchedHostKey(t *testing.T) {
	signingPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(signing): %v", err)
	}
	signingSigner, err := NewSignerFromKey(signingPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(signing): %v", err)
	}
	bundle, err := NewSelfSignedGMKexCertificateBundle(rand.Reader, signingSigner, "mismatch-host")
	if err != nil {
		t.Fatalf("NewSelfSignedGMKexCertificateBundle(): %v", err)
	}

	otherPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	otherSigner, err := NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(other): %v", err)
	}

	if err := RegisterGMKexCertificateBundle(otherSigner.PublicKey(), bundle); err == nil {
		t.Fatal("RegisterGMKexCertificateBundle() succeeded with mismatched host key")
	}
}
