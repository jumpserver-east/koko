// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

// gmt0129KEX implements the GM/T 0129-2023 key exchange algorithm.
//
// Protocol flow:
//
//	Client → Server: msgGMKexRequest(200) {random_client}
//	Server → Client: msgGMKexReply(201)   {certificate, random_server, signature}
//	Client → Server: msgGMKex(202)        {SM2_Encrypt(K)}
//
// The server signs random_client||random_server (not H).
// H = SM3(random_client || random_server || certificate || K)
// K is a raw 32-byte random session key.
type gmt0129KEX struct{}

const gmt0129RandomSize = 8

var gmKexSessionKeyEncrypterOpts = sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C3C2)

// GMKexCertificateBundle holds the signing/encryption certificate pair used by
// the GM/T 0129 key exchange reply.
type GMKexCertificateBundle struct {
	certificate    []byte
	signingCert    *smx509.Certificate
	encryptionCert *smx509.Certificate
	encryptionKey  *sm2.PrivateKey
}

var gmKexCertificateCache sync.Map

func marshalGMKexCertificate(signingCertificate, encryptionCertificate []byte) []byte {
	certificate := make([]byte, 0, len(signingCertificate)+len(encryptionCertificate))
	certificate = append(certificate, signingCertificate...)
	certificate = append(certificate, encryptionCertificate...)
	return certificate
}

func parseGMKexCertificate(certificate []byte) (signingKey, encryptionKey PublicKey, err error) {
	signingKey, encryptionKey, _, err = parseGMKexCertificateDetails(certificate)
	return signingKey, encryptionKey, err
}

func parseGMKexCertificateDetails(certificate []byte) (signingKey, encryptionKey PublicKey, certs []*smx509.Certificate, err error) {
	if len(certificate) > 0 && certificate[0] == 0x30 {
		certs, err = smx509.ParseCertificates(certificate)
		if err != nil {
			return nil, nil, nil, err
		}
		switch len(certs) {
		case 1:
			signingKey, err = newPublicKeyFromCertificate(certs[0])
			if err != nil {
				return nil, nil, nil, err
			}
			return signingKey, signingKey, certs, nil
		case 2:
			signingKey, err = newPublicKeyFromCertificate(certs[0])
			if err != nil {
				return nil, nil, nil, err
			}
			encryptionKey, err = newPublicKeyFromCertificate(certs[1])
			if err != nil {
				return nil, nil, nil, err
			}
			return signingKey, encryptionKey, certs, nil
		default:
			return nil, nil, nil, fmt.Errorf("ssh: expected 1 or 2 GM/T 0129 certificates, got %d", len(certs))
		}
	}

	signingKey, encryptionKey, err = parseLegacyGMKexCertificate(certificate)
	return signingKey, encryptionKey, nil, err
}

func newPublicKeyFromCertificate(cert *smx509.Certificate) (PublicKey, error) {
	key, err := NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ssh: unsupported GM/T 0129 certificate public key: %w", err)
	}
	return key, nil
}

func parseLegacyGMKexCertificate(certificate []byte) (signingKey, encryptionKey PublicKey, err error) {
	signingKey, rest, err := parsePublicKeyWithRest(certificate)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) == 0 {
		// Accept legacy single-key replies, but standard replies carry
		// signature and encryption keys concatenated in this field.
		return signingKey, signingKey, nil
	}

	encryptionKey, rest, err = parsePublicKeyWithRest(rest)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) > 0 {
		return nil, nil, errors.New("ssh: trailing junk in GM/T 0129 KEX certificate")
	}

	return signingKey, encryptionKey, nil
}

func parsePublicKeyWithRest(in []byte) (out PublicKey, rest []byte, err error) {
	algo, in, ok := parseString(in)
	if !ok {
		return nil, nil, errShortRead
	}

	return parsePubKey(in, string(algo))
}

func encryptGMKexSessionKey(rand io.Reader, pub *ecdsa.PublicKey, sessionKey []byte) ([]byte, error) {
	return sm2.Encrypt(rand, pub, sessionKey, gmKexSessionKeyEncrypterOpts)
}

func marshalGMKexReplySignature(format string, signature []byte) []byte {
	return Marshal(&Signature{
		Format: format,
		Blob:   append([]byte(nil), signature...),
	})
}

func signGMKexReply(rand io.Reader, signer AlgorithmSigner, data []byte, algo string) (wireSignature, marshaledSignature []byte, err error) {
	sig, err := signer.SignWithAlgorithm(rand, data, underlyingAlgo(algo))
	if err != nil {
		return nil, nil, err
	}
	wireSignature = append([]byte(nil), sig.Blob...)
	marshaledSignature = Marshal(sig)
	return wireSignature, marshaledSignature, nil
}

func (b *GMKexCertificateBundle) SigningCertificate() *smx509.Certificate {
	if b == nil {
		return nil
	}
	return b.signingCert
}

func (b *GMKexCertificateBundle) EncryptionCertificate() *smx509.Certificate {
	if b == nil {
		return nil
	}
	return b.encryptionCert
}

func (b *GMKexCertificateBundle) EncryptionKey() *sm2.PrivateKey {
	if b == nil {
		return nil
	}
	return b.encryptionKey
}

func (b *GMKexCertificateBundle) CertificateBlob() []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b.certificate...)
}

func validateGMKexCertificateBundle(hostKey PublicKey, bundle *GMKexCertificateBundle) error {
	if bundle == nil {
		return errors.New("ssh: GM/T 0129 certificate bundle is nil")
	}
	if bundle.signingCert == nil {
		return errors.New("ssh: GM/T 0129 signing certificate is nil")
	}
	if bundle.encryptionCert == nil {
		return errors.New("ssh: GM/T 0129 encryption certificate is nil")
	}
	if bundle.encryptionKey == nil {
		return errors.New("ssh: GM/T 0129 encryption private key is nil")
	}

	signingKey, err := newPublicKeyFromCertificate(bundle.signingCert)
	if err != nil {
		return err
	}
	if hostKey != nil && !bytes.Equal(signingKey.Marshal(), hostKey.Marshal()) {
		return errors.New("ssh: GM/T 0129 signing certificate does not match host key")
	}

	encryptionKey, err := newPublicKeyFromCertificate(bundle.encryptionCert)
	if err != nil {
		return err
	}
	encryptionPrivKey, err := NewPublicKey(&bundle.encryptionKey.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(encryptionKey.Marshal(), encryptionPrivKey.Marshal()) {
		return errors.New("ssh: GM/T 0129 encryption certificate does not match private key")
	}

	return nil
}

func newGMKexCertificateBundle(signingCert, encryptionCert *smx509.Certificate, encryptionKey *sm2.PrivateKey) (*GMKexCertificateBundle, error) {
	bundle := &GMKexCertificateBundle{
		certificate:    marshalGMKexCertificate(signingCert.Raw, encryptionCert.Raw),
		signingCert:    signingCert,
		encryptionCert: encryptionCert,
		encryptionKey:  encryptionKey,
	}
	if err := validateGMKexCertificateBundle(nil, bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}

// NewGMKexCertificateBundle creates a GM/T 0129 certificate bundle from two
// DER-encoded X.509 certificates and the matching encryption private key.
func NewGMKexCertificateBundle(signingCertificate, encryptionCertificate []byte, encryptionKey *sm2.PrivateKey) (*GMKexCertificateBundle, error) {
	signingCert, err := smx509.ParseCertificate(signingCertificate)
	if err != nil {
		return nil, fmt.Errorf("ssh: parse GM/T 0129 signing certificate: %w", err)
	}
	encryptionCert, err := smx509.ParseCertificate(encryptionCertificate)
	if err != nil {
		return nil, fmt.Errorf("ssh: parse GM/T 0129 encryption certificate: %w", err)
	}
	return newGMKexCertificateBundle(signingCert, encryptionCert, encryptionKey)
}

// NewSelfSignedGMKexCertificateBundle creates a self-signed GM/T 0129 dual
// certificate bundle for the provided SM2 host signer.
func NewSelfSignedGMKexCertificateBundle(rand io.Reader, signer Signer, commonName string) (*GMKexCertificateBundle, error) {
	signingSigner, err := extractGMKexSigner(signer)
	if err != nil {
		return nil, err
	}
	signingPub, ok := signingSigner.Public().(*ecdsa.PublicKey)
	if !ok || !sm2.IsSM2PublicKey(signingPub) {
		return nil, errors.New("ssh: GM/T 0129 requires SM2 signing key")
	}

	if commonName == "" {
		commonName = "gmssh-host"
	}

	now := time.Now()
	signingCertDER, err := createGMKexCertificate(rand, signingPub, signingSigner, commonName+" signing", x509.KeyUsageDigitalSignature, now)
	if err != nil {
		return nil, err
	}
	signingCert, err := smx509.ParseCertificate(signingCertDER)
	if err != nil {
		return nil, err
	}

	encryptionKey, err := sm2.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	encryptionCertDER, err := createGMKexCertificate(rand, &encryptionKey.PublicKey, encryptionKey, commonName+" encryption", x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment, now)
	if err != nil {
		return nil, err
	}
	encryptionCert, err := smx509.ParseCertificate(encryptionCertDER)
	if err != nil {
		return nil, err
	}

	return newGMKexCertificateBundle(signingCert, encryptionCert, encryptionKey)
}

// RegisterGMKexCertificateBundle binds a GM/T 0129 certificate bundle to a
// host key so the server uses it in SSH_MSG_GM_KEX_REPLY(201).
func RegisterGMKexCertificateBundle(hostKey PublicKey, bundle *GMKexCertificateBundle) error {
	if hostKey == nil {
		return errors.New("ssh: GM/T 0129 host key is nil")
	}
	if err := validateGMKexCertificateBundle(hostKey, bundle); err != nil {
		return err
	}
	gmKexCertificateCache.Store(string(hostKey.Marshal()), bundle)
	return nil
}

func getGMKexCertificateBundle(rand io.Reader, priv AlgorithmSigner) (*GMKexCertificateBundle, error) {
	cacheKey := string(priv.PublicKey().Marshal())
	if cached, ok := gmKexCertificateCache.Load(cacheKey); ok {
		return cached.(*GMKexCertificateBundle), nil
	}

	bundle, err := NewSelfSignedGMKexCertificateBundle(rand, priv, "gmssh")
	if err != nil {
		return nil, err
	}
	if cached, loaded := gmKexCertificateCache.LoadOrStore(cacheKey, bundle); loaded {
		return cached.(*GMKexCertificateBundle), nil
	}
	return bundle, nil
}

func createGMKexCertificate(rand io.Reader, pub *ecdsa.PublicKey, signer crypto.Signer, commonName string, keyUsage x509.KeyUsage, now time.Time) ([]byte, error) {
	template := &smx509.Certificate{
		Subject:            pkix.Name{CommonName: commonName},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(3650 * 24 * time.Hour),
		KeyUsage:           keyUsage,
		SignatureAlgorithm: smx509.SM2WithSM3,
	}
	return smx509.CreateCertificate(rand, template, template, pub, signer)
}

func extractGMKexCryptoSigner(priv AlgorithmSigner) (crypto.Signer, error) {
	switch s := priv.(type) {
	case *multiAlgorithmSigner:
		return extractGMKexCryptoSigner(s.AlgorithmSigner)
	case *wrappedSigner:
		return s.signer, nil
	case algorithmSignerWrapper:
		return extractGMKexSigner(s.Signer)
	default:
		return nil, errors.New("ssh: GM/T 0129 requires access to the SM2 signing key")
	}
}

func extractGMKexSigner(signer Signer) (crypto.Signer, error) {
	switch s := signer.(type) {
	case *multiAlgorithmSigner:
		return extractGMKexCryptoSigner(s.AlgorithmSigner)
	case *wrappedSigner:
		return s.signer, nil
	case algorithmSignerWrapper:
		return extractGMKexSigner(s.Signer)
	case *sm2Signer:
		return s.key, nil
	default:
		return nil, errors.New("ssh: GM/T 0129 requires access to the SM2 signing key")
	}
}

func (kex *gmt0129KEX) Client(c packetConn, rand io.Reader, magics *handshakeMagics) (*kexResult, error) {
	debugf(debugLevel1, "GM/T 0129: starting client-side key exchange")

	// 1. Generate random_client
	randomClient := make([]byte, gmt0129RandomSize)
	if _, err := io.ReadFull(rand, randomClient); err != nil {
		return nil, err
	}
	debugf(debugLevel3, "GM/T 0129: random_client = %s", hex.EncodeToString(randomClient))

	// 2. Send msgGMKexRequest(200)
	debugf(debugLevel1, "GM/T 0129: sending SSH_MSG_GM_KEX_REQUEST(200)")
	if err := c.writePacket(Marshal(&gmKexRequestMsg{
		RandomClient: randomClient,
	})); err != nil {
		return nil, err
	}

	// 3. Receive msgGMKexReply(201)
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	var reply gmKexReplyMsg
	if err := Unmarshal(packet, &reply); err != nil {
		return nil, err
	}
	debugf(debugLevel1, "GM/T 0129: received SSH_MSG_GM_KEX_REPLY(201)")
	debugf(debugLevel3, "GM/T 0129: random_server = %s", hex.EncodeToString(reply.RandomServer))
	debugf(debugLevel3, "GM/T 0129: certificate length = %d bytes", len(reply.Certificate))
	debugf(debugLevel3, "GM/T 0129: signature length = %d bytes", len(reply.Signature))

	signingKey, encryptionKey, hostCertificates, err := parseGMKexCertificateDetails(reply.Certificate)
	if err != nil {
		return nil, err
	}
	debugf(debugLevel2, "GM/T 0129: server signing key type: %s", signingKey.Type())
	debugf(debugLevel2, "GM/T 0129: server encryption key type: %s", encryptionKey.Type())

	cpk, ok := encryptionKey.(CryptoPublicKey)
	if !ok {
		return nil, errors.New("ssh: GM/T 0129 requires SM2 encryption key")
	}
	sm2Pub, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("ssh: GM/T 0129 requires SM2 encryption key")
	}
	debugf(debugLevel3, "GM/T 0129: SM2 public key curve: %s", sm2Pub.Curve.Params().Name)

	// 5. Generate K (32-byte random session key)
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand, sessionKey); err != nil {
		return nil, err
	}
	debugf(debugLevel2, "GM/T 0129: generated 32-byte session key K")

	// 6. SM2 encrypt K with the server's encryption certificate key.
	// GM/T 0129 packet captures use plain SM2 ciphertext on the wire.
	encK, err := encryptGMKexSessionKey(rand, sm2Pub, sessionKey)
	if err != nil {
		return nil, err
	}
	debugf(debugLevel2, "GM/T 0129: SM2 encrypted K (%d bytes ciphertext)", len(encK))

	// 7. Send msgGMKex(202)
	debugf(debugLevel1, "GM/T 0129: sending SSH_MSG_GM_KEX(202) with encrypted session key")
	if err := c.writePacket(Marshal(&gmKexMsg{
		EncryptedK: encK,
	})); err != nil {
		return nil, err
	}

	// 8. Compute H = SM3(random_client || random_server || certificate || K)
	// H uses raw K bytes.
	h := sm3.New()
	h.Write(randomClient)
	h.Write(reply.RandomServer)
	h.Write(reply.Certificate)
	h.Write(sessionKey)

	// 9. SignedData = random_client || random_server (for signature verification)
	signedData := make([]byte, 0, len(randomClient)+len(reply.RandomServer))
	signedData = append(signedData, randomClient...)
	signedData = append(signedData, reply.RandomServer...)

	// K in mpint format for key derivation.
	ki := new(big.Int).SetBytes(sessionKey)
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)

	hSum := h.Sum(nil)
	debugf(debugLevel2, "GM/T 0129: H = SM3(random_client || random_server || certificate || K)")
	debugf(debugLevel3, "GM/T 0129: H = %s", hex.EncodeToString(hSum))
	debugf(debugLevel2, "GM/T 0129: signature verification data = random_client || random_server (%d bytes)", len(signedData))
	debugf(debugLevel1, "GM/T 0129: client-side key exchange completed")

	return &kexResult{
		H:                hSum,
		K:                K,
		HostKey:          signingKey.Marshal(),
		Signature:        marshalGMKexReplySignature(signingKey.Type(), reply.Signature),
		HashFunc:         sm3.New,
		SignedData:       signedData,
		HostCertificates: hostCertificates,
	}, nil
}

func (kex *gmt0129KEX) Server(c packetConn, rand io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string) (*kexResult, error) {
	debugf(debugLevel1, "GM/T 0129: starting server-side key exchange")

	// 1. Receive msgGMKexRequest(200)
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	var req gmKexRequestMsg
	if err := Unmarshal(packet, &req); err != nil {
		return nil, err
	}
	debugf(debugLevel1, "GM/T 0129: received SSH_MSG_GM_KEX_REQUEST(200)")
	debugf(debugLevel3, "GM/T 0129: random_client = %s", hex.EncodeToString(req.RandomClient))

	// 2. Generate random_server
	randomServer := make([]byte, gmt0129RandomSize)
	if _, err := io.ReadFull(rand, randomServer); err != nil {
		return nil, err
	}
	debugf(debugLevel3, "GM/T 0129: random_server = %s", hex.EncodeToString(randomServer))

	// 3. Sign random_client || random_server
	signedData := make([]byte, 0, len(req.RandomClient)+len(randomServer))
	signedData = append(signedData, req.RandomClient...)
	signedData = append(signedData, randomServer...)

	debugf(debugLevel2, "GM/T 0129: signing random_client||random_server (%d bytes)", len(signedData))
	wireSig, sig, err := signGMKexReply(rand, priv, signedData, algo)
	if err != nil {
		return nil, err
	}

	// 4. Send msgGMKexReply(201)
	bundle, err := getGMKexCertificateBundle(rand, priv)
	if err != nil {
		return nil, err
	}
	hostKeyBytes := priv.PublicKey().Marshal()
	certificate := bundle.certificate
	debugf(debugLevel1, "GM/T 0129: sending SSH_MSG_GM_KEX_REPLY(201)")
	if err := c.writePacket(Marshal(&gmKexReplyMsg{
		Certificate:  certificate,
		RandomServer: randomServer,
		Signature:    wireSig,
	})); err != nil {
		return nil, err
	}

	// 5. Receive msgGMKex(202)
	packet, err = c.readPacket()
	if err != nil {
		return nil, err
	}
	var kexMsg gmKexMsg
	if err := Unmarshal(packet, &kexMsg); err != nil {
		return nil, err
	}
	debugf(debugLevel1, "GM/T 0129: received SSH_MSG_GM_KEX(202)")
	debugf(debugLevel3, "GM/T 0129: encrypted K length = %d bytes", len(kexMsg.EncryptedK))

	// 6. Use the encryption certificate's private key to unwrap K.
	sessionKey, err := sm2.Decrypt(bundle.encryptionKey, kexMsg.EncryptedK)
	if err != nil {
		return nil, err
	}
	debugf(debugLevel2, "GM/T 0129: SM2 decrypted session key K (%d bytes)", len(sessionKey))

	// 7. Compute H = SM3(random_client || random_server || certificate || K)
	// H uses raw K bytes.
	h := sm3.New()
	h.Write(req.RandomClient)
	h.Write(randomServer)
	h.Write(certificate)
	h.Write(sessionKey)

	// K in mpint format for key derivation.
	ki := new(big.Int).SetBytes(sessionKey)
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)

	hSum := h.Sum(nil)
	debugf(debugLevel3, "GM/T 0129: H = %s", hex.EncodeToString(hSum))
	debugf(debugLevel1, "GM/T 0129: server-side key exchange completed")

	return &kexResult{
		H:                hSum,
		K:                K,
		HostKey:          hostKeyBytes,
		Signature:        sig,
		HashFunc:         sm3.New,
		SignedData:       signedData,
		HostCertificates: []*smx509.Certificate{bundle.signingCert, bundle.encryptionCert},
	}, nil
}
