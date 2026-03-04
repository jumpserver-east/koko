// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

// gmt0129KEX implements the GM/T 0129-2023 key exchange algorithm.
//
// Protocol flow:
//
//	Client → Server: msgGMKexRequest(200) {random_client}
//	Server → Client: msgGMKexReply(201)   {host_key, random_server, signature}
//	Client → Server: msgGMKex(202)        {SM2_Encrypt(K)}
//
// The server signs random_client||random_server (not H).
// H = SM3(random_client || random_server || host_key || K)
// K is a raw 32-byte random session key.
type gmt0129KEX struct{}

const gmt0129RandomSize = 8

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
	debugf(debugLevel3, "GM/T 0129: host_key length = %d bytes", len(reply.HostKey))
	debugf(debugLevel3, "GM/T 0129: signature length = %d bytes", len(reply.Signature))

	// 4. Parse host key to get SM2 public key
	hostKey, err := ParsePublicKey(reply.HostKey)
	if err != nil {
		return nil, err
	}
	debugf(debugLevel2, "GM/T 0129: server host key type: %s", hostKey.Type())

	cpk, ok := hostKey.(CryptoPublicKey)
	if !ok {
		return nil, errors.New("ssh: GM/T 0129 requires SM2 host key")
	}
	sm2Pub, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("ssh: GM/T 0129 requires SM2 host key")
	}
	debugf(debugLevel3, "GM/T 0129: SM2 public key curve: %s", sm2Pub.Curve.Params().Name)

	// 5. Generate K (32-byte random session key)
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rand, sessionKey); err != nil {
		return nil, err
	}
	debugf(debugLevel2, "GM/T 0129: generated 32-byte session key K")

	// 6. SM2 encrypt K with server's public key (ASN.1 DER per GB/T 35276)
	encK, err := sm2.EncryptASN1(rand, sm2Pub, sessionKey)
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

	// 8. Compute H = SM3(random_client || random_server || host_key || K)
	// H uses raw K bytes.
	h := sm3.New()
	h.Write(randomClient)
	h.Write(reply.RandomServer)
	h.Write(reply.HostKey)
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
	debugf(debugLevel2, "GM/T 0129: H = SM3(random_client || random_server || host_key || K)")
	debugf(debugLevel3, "GM/T 0129: H = %s", hex.EncodeToString(hSum))
	debugf(debugLevel2, "GM/T 0129: signature verification data = random_client || random_server (%d bytes)", len(signedData))
	debugf(debugLevel1, "GM/T 0129: client-side key exchange completed")

	return &kexResult{
		H:          hSum,
		K:          K,
		HostKey:    reply.HostKey,
		Signature:  reply.Signature,
		HashFunc:   sm3.New,
		SignedData: signedData,
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
	sig, err := signAndMarshal(priv, rand, signedData, algo)
	if err != nil {
		return nil, err
	}

	// 4. Send msgGMKexReply(201)
	hostKeyBytes := priv.PublicKey().Marshal()
	debugf(debugLevel1, "GM/T 0129: sending SSH_MSG_GM_KEX_REPLY(201)")
	if err := c.writePacket(Marshal(&gmKexReplyMsg{
		HostKey:      hostKeyBytes,
		RandomServer: randomServer,
		Signature:    sig,
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

	// 6. SM2 decrypt to get K
	// Unwrap algorithmSignerWrapper to get the underlying sm2Signer
	var decrypter SM2Decrypter
	switch s := priv.(type) {
	case SM2Decrypter:
		decrypter = s
	case algorithmSignerWrapper:
		if d, ok := s.Signer.(SM2Decrypter); ok {
			decrypter = d
		}
	}
	if decrypter == nil {
		return nil, errors.New("ssh: GM/T 0129 requires SM2 host key with decrypt capability")
	}

	sessionKey, err := decrypter.SM2Decrypt(kexMsg.EncryptedK)
	if err != nil {
		return nil, err
	}
	debugf(debugLevel2, "GM/T 0129: SM2 decrypted session key K (%d bytes)", len(sessionKey))

	// 7. Compute H = SM3(random_client || random_server || host_key || K)
	// H uses raw K bytes.
	h := sm3.New()
	h.Write(req.RandomClient)
	h.Write(randomServer)
	h.Write(hostKeyBytes)
	h.Write(sessionKey)

	// K in mpint format for key derivation.
	ki := new(big.Int).SetBytes(sessionKey)
	K := make([]byte, intLength(ki))
	marshalInt(K, ki)

	hSum := h.Sum(nil)
	debugf(debugLevel3, "GM/T 0129: H = %s", hex.EncodeToString(hSum))
	debugf(debugLevel1, "GM/T 0129: server-side key exchange completed")

	return &kexResult{
		H:         hSum,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		HashFunc:  sm3.New,
	}, nil
}
