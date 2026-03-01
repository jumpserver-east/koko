// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

// sm2ECDH performs SM2 Elliptic Curve Diffie-Hellman key exchange
// using the SM2 P256 curve with SM3 as the hash function.
type sm2ECDH struct{}

func (kex *sm2ECDH) Client(c packetConn, rand io.Reader, magics *handshakeMagics) (*kexResult, error) {
	curve := sm2.P256()

	ephKey, err := ecdsa.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}

	kexInit := kexECDHInitMsg{
		ClientPubKey: elliptic.Marshal(curve, ephKey.PublicKey.X, ephKey.PublicKey.Y),
	}

	serialized := Marshal(&kexInit)
	if err := c.writePacket(serialized); err != nil {
		return nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var reply kexECDHReplyMsg
	if err = Unmarshal(packet, &reply); err != nil {
		return nil, err
	}

	x, y, err := unmarshalSM2ECKey(curve, reply.EphemeralPubKey)
	if err != nil {
		return nil, err
	}

	// generate shared secret using SM2KAP
	peerPub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	byteLen := (curve.Params().BitSize + 7) / 8
	kdfKey, err := sm2KAPComputeKey(ephKey, peerPub, false, byteLen)
	if err != nil {
		return nil, err
	}
	secret := new(big.Int).SetBytes(kdfKey)

	h := sm3.New()
	magics.write(h)
	writeString(h, reply.HostKey)
	writeString(h, kexInit.ClientPubKey)
	writeString(h, reply.EphemeralPubKey)
	K := make([]byte, intLength(secret))
	marshalInt(K, secret)
	h.Write(K)

	return &kexResult{
		H:        h.Sum(nil),
		K:        K,
		HostKey:  reply.HostKey,
		Signature: reply.Signature,
		HashFunc: sm3.New,
	}, nil
}

func (kex *sm2ECDH) Server(c packetConn, rand io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string) (result *kexResult, err error) {
	curve := sm2.P256()

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexECDHInit kexECDHInitMsg
	if err = Unmarshal(packet, &kexECDHInit); err != nil {
		return nil, err
	}

	clientX, clientY, err := unmarshalSM2ECKey(curve, kexECDHInit.ClientPubKey)
	if err != nil {
		return nil, err
	}

	// We could cache this key across multiple users/multiple
	// connection attempts, but the benefit is small. OpenSSH
	// generates a new key for each incoming connection.
	ephKey, err := ecdsa.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}

	hostKeyBytes := priv.PublicKey().Marshal()

	serializedEphKey := elliptic.Marshal(curve, ephKey.PublicKey.X, ephKey.PublicKey.Y)

	// generate shared secret using SM2KAP
	clientPub := &ecdsa.PublicKey{Curve: curve, X: clientX, Y: clientY}
	byteLen := (curve.Params().BitSize + 7) / 8
	kdfKey, err := sm2KAPComputeKey(ephKey, clientPub, true, byteLen)
	if err != nil {
		return nil, err
	}
	secret := new(big.Int).SetBytes(kdfKey)

	h := sm3.New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	writeString(h, kexECDHInit.ClientPubKey)
	writeString(h, serializedEphKey)

	K := make([]byte, intLength(secret))
	marshalInt(K, secret)
	h.Write(K)

	H := h.Sum(nil)

	// H is already a hash, but the hostkey signing will apply its
	// own key-specific hash algorithm.
	sig, err := signAndMarshal(priv, rand, H, algo)
	if err != nil {
		return nil, err
	}

	reply := kexECDHReplyMsg{
		EphemeralPubKey: serializedEphKey,
		HostKey:         hostKeyBytes,
		Signature:       sig,
	}

	serialized := Marshal(&reply)
	if err := c.writePacket(serialized); err != nil {
		return nil, err
	}

	return &kexResult{
		H:        H,
		K:        K,
		HostKey:  reply.HostKey,
		Signature: sig,
		HashFunc: sm3.New,
	}, nil
}

// sm2KAPComputeKey computes the shared secret using SM2 Key Agreement Protocol
// (SM2KAP) per GM/T 0003-2012, with static key = ephemeral key.
func sm2KAPComputeKey(localPriv *ecdsa.PrivateKey, peerPub *ecdsa.PublicKey, isServer bool, keyLen int) ([]byte, error) {
	curve := sm2.P256()
	N := curve.Params().N

	// w = ceil(ceil(log2(n)) / 2) - 1 = (N.BitLen() + 1) / 2 - 1
	w := uint((N.BitLen()+1)/2 - 1) // 127 for SM2

	// avf(x) = 2^w + (x & (2^w - 1))
	pow2w := new(big.Int).Lsh(big.NewInt(1), w)
	mask := new(big.Int).Sub(pow2w, big.NewInt(1))

	localAvf := new(big.Int).And(localPriv.PublicKey.X, mask)
	localAvf.Add(localAvf, pow2w)

	peerAvf := new(big.Int).And(peerPub.X, mask)
	peerAvf.Add(peerAvf, pow2w)

	// t = (d + avf(localPub.X) * d) mod N
	// Since static key = ephemeral key, d_A = r_A = d
	t := new(big.Int).Mul(localAvf, localPriv.D)
	t.Add(t, localPriv.D)
	t.Mod(t, N)

	// base point = peerPub + [avf(peerPub.X)] * peerPub
	bx, by := curve.ScalarMult(peerPub.X, peerPub.Y, peerAvf.Bytes())
	bx, by = curve.Add(peerPub.X, peerPub.Y, bx, by)

	// V = [t] * base_point
	vx, vy := curve.ScalarMult(bx, by, t.Bytes())

	if vx.Sign() == 0 && vy.Sign() == 0 {
		return nil, errors.New("ssh: SM2KAP computed point at infinity")
	}

	// Compute ZA (client Z) and ZB (server Z)
	// UID must match openEuler OpenSSH: raw bytes {1,2,...,8,1,2,...,8}, NOT ASCII "1234567812345678"
	defaultUID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}

	var clientPub, serverPub *ecdsa.PublicKey
	if isServer {
		clientPub = peerPub
		serverPub = &localPriv.PublicKey
	} else {
		clientPub = &localPriv.PublicKey
		serverPub = peerPub
	}

	za, err := sm2.CalculateZA(clientPub, defaultUID)
	if err != nil {
		return nil, err
	}
	zb, err := sm2.CalculateZA(serverPub, defaultUID)
	if err != nil {
		return nil, err
	}

	// Derive shared key = sm3.Kdf(V.X || V.Y || ZA || ZB, keyLen)
	byteSize := (curve.Params().BitSize + 7) / 8
	vxBytes := make([]byte, byteSize)
	vyBytes := make([]byte, byteSize)
	vxBuf := vx.Bytes()
	vyBuf := vy.Bytes()
	copy(vxBytes[byteSize-len(vxBuf):], vxBuf)
	copy(vyBytes[byteSize-len(vyBuf):], vyBuf)

	z := make([]byte, 0, len(vxBytes)+len(vyBytes)+len(za)+len(zb))
	z = append(z, vxBytes...)
	z = append(z, vyBytes...)
	z = append(z, za...)
	z = append(z, zb...)

	return sm3.Kdf(z, keyLen), nil
}

// unmarshalSM2ECKey parses and checks an SM2 EC key.
func unmarshalSM2ECKey(curve elliptic.Curve, pubkey []byte) (x, y *big.Int, err error) {
	x, y = elliptic.Unmarshal(curve, pubkey)
	if x == nil {
		return nil, nil, errors.New("ssh: elliptic.Unmarshal failure for SM2 key")
	}
	if !validateECPublicKey(curve, x, y) {
		return nil, nil, errors.New("ssh: SM2 public key not on curve")
	}
	return x, y, nil
}
