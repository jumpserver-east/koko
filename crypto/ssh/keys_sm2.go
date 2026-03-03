// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"

	"github.com/emmansun/gmsm/sm2"
)

const sm2CurveName = "sm2"

// sm2PublicKey implements the PublicKey interface for SM2 keys.
// 符合 GM/T 0009-2012 和 GM/T 0129-2023 规范
type sm2PublicKey struct {
	key ecdsa.PublicKey
}

func (k *sm2PublicKey) Type() string {
	return KeyAlgoSM2
}

func (k *sm2PublicKey) Marshal() []byte {
	// SSH wire format: string "ssh-sm2", string "sm2p256v1", string point
	keyBytes := elliptic.Marshal(k.key.Curve, k.key.X, k.key.Y)
	w := struct {
		Name string
		ID   string
		Key  []byte
	}{
		KeyAlgoSM2,
		sm2CurveName,
		keyBytes,
	}
	return Marshal(&w)
}

func (k *sm2PublicKey) Verify(data []byte, sig *Signature) error {
	if sig.Format != k.Type() {
		return errors.New("ssh: signature type mismatch for SM2 key")
	}

	// 使用 GM/T 0009-2012 规范的 SM2 签名验证
	if !sm2.VerifyASN1WithSM2(&k.key, nil, data, sig.Blob) {
		return errors.New("ssh: SM2 signature verification failed")
	}

	return nil
}

func (k *sm2PublicKey) CryptoPublicKey() crypto.PublicKey {
	return &k.key
}

// 辅助方法：获取 SM2 密钥的压缩格式
func (k *sm2PublicKey) MarshalCompressed() []byte {
	// SM2 压缩格式：1字节前缀(0x02或0x03) + x坐标
	prefix := byte(0x02)
	if k.key.Y.Bit(0) != 0 {
		prefix = 0x03
	}

	xBytes := k.key.X.Bytes()
	if len(xBytes) < 32 {
		// 确保长度为 32 字节，左填充零
		padding := make([]byte, 32-len(xBytes))
		xBytes = append(padding, xBytes...)
	} else if len(xBytes) > 32 {
		// 截取前 32 字节
		xBytes = xBytes[len(xBytes)-32:]
	}

	return append([]byte{prefix}, xBytes...)
}

// parseSM2 parses an SM2 public key from SSH wire format.
func parseSM2(in []byte) (out PublicKey, rest []byte, err error) {
	var w struct {
		Curve    string
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	if w.Curve != sm2CurveName {
		return nil, nil, errors.New("ssh: unsupported SM2 curve: " + w.Curve)
	}

	x, y := elliptic.Unmarshal(sm2.P256(), w.KeyBytes)
	if x == nil || y == nil {
		return nil, nil, errors.New("ssh: invalid SM2 public key point")
	}

	key := &sm2PublicKey{
		key: ecdsa.PublicKey{
			Curve: sm2.P256(),
			X:     x,
			Y:     y,
		},
	}
	return key, w.Rest, nil
}

// sm2Signer implements the Signer interface for SM2 private keys.
type sm2Signer struct {
	key *sm2.PrivateKey
}

// SM2Decrypter is implemented by SM2 signers that can also decrypt.
type SM2Decrypter interface {
	SM2Decrypt(ciphertext []byte) ([]byte, error)
}

func (s *sm2Signer) SM2Decrypt(ciphertext []byte) ([]byte, error) {
	return sm2.Decrypt(s.key, ciphertext)
}

func (s *sm2Signer) PublicKey() PublicKey {
	return &sm2PublicKey{key: s.key.PublicKey}
}

func (s *sm2Signer) Sign(rand io.Reader, data []byte) (*Signature, error) {
	// 使用 GM/T 0009-2012 规范的 SM2 签名
	// 使用默认的SM2签名选项，确保兼容性
	sig, err := s.key.Sign(rand, data, sm2.DefaultSM2SignerOpts)
	if err != nil {
		return nil, err
	}
	return &Signature{
		Format: KeyAlgoSM2,
		Blob:   sig,
	}, nil
}

// 为GM/T 0129-2023规范优化的签名方法
func (s *sm2Signer) SignWithGM129(rand io.Reader, data []byte) (*Signature, error) {
	// 对于GM/T 0129-2023，我们使用固定的UID：1234567812345678
	const gm129UID = "1234567812345678"

	opts := sm2.NewSM2SignerOption(true, []byte(gm129UID))

	sig, err := s.key.Sign(rand, data, opts)
	if err != nil {
		return nil, err
	}

	return &Signature{
		Format: KeyAlgoSM2,
		Blob:   sig,
	}, nil
}
