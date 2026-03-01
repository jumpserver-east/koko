// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

// cbcMAC implements the hash.Hash interface for CBC-MAC (GB/T 15852.1)
// using SM4 as the underlying block cipher.
type cbcMAC struct {
	block   cipher.Block
	key     []byte              // kept for Reset
	state   [sm4.BlockSize]byte // CBC chaining state
	buf     [sm4.BlockSize]byte // partial block buffer
	bufUsed int
}

func newCBCMAC(key []byte) *cbcMAC {
	block, err := sm4.NewCipher(key[:sm4.BlockSize])
	if err != nil {
		panic("ssh: cbcMAC: " + err.Error())
	}
	k := make([]byte, sm4.BlockSize)
	copy(k, key[:sm4.BlockSize])
	return &cbcMAC{
		block: block,
		key:   k,
	}
}

func (m *cbcMAC) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		// Fill the buffer
		space := sm4.BlockSize - m.bufUsed
		if len(p) < space {
			copy(m.buf[m.bufUsed:], p)
			m.bufUsed += len(p)
			break
		}
		copy(m.buf[m.bufUsed:], p[:space])
		p = p[space:]
		m.bufUsed = 0

		// XOR buf into state and encrypt
		for i := 0; i < sm4.BlockSize; i++ {
			m.state[i] ^= m.buf[i]
		}
		m.block.Encrypt(m.state[:], m.state[:])
	}
	return n, nil
}

func (m *cbcMAC) Sum(in []byte) []byte {
	// Process any remaining partial block using a copy of state
	var state [sm4.BlockSize]byte
	copy(state[:], m.state[:])
	if m.bufUsed > 0 {
		// Zero-pad the partial block
		var padded [sm4.BlockSize]byte
		copy(padded[:], m.buf[:m.bufUsed])
		for i := 0; i < sm4.BlockSize; i++ {
			state[i] ^= padded[i]
		}
		m.block.Encrypt(state[:], state[:])
	}
	return append(in, state[:]...)
}

func (m *cbcMAC) Reset() {
	m.state = [sm4.BlockSize]byte{}
	m.buf = [sm4.BlockSize]byte{}
	m.bufUsed = 0
}

func (m *cbcMAC) Size() int {
	return sm4.BlockSize
}

func (m *cbcMAC) BlockSize() int {
	return sm4.BlockSize
}
