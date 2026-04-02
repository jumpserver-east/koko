// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// Key exchange tests.

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func kexTestServerSigner(t testing.TB, name string) (AlgorithmSigner, string) {
	t.Helper()

	if name != KeyExchangeSM2SM3 {
		signer := testSigners["ecdsa"].(AlgorithmSigner)
		return signer, signer.PublicKey().Type()
	}

	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(sm2): %v", err)
	}
	signer, err := NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("NewSignerFromKey(sm2): %v", err)
	}
	if algorithmSigner, ok := signer.(AlgorithmSigner); ok {
		return algorithmSigner, algorithmSigner.PublicKey().Type()
	}
	return algorithmSignerWrapper{signer}, signer.PublicKey().Type()
}

func equalKexResult(a, b *kexResult) bool {
	if a == nil || b == nil {
		return a == b
	}

	if len(a.HostCertificates) != len(b.HostCertificates) {
		return false
	}
	for i := range a.HostCertificates {
		if !bytes.Equal(a.HostCertificates[i].Raw, b.HostCertificates[i].Raw) {
			return false
		}
	}

	return bytes.Equal(a.H, b.H) &&
		bytes.Equal(a.K, b.K) &&
		bytes.Equal(a.HostKey, b.HostKey) &&
		bytes.Equal(a.Signature, b.Signature) &&
		a.Hash == b.Hash &&
		bytes.Equal(a.SessionID, b.SessionID) &&
		bytes.Equal(a.SignedData, b.SignedData) &&
		(a.HashFunc == nil) == (b.HashFunc == nil)
}

// Runs multiple key exchanges concurrent to detect potential data races with
// kex obtained from the global kexAlgoMap.
// This test needs to be executed using the race detector in order to detect
// race conditions.
func TestKexes(t *testing.T) {
	type kexResultErr struct {
		result *kexResult
		err    error
	}

	for name, kex := range kexAlgoMap {
		t.Run(name, func(t *testing.T) {
			serverSigner, serverAlgo := kexTestServerSigner(t, name)

			wg := sync.WaitGroup{}
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					a, b := memPipe()

					s := make(chan kexResultErr, 1)
					c := make(chan kexResultErr, 1)
					var magics handshakeMagics
					go func() {
						r, e := kex.Client(a, rand.Reader, &magics)
						a.Close()
						c <- kexResultErr{r, e}
					}()
					go func() {
						r, e := kex.Server(b, rand.Reader, &magics, serverSigner, serverAlgo)
						b.Close()
						s <- kexResultErr{r, e}
					}()

					clientRes := <-c
					serverRes := <-s
					if clientRes.err != nil {
						t.Errorf("client: %v", clientRes.err)
					}
					if serverRes.err != nil {
						t.Errorf("server: %v", serverRes.err)
					}
					if !equalKexResult(clientRes.result, serverRes.result) {
						t.Errorf("kex %q: mismatch %#v, %#v", name, clientRes.result, serverRes.result)
					}
				}()
			}
			wg.Wait()
		})
	}
}

func BenchmarkKexes(b *testing.B) {
	type kexResultErr struct {
		result *kexResult
		err    error
	}

	for name, kex := range kexAlgoMap {
		b.Run(name, func(b *testing.B) {
			serverSigner, serverAlgo := kexTestServerSigner(b, name)

			for i := 0; i < b.N; i++ {
				t1, t2 := memPipe()

				s := make(chan kexResultErr, 1)
				c := make(chan kexResultErr, 1)
				var magics handshakeMagics

				go func() {
					r, e := kex.Client(t1, rand.Reader, &magics)
					t1.Close()
					c <- kexResultErr{r, e}
				}()
				go func() {
					r, e := kex.Server(t2, rand.Reader, &magics, serverSigner, serverAlgo)
					t2.Close()
					s <- kexResultErr{r, e}
				}()

				clientRes := <-c
				serverRes := <-s

				if clientRes.err != nil {
					panic(fmt.Sprintf("client: %v", clientRes.err))
				}
				if serverRes.err != nil {
					panic(fmt.Sprintf("server: %v", serverRes.err))
				}
			}
		})
	}
}
