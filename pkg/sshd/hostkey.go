package sshd

import (
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/emmansun/gmsm/sm2"
	"golang.org/x/crypto/ssh"

	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/logger"
)

func ParsePrivateKeyFromString(content string) (signer ssh.Signer, err error) {
	return ssh.ParsePrivateKey([]byte(content))
}

func ParsePrivateKeyWithPassphrase(privateKey, Passphrase string) (signer ssh.Signer, err error) {
	return ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(Passphrase))
}

func GenerateSM2HostKey() (ssh.Signer, error) {
	keyPath := filepath.Join(config.GlobalConfig.KeyFolderPath, ".sm2_host_key")

	// Try loading existing key
	data, err := os.ReadFile(keyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err == nil {
			logger.Infof("Loaded SM2 host key from %s", keyPath)
			return signer, nil
		}
		logger.Warnf("Failed to parse SM2 host key from %s: %s, regenerating", keyPath, err)
	}

	// Generate new key
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Persist to file
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		logger.Warnf("Failed to marshal SM2 host key: %s", err)
		return ssh.NewSignerFromKey(key)
	}
	pemData := pem.EncodeToMemory(block)
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		logger.Warnf("Failed to save SM2 host key to %s: %s", keyPath, err)
	} else {
		logger.Infof("Generated and saved SM2 host key to %s", keyPath)
	}

	return ssh.NewSignerFromKey(key)
}
