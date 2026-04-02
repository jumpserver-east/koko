package sshd

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/crypto/ssh"

	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/logger"
)

const (
	sm2HostKeyFileName      = ".sm2_host_key"
	sm2HostSignCertFileName = ".sm2_host_sign_cert.pem"
	sm2HostEncCertFileName  = ".sm2_host_enc_cert.pem"
	sm2HostEncKeyFileName   = ".sm2_host_enc_key"
)

func ParsePrivateKeyFromString(content string) (signer ssh.Signer, err error) {
	return ssh.ParsePrivateKey([]byte(content))
}

func ParsePrivateKeyWithPassphrase(privateKey, Passphrase string) (signer ssh.Signer, err error) {
	return ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(Passphrase))
}

func GenerateSM2HostKey() (ssh.Signer, error) {
	keyPath := filepath.Join(config.GlobalConfig.KeyFolderPath, sm2HostKeyFileName)

	// Try loading existing key
	data, err := os.ReadFile(keyPath)
	var signer ssh.Signer
	if err == nil {
		signer, err = ssh.ParsePrivateKey(data)
		if err == nil {
			logger.Infof("Loaded SM2 host key from %s", keyPath)
			if err := ensureSM2HostGMKexCertificateBundle(signer); err != nil {
				logger.Warnf("Failed to prepare GM/T 0129 host certificates: %s", err)
			}
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

	signer, err = ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	if err := ensureSM2HostGMKexCertificateBundle(signer); err != nil {
		logger.Warnf("Failed to prepare GM/T 0129 host certificates: %s", err)
	}
	return signer, nil
}

func ensureSM2HostGMKexCertificateBundle(signer ssh.Signer) error {
	signCertPath := filepath.Join(config.GlobalConfig.CertsFolderPath, sm2HostSignCertFileName)
	encCertPath := filepath.Join(config.GlobalConfig.CertsFolderPath, sm2HostEncCertFileName)
	encKeyPath := filepath.Join(config.GlobalConfig.KeyFolderPath, sm2HostEncKeyFileName)

	bundle, err := loadSM2HostGMKexCertificateBundle(signCertPath, encCertPath, encKeyPath)
	if err == nil {
		if err := ssh.RegisterGMKexCertificateBundle(signer.PublicKey(), bundle); err == nil {
			logger.Infof("Loaded GM/T 0129 dual certificates from %s and %s", signCertPath, encCertPath)
			return nil
		} else {
			logger.Warnf("Persisted GM/T 0129 host certificates do not match current host key: %s, regenerating", err)
		}
	} else {
		if !os.IsNotExist(err) {
			logger.Warnf("Failed to load persisted GM/T 0129 host certificates: %s, regenerating", err)
		}
	}

	bundle, err = ssh.NewSelfSignedGMKexCertificateBundle(rand.Reader, signer, "koko-gm-host")
	if err != nil {
		return err
	}
	if err := saveSM2HostGMKexCertificateBundle(bundle, signCertPath, encCertPath, encKeyPath); err != nil {
		return err
	}
	if err := ssh.RegisterGMKexCertificateBundle(signer.PublicKey(), bundle); err != nil {
		return err
	}
	logger.Infof("Generated and saved GM/T 0129 dual certificates to %s and %s", signCertPath, encCertPath)
	return nil
}

func loadSM2HostGMKexCertificateBundle(signCertPath, encCertPath, encKeyPath string) (*ssh.GMKexCertificateBundle, error) {
	signingCert, err := loadCertificatePEM(signCertPath)
	if err != nil {
		return nil, err
	}
	encryptionCert, err := loadCertificatePEM(encCertPath)
	if err != nil {
		return nil, err
	}
	encryptionKey, err := loadSM2PrivateKey(encKeyPath)
	if err != nil {
		return nil, err
	}
	return ssh.NewGMKexCertificateBundle(signingCert.Raw, encryptionCert.Raw, encryptionKey)
}

func saveSM2HostGMKexCertificateBundle(bundle *ssh.GMKexCertificateBundle, signCertPath, encCertPath, encKeyPath string) error {
	if err := saveCertificatePEM(signCertPath, bundle.SigningCertificate()); err != nil {
		return err
	}
	if err := saveCertificatePEM(encCertPath, bundle.EncryptionCertificate()); err != nil {
		return err
	}
	return saveSM2PrivateKey(encKeyPath, bundle.EncryptionKey())
}

func loadCertificatePEM(path string) (*smx509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := smx509.ParseCertificatePEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}

func saveCertificatePEM(path string, cert *smx509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate for %s is nil", path)
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

func loadSM2PrivateKey(path string) (*sm2.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rawKey, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 private key %s: %w", path, err)
	}
	key, ok := rawKey.(*sm2.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %s is %T, want *sm2.PrivateKey", path, rawKey)
	}
	return key, nil
}

func saveSM2PrivateKey(path string, key *sm2.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("private key for %s is nil", path)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}
