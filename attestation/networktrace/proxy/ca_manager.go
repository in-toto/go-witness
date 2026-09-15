// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/in-toto/go-witness/log"
)

// CAManager loads or generates a CA certificate for TLS interception
type CAManager struct {
	caKey  any // Can be *rsa.PrivateKey or *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func NewCAManager(caKeyPath, caCertPath string, generate bool) (*CAManager, error) {
	manager := &CAManager{}

	if err := manager.loadOrGenerateCA(caKeyPath, caCertPath, generate); err != nil {
		return nil, fmt.Errorf("load or generate CA: %w", err)
	}

	return manager, nil
}

func (cm *CAManager) loadOrGenerateCA(keyPath, certPath string, generate bool) error {
	if _, err := os.Stat(keyPath); err == nil {
		if _, err = os.Stat(certPath); err == nil {
			if err = cm.loadCA(keyPath, certPath); err == nil {
				log.Info("Loaded existing CA certificate")
				return nil
			} else {
				log.Warnf("Failed to load existing CA (will regenerate if allowed): %v", err)
			}
		}
	}

	if !generate {
		return fmt.Errorf("CA certificate or key not found, and generation is disabled")
	}

	log.Info("Generating new CA certificate (ECDSA P-256)")
	if err := cm.generateCA(); err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}

	if err := cm.saveCA(keyPath, certPath); err != nil {
		return fmt.Errorf("save CA: %w", err)
	}

	log.Infof("Saved CA certificate to %s (0644) and key to %s (0600)", certPath, keyPath)
	return nil
}

func (cm *CAManager) loadCA(keyPath, certPath string) error {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode PEM key")
	}

	var privateKey any

	// Try PKCS#8 (Standard for modern keys)
	if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		privateKey = key
	} else {
		// Try PKCS#1 (Legacy RSA)
		if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
			privateKey = key
		} else {
			// Try SEC1 (Legacy EC)
			if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
				privateKey = key
			} else {
				return errors.New("failed to parse private key: format not recognized (tried PKCS#8, PKCS#1, SEC1)")
			}
		}
	}

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		cm.caKey = k
	case *ecdsa.PrivateKey:
		cm.caKey = k
	default:
		return fmt.Errorf("unsupported key type: %T", privateKey)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read cert file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode PEM cert")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	cm.caCert = cert
	cm.caKey = privateKey

	return nil
}

func (cm *CAManager) generateCA() error {
	// Generate ECDSA key (Much faster than RSA for MITM signing)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Witness Transparent Proxy CA"},
			CommonName:   "Witness Proxy CA",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),       // Backdate slightly to avoid clock skew
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 year validity

		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		// BasicConstraintsValid=true and IsCA=true are CRITICAL for this to work as a CA
		BasicConstraintsValid: true,
		IsCA:                  true,

		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse generated certificate: %w", err)
	}

	cm.caKey = key
	cm.caCert = cert

	return nil
}

func (cm *CAManager) saveCA(keyPath, certPath string) error {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyFile.Close()

	// Marshal to PKCS#8 (Handles both RSA and ECDSA generically)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(cm.caKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("write key pem: %w", err)
	}

	// Use 0644 so Snap/Curl/Other users can read the public cert
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}); err != nil {
		return fmt.Errorf("write cert pem: %w", err)
	}

	// Just in case, ensuring permissions are correct
	_ = os.Chmod(certPath, 0644)

	return nil
}

// GetCA returns the CA certificate as a tls.Certificate
func (cm *CAManager) GetCA() *tls.Certificate {
	cert := tls.Certificate{
		Certificate: [][]byte{cm.caCert.Raw},
		PrivateKey:  cm.caKey,
		Leaf:        cm.caCert,
	}
	return &cert
}

func (cm *CAManager) CertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}))
}
