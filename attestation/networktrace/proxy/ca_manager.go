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

// NewCAManager creates a new CAManager, loading or generating the CA certificate
func NewCAManager(caKeyPath, caCertPath string, generate bool) (*CAManager, error) {
	manager := &CAManager{}

	if err := manager.loadOrGenerateCA(caKeyPath, caCertPath, generate); err != nil {
		return nil, fmt.Errorf("load or generate CA: %w", err)
	}

	return manager, nil
}

// loadOrGenerateCA loads existing CA or generates a new one
func (cm *CAManager) loadOrGenerateCA(keyPath, certPath string, generate bool) error {
	// 1. Try to load existing CA
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

	// Save CA to disk
	if err := cm.saveCA(keyPath, certPath); err != nil {
		return fmt.Errorf("save CA: %w", err)
	}

	log.Infof("Saved CA certificate to %s (0644) and key to %s (0600)", certPath, keyPath)
	return nil
}

// loadCA loads CA certificate and key from disk with polymorphic parsing
func (cm *CAManager) loadCA(keyPath, certPath string) error {
	// --- Load Private Key ---
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode PEM key")
	}

	// Try parsing in order of likelihood: PKCS#8 (Modern), PKCS#1 (Legacy RSA), SEC1 (Legacy EC)
	var privateKey any

	// 1. Try PKCS#8 (Standard for modern keys)
	if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		privateKey = key
	} else {
		// 2. Try PKCS#1 (Legacy RSA)
		if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
			privateKey = key
		} else {
			// 3. Try SEC1 (Legacy EC)
			if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
				privateKey = key
			} else {
				return errors.New("failed to parse private key: format not recognized (tried PKCS#8, PKCS#1, SEC1)")
			}
		}
	}

	// Validate key type
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		cm.caKey = k
	case *ecdsa.PrivateKey:
		cm.caKey = k
	default:
		return fmt.Errorf("unsupported key type: %T", privateKey)
	}

	// --- Load Certificate ---
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

// generateCA generates a new CA certificate using ECDSA (P-256)
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

		// Explicitly set signature algorithm
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

// saveCA saves CA certificate to disk
func (cm *CAManager) saveCA(keyPath, certPath string) error {
	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	// --- Save Private Key (PKCS#8 Standard) ---
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // Secure permissions
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

	// --- Save Certificate ---
	// FIX: Use 0644 so Snap/Curl/Other users can read the public cert
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}); err != nil {
		return fmt.Errorf("write cert pem: %w", err)
	}

	// Double check permissions (OpenFile usually handles it, but explicit chmod is safer)
	os.Chmod(certPath, 0644)

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
