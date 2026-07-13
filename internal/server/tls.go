package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

// generateSelfSignedCert creates an in-memory ECDSA self-signed certificate
// valid for one year. Used when the server config has no TLS cert/key file,
// which is the expected path for "just point this at an EC2 public IP" setups
// without a real domain to get a CA-signed cert for.
//
// Returns the tls.Certificate ready to use in a tls.Config, plus the
// SHA-256 fingerprint of the DER-encoded cert (hex-encoded) so it can be
// logged for the operator to pin in their client config's
// server_fingerprint field.
func generateSelfSignedCert() (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("tls: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("tls: generate serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tunneld self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         false,
		// No DNSNames/IPAddresses restriction: since clients connect by
		// raw IP and we don't have a domain, and verification is either
		// disabled or done via fingerprint pinning rather than hostname
		// matching, we leave SANs open. Document this tradeoff clearly
		// in the README.
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("tls: create certificate: %w", err)
	}

	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return cert, fingerprint, nil
}
