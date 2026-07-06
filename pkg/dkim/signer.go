package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/emersion/go-msgauth/dkim"
)

// Signer signs outgoing messages with a DKIM signature.
type Signer struct {
	domain   string
	selector string
	privKey  crypto.Signer
}

// NewSigner creates a new DKIM signer.
func NewSigner(domain, selector string, key crypto.Signer) *Signer {
	return &Signer{
		domain:   domain,
		selector: selector,
		privKey:  key,
	}
}

// Sign reads a message and returns it with a DKIM-Signature header added.
func (s *Signer) Sign(ctx context.Context, msg io.Reader) ([]byte, error) {
	data, err := io.ReadAll(msg)
	if err != nil {
		return nil, fmt.Errorf("dkim: read message: %w", err)
	}

	var buf bytes.Buffer
	err = dkim.Sign(&buf, bytes.NewReader(data), &dkim.SignOptions{
		Domain:   s.domain,
		Selector: s.selector,
		Signer:   s.privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("dkim: sign: %w", err)
	}
	return buf.Bytes(), nil
}

// GenerateKey generates a new 2048-bit RSA private key for DKIM signing.
func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// EncodePrivateKey returns the PEM-encoded private key.
func EncodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// DNSTXTRecord returns the DNS TXT record value for a DKIM public key.
func DNSTXTRecord(key *rsa.PrivateKey, selector, domain string) string {
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("v=DKIM1; k=rsa; p=%x", pubDER)
}
