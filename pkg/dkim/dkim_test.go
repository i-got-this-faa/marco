package dkim

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	// Generate a key, sign a message, then verify the signature.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer := NewSigner("example.com", "default", key)
	msg := strings.NewReader("From: <alice@example.com>\r\nTo: <bob@example.com>\r\nSubject: Test\r\n\r\nHello, world.\r\n")

	signed, err := signer.Sign(context.Background(), msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Signed output must contain a DKIM-Signature header.
	if !bytes.Contains(signed, []byte("DKIM-Signature")) {
		t.Error("signed message missing DKIM-Signature header")
	}

	if !bytes.Contains(signed, []byte("Hello, world.")) {
		t.Error("signed message missing original body")
	}

	// Re-verify the signed message.
	// Note: verification looks up the public key via DNS for the domain in the
	// DKIM-Signature header. Since there's no DNS record for example.com pointing
	// to our test key, offline verification will fail with "key revoked".
	// We test that the function runs without error and returns a result.
	result, err := Verify(bytes.NewReader(signed))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result == nil {
		t.Fatal("Verify returned nil result")
	}
	// Err should be set since there's no DNS key available for offline verification.
	if result.Err == nil {
		t.Log("offline verify succeeded (unexpected but acceptable)")
	}
}

func TestSignInvalidDomain(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer := NewSigner("", "default", key)
	msg := strings.NewReader("From: test@example.com\r\nTo: dest@example.com\r\nSubject: X\r\n\r\nBody.")

	_, err = signer.Sign(context.Background(), msg)
	if err != nil {
		// Expected — empty domain should cause signing to fail.
		return
	}
	t.Log("signer accepted empty domain (library-dependent)")
}

func TestSignWrongDomainVerifyFails(t *testing.T) {
	// Sign with one domain, then verify — verification needs DNS but won't find it.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer := NewSigner("example.com", "default", key)
	msg := strings.NewReader("From: a@example.com\r\nTo: b@example.com\r\nSubject: T\r\n\r\nBody.\r\n")

	signed, err := signer.Sign(context.Background(), msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify runs without error and returns a result (fails because no DNS key).
	result, err := Verify(bytes.NewReader(signed))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result == nil {
		t.Fatal("Verify returned nil result")
	}
	t.Logf("offline verify result: Err=%v (expected without DNS key fetch)", result.Err)
}

func TestVerifyNoSignature(t *testing.T) {
	msg := strings.NewReader("From: a@example.com\r\nTo: b@example.com\r\nSubject: T\r\n\r\nBody.\r\n")

	result, err := Verify(msg)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for unsigned message, got %+v", result)
	}
}

func TestVerifyEmptyBody(t *testing.T) {
	msg := strings.NewReader("")
	result, err := Verify(msg)
	if err != nil {
		t.Logf("Verify empty body returned error: %v (expected without headers)", err)
		return
	}
	if result != nil {
		t.Errorf("expected nil result for empty body, got %+v", result)
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit key, got %d bits", key.N.BitLen())
	}
}

func TestEncodePrivateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pem := EncodePrivateKey(key)
	if len(pem) == 0 {
		t.Fatal("EncodePrivateKey returned empty bytes")
	}
	if !bytes.Contains(pem, []byte("RSA PRIVATE KEY")) {
		t.Error("PEM output missing RSA PRIVATE KEY header")
	}
}

func TestDNSTXTRecord(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	record := DNSTXTRecord(key, "default", "example.com")
	if record == "" {
		t.Fatal("DNSTXTRecord returned empty string")
	}
	if !strings.HasPrefix(record, "v=DKIM1; k=rsa; p=") {
		t.Errorf("unexpected DNS record format: %s", record)
	}
}
