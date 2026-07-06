package main

import (
	"bytes"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/i-got-this-faa/marco/pkg/auth"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()

	fn()

	w.Close()
	os.Stdout = old
	return <-done
}

func TestHashRoundTrip(t *testing.T) {
	hash, err := auth.HashPassword("my-secure-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := auth.VerifyPassword("my-secure-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword returned false")
	}
	ok, err = auth.VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword wrong: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword should return false for wrong password")
	}
}

func TestGenKeyOutput(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"marco", "gen-key", "example.org"}

	output := captureStdout(t, genKey)

	if !strings.Contains(output, "RSA PRIVATE KEY") {
		t.Error("expected RSA PRIVATE KEY in output")
	}
	if !strings.Contains(output, "v=DKIM1") {
		t.Error("expected DKIM DNS record in output")
	}
}

func TestGenKeyPEMValid(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"marco", "gen-key"}

	output := captureStdout(t, genKey)

	block, _ := pem.Decode([]byte(output))
	if block == nil {
		t.Fatal("expected valid PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("PEM type = %s, want RSA PRIVATE KEY", block.Type)
	}
}

func TestHelpOutput(t *testing.T) {
	output := captureStdout(t, printHelp)
	if !strings.Contains(output, "run") || !strings.Contains(output, "marco") {
		t.Errorf("help output missing expected terms: %s", output[:min(len(output), 200)])
	}
}

func TestHelpContainsCommands(t *testing.T) {
	output := captureStdout(t, printHelp)
	expected := []string{"run", "hash-password", "gen-key", "audit"}
	for _, cmd := range expected {
		if !strings.Contains(output, cmd) {
			t.Errorf("help should mention %q", cmd)
		}
	}
}

func TestAuditOutput(t *testing.T) {
	output := captureStdout(t, audit)
	if output == "" {
		t.Error("audit produced no output")
	} else {
		t.Logf("audit output: %s", output[:min(len(output), 500)])
	}
	if !strings.Contains(output, "Marco") || !strings.Contains(output, "Audit") {
		t.Errorf("audit output missing expected header, got: %s", output[:min(len(output), 100)])
	}
}
