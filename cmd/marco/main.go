package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/marco"
)

func main() {
	if len(os.Args) < 2 {
		marco.Run()
		return
	}

	switch os.Args[1] {
	case "run":
		marco.Run()
	case "hash-password":
		hashPassword()
	case "gen-key":
		genKey()
	case "audit":
		audit()
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func hashPassword() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		slog.Error("read password", "error", err)
		os.Exit(1)
	}
	password = strings.TrimSpace(password)

	hash, err := auth.HashPassword(password)
	if err != nil {
		slog.Error("hash password", "error", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}

func genKey() {
	domain := "example.com"
	if len(os.Args) > 2 {
		domain = os.Args[2]
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("generate key", "error", err)
		os.Exit(1)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		slog.Error("marshal public key", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Private key:\n%s\n", privPEM)
	fmt.Printf("DNS TXT record for %s._domainkey.%s:\n", "default", domain)
	fmt.Printf("v=DKIM1; k=rsa; p=%x\n", pubDER)
}

func audit() {
	fmt.Println("Marco Mail Server - Audit")
	fmt.Println("========================")
	fmt.Println("Status: MVP build - no audit checks implemented yet")
	fmt.Println("Run 'marco run' to start the server")
}

func printHelp() {
	fmt.Println("Marco Mail Server")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  marco [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run              Start the mail server (default)")
	fmt.Println("  hash-password    Hash a password using Argon2id")
	fmt.Println("  gen-key [domain] Generate a DKIM key pair")
	fmt.Println("  audit            Check configuration and DNS")
	fmt.Println("  help             Show this help")
}
