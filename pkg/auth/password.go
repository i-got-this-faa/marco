package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2idParams defines the recommended parameters for Argon2id.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword creates an Argon2id password hash encoded in the
// PHC string format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, saltB64, hashB64)

	return encoded, nil
}

// VerifyPassword checks a password against an Argon2id PHC string.
func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	// Expected: [ "", "argon2id", "v=19", "m=65536,t=1,p=4", "salt", "hash" ]
	if len(parts) != 6 {
		return false, fmt.Errorf("auth: invalid hash format")
	}
	if parts[1] != "argon2id" {
		return false, fmt.Errorf("auth: unsupported algorithm: %s", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("auth: parse version: %w", err)
	}

	var memory, time, threads int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("auth: parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("auth: decode salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("auth: decode hash: %w", err)
	}

	computedHash := argon2.IDKey([]byte(password), salt, uint32(time), uint32(memory), uint8(threads), uint32(len(expectedHash)))

	if subtle.ConstantTimeCompare(expectedHash, computedHash) == 1 {
		return true, nil
	}
	return false, nil
}

// ValidatePasswordStrength checks minimum password requirements.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("auth: password must be at least 8 characters")
	}
	return nil
}
