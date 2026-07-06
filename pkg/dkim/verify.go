package dkim

import (
	"bytes"
	"fmt"
	"io"

	"github.com/emersion/go-msgauth/dkim"
)

// Verify checks DKIM signatures on a message and returns the first
// verification result.
func Verify(msg io.Reader) (*dkim.Verification, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, msg)
	if err != nil {
		return nil, fmt.Errorf("dkim: read for verify: %w", err)
	}

	results, err := dkim.Verify(&buf)
	if err != nil {
		return nil, fmt.Errorf("dkim: verify: %w", err)
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results[0], nil
}
