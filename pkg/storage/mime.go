package storage

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
)

// ParsedMessage extends a Message with decoded body content.
type ParsedMessage struct {
	Message
	TextBody string `json:"text_body"`
	HTMLBody string `json:"html_body"`
}

// ParseMessageBody parses a raw RFC 5322 message stream and extracts the
// plain text and HTML body parts. It returns the populated ParsedMessage
// or an error if the message cannot be parsed.
func ParseMessageBody(msg *Message, r io.Reader) (*ParsedMessage, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	pm := &ParsedMessage{Message: *msg}

	mediaType, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil {
		// Treat as plain text.
		body, _ := decodeBody(m.Body, m.Header.Get("Content-Transfer-Encoding"))
		pm.TextBody = string(body)
		return pm, nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		pm.TextBody, pm.HTMLBody = extractParts(m.Body, params["boundary"])
	} else {
		body, _ := decodeBody(m.Body, m.Header.Get("Content-Transfer-Encoding"))
		if mediaType == "text/html" {
			pm.HTMLBody = string(body)
		} else {
			pm.TextBody = string(body)
		}
	}

	return pm, nil
}

func extractParts(r io.Reader, boundary string) (textBody, htmlBody string) {
	if boundary == "" {
		body, _ := io.ReadAll(r)
		return string(body), ""
	}

	mr := multipart.NewReader(r, boundary)
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}

		mediaType, params, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
		if err != nil {
			continue
		}

		// Recurse into nested multipart parts.
		if strings.HasPrefix(mediaType, "multipart/") {
			nt, nh := extractParts(p, params["boundary"])
			if textBody == "" {
				textBody = nt
			}
			if htmlBody == "" {
				htmlBody = nh
			}
			continue
		}

		slurp, err := decodeBody(p, p.Header.Get("Content-Transfer-Encoding"))
		if err != nil {
			continue
		}

		switch mediaType {
		case "text/plain":
			if textBody == "" {
				textBody = string(slurp)
			}
		case "text/html":
			if htmlBody == "" {
				htmlBody = string(slurp)
			}
		}
	}

	return textBody, htmlBody
}

// decodeBody reads the body and decodes it according to the
// Content-Transfer-Encoding header value.
func decodeBody(r io.Reader, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(r))
	case "base64":
		return io.ReadAll(base64.NewDecoder(base64.StdEncoding, r))
	default:
		return io.ReadAll(r)
	}
}
