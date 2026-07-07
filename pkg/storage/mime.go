package storage

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
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
		body, _ := io.ReadAll(m.Body)
		pm.TextBody = string(body)
		return pm, nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		pm.TextBody, pm.HTMLBody = extractParts(m.Body, params["boundary"])
	} else if mediaType == "text/html" {
		body, _ := io.ReadAll(m.Body)
		pm.HTMLBody = string(body)
	} else {
		body, _ := io.ReadAll(m.Body)
		pm.TextBody = string(body)
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

		mediaType, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		slurp, err := io.ReadAll(p)
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
