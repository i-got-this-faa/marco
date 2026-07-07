package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/marco/pkg/storage"
)

// handleMe returns the currently authenticated user.
func (h *handlers) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	user, err := storage.GetUserByID(ctx, h.db, userID)
	if err != nil {
		slog.Error("get user", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to load user"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true, Data: map[string]interface{}{
		"id":       user.ID,
		"email":    user.Email,
		"is_admin": user.IsAdmin,
	}})
}

// handleListMailboxes returns all mailboxes for the authenticated user.
func (h *handlers) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	boxes, err := storage.ListMailboxes(ctx, h.db, userID)
	if err != nil {
		slog.Error("list mailboxes", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to list mailboxes"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true, Data: boxes})
}

// handleListMailboxMessages returns messages in a mailbox owned by the user.
func (h *handlers) handleListMailboxMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	idStr := r.PathValue("id")
	mailboxID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid mailbox id"})
		return
	}

	mbox, err := storage.GetMailboxByID(ctx, h.db, mailboxID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, response{Error: "mailbox not found"})
			return
		}
		slog.Error("get mailbox", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to load mailbox"})
		return
	}
	if mbox.UserID != userID {
		writeJSON(w, http.StatusForbidden, response{Error: "access denied"})
		return
	}

	limit := parseIntQuery(r, "limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := parseIntQuery(r, "offset", 0)

	messages, err := storage.ListMessagesPaginated(ctx, h.db, mailboxID, limit, offset)
	if err != nil {
		slog.Error("list messages", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to list messages"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true, Data: messages})
}

// handleGetMessage returns a single message with its parsed body.
func (h *handlers) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	idStr := r.PathValue("id")
	msgID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid message id"})
		return
	}

	msg, err := storage.GetMessageByID(ctx, h.db, msgID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, response{Error: "message not found"})
			return
		}
		slog.Error("get message", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to load message"})
		return
	}

	mbox, err := storage.GetMailboxByID(ctx, h.db, msg.MailboxID)
	if err != nil {
		slog.Error("get mailbox for message", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to load message"})
		return
	}
	if mbox.UserID != userID {
		writeJSON(w, http.StatusForbidden, response{Error: "access denied"})
		return
	}

	rc, err := h.blob.Get(ctx, msg.BlobKey)
	if err != nil {
		slog.Error("get blob", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to load message body"})
		return
	}
	defer rc.Close()

	pm, err := storage.ParseMessageBody(msg, rc)
	if err != nil {
		slog.Error("parse message body", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to parse message body"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true, Data: pm})
}

// flagSeen is the IMAP \Seen flag bit used in the flags column.
const flagSeen = 1

// handleUpdateFlags updates message flags (currently supports marking read/unread).
func (h *handlers) handleUpdateFlags(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	idStr := r.PathValue("id")
	msgID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid message id"})
		return
	}

	var req struct {
		Seen bool `json:"seen"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}

	msg, err := storage.GetMessageByID(ctx, h.db, msgID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, response{Error: "message not found"})
			return
		}
		slog.Error("get message", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to update flags"})
		return
	}

	mbox, err := storage.GetMailboxByID(ctx, h.db, msg.MailboxID)
	if err != nil {
		slog.Error("get mailbox for message", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to update flags"})
		return
	}
	if mbox.UserID != userID {
		writeJSON(w, http.StatusForbidden, response{Error: "access denied"})
		return
	}

	flags := msg.Flags
	if req.Seen {
		flags |= flagSeen
	} else {
		flags &^= flagSeen
	}

	if err := storage.UpdateFlags(ctx, h.db, msgID, flags, flagSeen); err != nil {
		slog.Error("update flags", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to update flags"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true})
}

// handleSendMessage accepts a composed message and enqueues it for delivery.
func (h *handlers) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	user, err := storage.GetUserByID(ctx, h.db, userID)
	if err != nil {
		slog.Error("get user", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to load user"})
		return
	}

	var req struct {
		To         string `json:"to"`
		Subject    string `json:"subject"`
		TextBody   string `json:"text_body"`
		HTMLBody   string `json:"html_body"`
		InReplyTo  string `json:"in_reply_to"`
		References string `json:"references"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}

	req.To = strings.TrimSpace(req.To)
	if req.To == "" || req.Subject == "" {
		writeJSON(w, http.StatusBadRequest, response{Error: "to and subject are required"})
		return
	}

	if _, err := mail.ParseAddress(req.To); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid recipient address"})
		return
	}

	fromAddr := user.Email
	raw := buildMessage(fromAddr, req.To, req.Subject, req.TextBody, req.HTMLBody, req.InReplyTo, req.References, h.dkimCfg.Domain)

	blobKey, size, err := h.blob.Put(ctx, bytes.NewReader(raw), nil)
	if err != nil {
		slog.Error("store outbound blob", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to store message"})
		return
	}

	// Insert into the sender's Sent mailbox.
	sentMbox, err := storage.GetMailbox(ctx, h.db, userID, "Sent")
	if err != nil {
		slog.Error("get sent mailbox", "error", err)
		_ = h.blob.Delete(ctx, blobKey)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to store message"})
		return
	}

	msgID, _, err := storage.InsertMessage(ctx, h.db, sentMbox.ID, blobKey, size, fromAddr, req.To, req.Subject, flagSeen)
	if err != nil {
		slog.Error("insert sent message", "error", err)
		_ = h.blob.Delete(ctx, blobKey)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to store message"})
		return
	}

	// Enqueue for delivery to the recipient.
	if err := h.qm.Enqueue(msgID, req.To); err != nil {
		slog.Error("enqueue message", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to queue message"})
		return
	}

	writeJSON(w, http.StatusCreated, response{OK: true, Data: map[string]int64{"id": msgID}})
}

// handleListContacts returns the authenticated user's address book.
func (h *handlers) handleListContacts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	contacts, err := storage.ListContacts(ctx, h.db, userID)
	if err != nil {
		slog.Error("list contacts", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to list contacts"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true, Data: contacts})
}

// handleCreateContact adds a contact to the authenticated user's address book.
func (h *handlers) handleCreateContact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, response{Error: "email is required"})
		return
	}
	if _, err := mail.ParseAddress(req.Email); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid email address"})
		return
	}

	id, err := storage.CreateContact(ctx, h.db, userID, req.Name, req.Email)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeJSON(w, http.StatusConflict, response{Error: "contact already exists"})
			return
		}
		slog.Error("create contact", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to create contact"})
		return
	}

	writeJSON(w, http.StatusCreated, response{OK: true, Data: map[string]int64{"id": id}})
}

// handleDeleteContact removes a contact from the authenticated user's address book.
func (h *handlers) handleDeleteContact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := userIDFromContext(ctx)

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid contact id"})
		return
	}

	if err := storage.DeleteContact(ctx, h.db, userID, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, response{Error: "contact not found"})
			return
		}
		slog.Error("delete contact", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to delete contact"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true})
}

func buildMessage(from, to, subject, textBody, htmlBody, inReplyTo, references, hostname string) []byte {
	var buf bytes.Buffer
	now := time.Now().Format(time.RFC1123Z)
	msgID := fmt.Sprintf("<%d-%s@%s>", time.Now().UnixNano(), from, hostname)

	buf.WriteString(fmt.Sprintf("Message-ID: %s\r\n", msgID))
	if inReplyTo != "" {
		buf.WriteString(fmt.Sprintf("In-Reply-To: %s\r\n", inReplyTo))
	}
	if references != "" {
		buf.WriteString(fmt.Sprintf("References: %s\r\n", references))
	}
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", now))
	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", to))
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	buf.WriteString("MIME-Version: 1.0\r\n")

	if htmlBody != "" {
		buf.WriteString("Content-Type: multipart/alternative; boundary=\"boundary\"\r\n")
		buf.WriteString("\r\n")
		buf.WriteString("--boundary\r\n")
		buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(textBody)
		buf.WriteString("\r\n\r\n")
		buf.WriteString("--boundary\r\n")
		buf.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(htmlBody)
		buf.WriteString("\r\n\r\n")
		buf.WriteString("--boundary--\r\n")
	} else {
		buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(textBody)
	}

	return buf.Bytes()
}

func parseIntQuery(r *http.Request, key string, defaultValue int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultValue
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return v
}
