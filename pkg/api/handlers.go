package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/dkim"
	"github.com/i-got-this-faa/marco/pkg/queue"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

type userKey struct{}

// handlers holds the dependencies for HTTP handler functions.
type handlers struct {
	db            *sql.DB
	blob          blobstore.Store
	qm            *queue.Manager
	am            *auth.Manager
	dk            *dkim.Signer
	sessionExpiry time.Duration
}

// response is the standard JSON envelope.
type response struct {
	OK    bool        `json:"ok"`
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, resp response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (h *handlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, response{OK: true, Data: map[string]string{
		"version": "0.1.0",
		"status":  "ok",
	}})
}

func (h *handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}

	ctx := r.Context()
	userID, err := h.am.Authenticate(ctx, req.Email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, response{Error: "invalid credentials"})
		return
	}

	user, err := storage.GetUserByID(ctx, h.db, userID)
	if err != nil {
		slog.Error("load user after login", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "login failed"})
		return
	}

	token, err := auth.CreateSession(ctx, h.db, userID, h.sessionExpiry)
	if err != nil {
		slog.Error("session create failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "login failed"})
		return
	}

	writeJSON(w, http.StatusOK, response{OK: true, Data: map[string]interface{}{
		"token":     token,
		"is_admin":  user.IsAdmin,
		"email":     user.Email,
	}})
}

func (h *handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token != "" {
		auth.RevokeSession(r.Context(), h.db, token)
	}
	writeJSON(w, http.StatusOK, response{OK: true})
}

func (h *handlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := storage.ListUsers(r.Context(), h.db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, response{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, response{OK: true, Data: users})
}

func (h *handlers) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}

	_, err := h.am.CreateUser(r.Context(), req.Email, req.Password, req.IsAdmin)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, response{OK: true})
}

// handleListDomains returns all configured domains.
func (h *handlers) handleListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := storage.ListDomains(r.Context(), h.db)
	if err != nil {
		slog.Error("list domains", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to list domains"})
		return
	}
	writeJSON(w, http.StatusOK, response{OK: true, Data: domains})
}

// handleCreateDomain adds a new domain.
func (h *handlers) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, response{Error: "domain name is required"})
		return
	}
	if err := storage.CreateDomain(r.Context(), h.db, req.Name); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeJSON(w, http.StatusConflict, response{Error: err.Error()})
			return
		}
		slog.Error("create domain", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to create domain"})
		return
	}
	writeJSON(w, http.StatusCreated, response{OK: true})
}

// handleDeleteDomain removes a domain.
func (h *handlers) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, response{Error: "domain name is required"})
		return
	}
	if err := storage.DeleteDomain(r.Context(), h.db, name); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, response{Error: "domain not found"})
			return
		}
		slog.Error("delete domain", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to delete domain"})
		return
	}
	writeJSON(w, http.StatusOK, response{OK: true})
}

// handleListAliases returns all email aliases.
func (h *handlers) handleListAliases(w http.ResponseWriter, r *http.Request) {
	aliases, err := storage.ListAliases(r.Context(), h.db)
	if err != nil {
		slog.Error("list aliases", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to list aliases"})
		return
	}
	writeJSON(w, http.StatusOK, response{OK: true, Data: aliases})
}

// handleCreateAlias adds a new email alias.
func (h *handlers) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Domain      string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid request"})
		return
	}
	if req.Source == "" || req.Destination == "" || req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, response{Error: "source, destination, and domain are required"})
		return
	}
	id, err := storage.CreateAlias(r.Context(), h.db, req.Source, req.Destination, req.Domain)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			writeJSON(w, http.StatusConflict, response{Error: err.Error()})
			return
		}
		slog.Error("create alias", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to create alias"})
		return
	}
	writeJSON(w, http.StatusCreated, response{OK: true, Data: map[string]int64{"id": id}})
}

// handleDeleteAlias removes an alias by ID.
func (h *handlers) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid alias id"})
		return
	}
	if err := storage.DeleteAlias(r.Context(), h.db, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, response{Error: "alias not found"})
			return
		}
		slog.Error("delete alias", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to delete alias"})
		return
	}
	writeJSON(w, http.StatusOK, response{OK: true})
}

// handleListQueue returns pending queue items.
func (h *handlers) handleListQueue(w http.ResponseWriter, r *http.Request) {
	items, err := storage.ListPending(r.Context(), h.db)
	if err != nil {
		slog.Error("list queue", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to list queue"})
		return
	}
	writeJSON(w, http.StatusOK, response{OK: true, Data: items})
}

// handleDeleteQueue removes a pending queue item.
func (h *handlers) handleDeleteQueue(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, response{Error: "invalid queue id"})
		return
	}
	// Complete it (removes from queue).
	if err := storage.Complete(r.Context(), h.db, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, response{Error: "queue item not found"})
			return
		}
		slog.Error("delete queue item", "error", err)
		writeJSON(w, http.StatusInternalServerError, response{Error: "failed to delete queue item"})
		return
	}
	writeJSON(w, http.StatusOK, response{OK: true})
}

// handleStats returns server statistics.
func (h *handlers) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userCount, _ := storage.CountUsers(ctx, h.db)
	domainCount := 0
	domains, err := storage.ListDomains(ctx, h.db)
	if err == nil {
		domainCount = len(domains)
	}
	aliasCount := 0
	aliases, err := storage.ListAliases(ctx, h.db)
	if err == nil {
		aliasCount = len(aliases)
	}
	queueSize, _ := storage.QueueSize(ctx, h.db)

	writeJSON(w, http.StatusOK, response{OK: true, Data: map[string]interface{}{
		"users":   userCount,
		"domains": domainCount,
		"aliases": aliasCount,
		"queue":   queueSize,
	}})
}

// userIDFromContext extracts the authenticated user ID from the request context.
func userIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(userKey{}).(int64)
	return id
}

// extractBearerToken gets the Bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
		return ""
	}
	return auth[len(prefix):]
}
