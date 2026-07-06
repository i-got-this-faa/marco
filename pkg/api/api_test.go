package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/marco/pkg/auth"
	"github.com/i-got-this-faa/marco/pkg/config"
	"github.com/i-got-this-faa/marco/pkg/storage"
	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(':memory:'): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := storage.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// setupTestHandler creates a handlers struct wired to a fresh in-memory DB
// and returns a test helper that serves HTTP requests through the router.
type testFixture struct {
	db     *sql.DB
	am     *auth.Manager
	router http.Handler
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	db := setupTestDB(t)
	am := auth.NewManager(db)
	router := withMiddleware(NewRouter(db, nil, nil, am, nil, 24*time.Hour)) // blob/qm/dk are unused by current handlers
	return &testFixture{db: db, am: am, router: router}
}

func (tf *testFixture) serve(method, target string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	tf.router.ServeHTTP(w, req)
	return w
}

func (tf *testFixture) serveWithToken(method, target, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	tf.router.ServeHTTP(w, req)
	return w
}

// readResponse decodes a JSON response envelope.
func readResponse(t *testing.T, body *bytes.Buffer) response {
	t.Helper()
	var resp response
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// createTestUser creates a user directly via auth for use in login tests.
func createTestUser(t *testing.T, am *auth.Manager, email, password string) int64 {
	t.Helper()
	id, err := am.CreateUser(context.Background(), email, password, true)
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", email, err)
	}
	return id
}

// login obtains a session token for the given credentials.
func login(t *testing.T, tf *testFixture, email, password string) string {
	t.Helper()
	body := map[string]string{"email": email, "password": password}
	data, _ := json.Marshal(body)
	w := tf.serve("POST", "/api/login", data)
	if w.Code != http.StatusOK {
		t.Fatalf("login returned status %d: %s", w.Code, w.Body.String())
	}
	resp := readResponse(t, w.Body)
	if !resp.OK {
		t.Fatalf("login returned ok=false: %s", resp.Error)
	}
	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("login data is not a map: %T", resp.Data)
	}
	token, ok := dataMap["token"].(string)
	if !ok || token == "" {
		t.Fatalf("login response missing token")
	}
	return token
}

// ---------------------------------------------------------------------------
// 1. Health endpoint
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	tf := newTestFixture(t)
	w := tf.serve("GET", "/api/health", nil)

	if w.Code != http.StatusOK {
		t.Errorf("GET /api/health = %d, want %d", w.Code, http.StatusOK)
	}

	resp := readResponse(t, w.Body)
	if !resp.OK {
		t.Errorf("health ok = false, want true")
	}

	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("health data type = %T, want map", resp.Data)
	}

	if v, ok := dataMap["version"].(string); !ok || v != "0.1.0" {
		t.Errorf(`health version = %q, want "0.1.0"`, v)
	}
	if v, ok := dataMap["status"].(string); !ok || v != "ok" {
		t.Errorf(`health status = %q, want "ok"`, v)
	}
}

// ---------------------------------------------------------------------------
// 2. Auth middleware
// ---------------------------------------------------------------------------

func TestAuthMiddlewareMissingToken(t *testing.T) {
	tf := newTestFixture(t)

	// Protected endpoints should all return 401 without a token.
	protected := []string{
		"POST /api/logout",
		"GET /api/users",
		"POST /api/users",
	}
	for _, route := range protected {
		parts := strings.SplitN(route, " ", 2)
		method, path := parts[0], parts[1]

		t.Run(route, func(t *testing.T) {
			w := tf.serve(method, path, nil)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s = %d, want 401", route, w.Code)
			}
			resp := readResponse(t, w.Body)
			if resp.Error == "" {
				t.Error("expected error message, got empty")
			}
			if resp.OK {
				t.Error("expected ok=false on unauthorized")
			}
		})
	}
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	tf := newTestFixture(t)

	w := tf.serveWithToken("GET", "/api/users", "this-is-not-a-valid-token", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
	resp := readResponse(t, w.Body)
	if resp.OK {
		t.Error("expected ok=false with invalid token")
	}
	if resp.Error == "" {
		t.Error("expected error message with invalid token")
	}
}

// ---------------------------------------------------------------------------
// 3. Login / Logout flow
// ---------------------------------------------------------------------------

func TestLoginSuccess(t *testing.T) {
	tf := newTestFixture(t)
	createTestUser(t, tf.am, "alice@example.com", "supersecret1")

	body := map[string]string{"email": "alice@example.com", "password": "supersecret1"}
	data, _ := json.Marshal(body)
	w := tf.serve("POST", "/api/login", data)

	if w.Code != http.StatusOK {
		t.Errorf("POST /api/login = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	resp := readResponse(t, w.Body)
	if !resp.OK {
		t.Fatalf("login ok=false: %s", resp.Error)
	}

	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("login data type = %T, want map", resp.Data)
	}
	token, _ := dataMap["token"].(string)
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	tf := newTestFixture(t)

	// Non-existent user
	body := map[string]string{"email": "nobody@example.com", "password": "whatever123"}
	data, _ := json.Marshal(body)
	w := tf.serve("POST", "/api/login", data)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password code = %d, want 401", w.Code)
	}
	resp := readResponse(t, w.Body)
	if resp.OK {
		t.Error("expected ok=false on invalid login")
	}
	if resp.Error == "" {
		t.Error("expected error message on invalid login")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	tf := newTestFixture(t)
	createTestUser(t, tf.am, "bob@example.com", "rightpassword1")

	body := map[string]string{"email": "bob@example.com", "password": "wrongpassword1"}
	data, _ := json.Marshal(body)
	w := tf.serve("POST", "/api/login", data)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password code = %d, want 401", w.Code)
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	tf := newTestFixture(t)
	w := tf.serve("POST", "/api/login", []byte("not-json"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("bad json code = %d, want 400", w.Code)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	tf := newTestFixture(t)
	createTestUser(t, tf.am, "carol@example.com", "mypassword1")
	token := login(t, tf, "carol@example.com", "mypassword1")

	// Verify the token works for a protected endpoint first
	w := tf.serveWithToken("GET", "/api/users", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("token should be valid before logout, got %d", w.Code)
	}

	// Logout
	w = tf.serveWithToken("POST", "/api/logout", token, nil)
	if w.Code != http.StatusOK {
		t.Errorf("logout returned %d, want 200", w.Code)
	}
	resp := readResponse(t, w.Body)
	if !resp.OK {
		t.Errorf("logout ok=false: %s", resp.Error)
	}

	// After logout, the same token should be invalid
	w = tf.serveWithToken("GET", "/api/users", token, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("after logout token should be 401, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// 4. User CRUD
// ---------------------------------------------------------------------------

func TestCreateUserViaAPI(t *testing.T) {
	tf := newTestFixture(t)
	// First create admin user to login
	createTestUser(t, tf.am, "admin@example.com", "adminpass1")
	token := login(t, tf, "admin@example.com", "adminpass1")

	body := map[string]string{"email": "newuser@example.com", "password": "newpass1234"}
	data, _ := json.Marshal(body)
	w := tf.serveWithToken("POST", "/api/users", token, data)

	if w.Code != http.StatusCreated {
		t.Errorf("POST /api/users = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	resp := readResponse(t, w.Body)
	if !resp.OK {
		t.Errorf("create user ok=false: %s", resp.Error)
	}
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	tf := newTestFixture(t)
	createTestUser(t, tf.am, "admin@example.com", "adminpass1")
	token := login(t, tf, "admin@example.com", "adminpass1")

	// Create the same user twice
	body := map[string]string{"email": "dup@example.com", "password": "dupuser1234"}
	data, _ := json.Marshal(body)
	w := tf.serveWithToken("POST", "/api/users", token, data)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create returned %d, want 201", w.Code)
	}

	w = tf.serveWithToken("POST", "/api/users", token, data)
	if w.Code != http.StatusBadRequest {
		t.Errorf("duplicate create = %d, want 400", w.Code)
	}
}

func TestCreateUserWeakPassword(t *testing.T) {
	tf := newTestFixture(t)
	createTestUser(t, tf.am, "admin@example.com", "adminpass1")
	token := login(t, tf, "admin@example.com", "adminpass1")

	body := map[string]string{"email": "weak@example.com", "password": "short"}
	data, _ := json.Marshal(body)
	w := tf.serveWithToken("POST", "/api/users", token, data)

	if w.Code != http.StatusBadRequest {
		t.Errorf("weak password create = %d, want 400", w.Code)
	}
}

func TestCreateUserInvalidJSON(t *testing.T) {
	tf := newTestFixture(t)
	createTestUser(t, tf.am, "admin@example.com", "adminpass1")
	token := login(t, tf, "admin@example.com", "adminpass1")

	w := tf.serveWithToken("POST", "/api/users", token, []byte("not-json"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad json code = %d, want 400", w.Code)
	}
}

func TestListUsers(t *testing.T) {
	tf := newTestFixture(t)
	createTestUser(t, tf.am, "admin@example.com", "adminpass1")
	token := login(t, tf, "admin@example.com", "adminpass1")

	// Create a couple of users
	createTestUser(t, tf.am, "user1@example.com", "user1pass1")
	createTestUser(t, tf.am, "user2@example.com", "user2pass1")

	w := tf.serveWithToken("GET", "/api/users", token, nil)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/users = %d, want 200", w.Code)
	}

	resp := readResponse(t, w.Body)
	if !resp.OK {
		t.Fatalf("list users ok=false: %s", resp.Error)
	}

	users, ok := resp.Data.([]interface{})
	if !ok {
		t.Fatalf("users data type = %T, want []interface{}", resp.Data)
	}
	if len(users) != 3 {
		t.Errorf("expected 3 users, got %d", len(users))
	}

	// Verify basic structure of first user
	first, ok := users[0].(map[string]interface{})
	if !ok {
		t.Fatalf("user type = %T, want map", users[0])
	}
	if _, ok := first["id"]; !ok {
		t.Error("user missing id field")
	}
	if _, ok := first["email"]; !ok {
		t.Error("user missing email field")
	}
}

func TestListUsersRequiresAuth(t *testing.T) {
	tf := newTestFixture(t)
	w := tf.serve("GET", "/api/users", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated list = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// 5. JSON envelope helpers
// ---------------------------------------------------------------------------

func TestJSONResponseFormat(t *testing.T) {
	tf := newTestFixture(t)
	w := tf.serve("GET", "/api/health", nil)

	ct := w.Header().Get("Content-Type")
	if ct == "" || ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func Test404ForUnknownRoute(t *testing.T) {
	tf := newTestFixture(t)
	w := tf.serve("GET", "/api/unknown", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown route = %d, want 404", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	tf := newTestFixture(t)
	// /api/health only allows GET
	w := tf.serve("POST", "/api/health", nil)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/health = %d, want 405", w.Code)
	}
}

// ---------------------------------------------------------------------------
// 6. CORS headers via withMiddleware
// ---------------------------------------------------------------------------

func TestCORSHeaders(t *testing.T) {
	tf := newTestFixture(t)
	w := tf.serve("GET", "/api/health", nil)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", origin)
	}
	if methods := w.Header().Get("Access-Control-Allow-Methods"); methods == "" {
		t.Error("Access-Control-Allow-Methods header missing")
	}
	if headers := w.Header().Get("Access-Control-Allow-Headers"); headers == "" {
		t.Error("Access-Control-Allow-Headers header missing")
	}
}

func TestCORSPreflight(t *testing.T) {
	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	w := httptest.NewRecorder()
	// Wrap in withMiddleware as the router does
	handler := withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should never reach here for OPTIONS
		t.Error("handler called for OPTIONS preflight")
	}))
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("OPTIONS = %d, want 204", w.Code)
	}
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", origin)
	}
}

// ---------------------------------------------------------------------------
// 7. Panic recovery via withMiddleware
// ---------------------------------------------------------------------------

func TestPanicRecovery(t *testing.T) {
	handler := withMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("after panic = %d, want 500", w.Code)
	}
	resp := readResponse(t, w.Body)
	if resp.OK {
		t.Error("expected ok=false after panic")
	}
	if resp.Error == "" {
		t.Error("expected error message after panic")
	}
}

// ---------------------------------------------------------------------------
// 8. Full integration: auth + user CRUD
// ---------------------------------------------------------------------------

func TestFullAPIFlow(t *testing.T) {
	tf := newTestFixture(t)

	// 1. Health check
	w := tf.serve("GET", "/api/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("health check failed: %d", w.Code)
	}

	// 2. Create an admin user directly to bootstrap
	createTestUser(t, tf.am, "admin@marco.test", "administrator1")

	// 3. Login
	token := login(t, tf, "admin@marco.test", "administrator1")

	// 4. Create a new user via API
	body := map[string]string{"email": "test@example.com", "password": "testpass123"}
	data, _ := json.Marshal(body)
	w = tf.serveWithToken("POST", "/api/users", token, data)
	if w.Code != http.StatusCreated {
		t.Fatalf("create user via API failed: %d: %s", w.Code, w.Body.String())
	}

	// 5. List users — should have 2 (admin + test)
	w = tf.serveWithToken("GET", "/api/users", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list users failed: %d", w.Code)
	}
	resp := readResponse(t, w.Body)
	users, ok := resp.Data.([]interface{})
	if !ok {
		t.Fatalf("users data type = %T", resp.Data)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}

	// 6. Logout
	w = tf.serveWithToken("POST", "/api/logout", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", w.Code)
	}

	// 7. Old token should be rejected
	w = tf.serveWithToken("GET", "/api/users", token, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("after logout, old token = %d, want 401", w.Code)
	}
}

// ---------------------------------------------------------------------------
// 9. NewServer constructor
// ---------------------------------------------------------------------------

func TestNewServer(t *testing.T) {
	db := setupTestDB(t)
	am := auth.NewManager(db)
	cfg := &config.AdminConfig{ListenAddr: ":9999"}
	srv := NewServer(cfg, db, nil, nil, am, nil, nil)

	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.Addr != ":9999" {
		t.Errorf("Addr = %q, want %q", srv.Addr, ":9999")
	}
	if srv.Handler == nil {
		t.Error("Handler is nil")
	}
}
