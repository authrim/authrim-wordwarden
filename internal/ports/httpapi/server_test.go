package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	hmacadapter "github.com/authrim/authrim-wordwarden/internal/adapters/hmac"
	"github.com/authrim/authrim-wordwarden/internal/core/audit"
	"github.com/authrim/authrim-wordwarden/internal/core/directory"
)

func TestHealthzIsShallow(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	NewHandler("test-version").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body["ok"] != true {
		t.Fatalf("ok = %v", body["ok"])
	}
	if _, ok := body["directory"]; ok {
		t.Fatal("healthz response must not include directory reachability")
	}
}

func TestVerifyPasswordSuccess(t *testing.T) {
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct",
		"attribute_names":["uid","mail"]
	}`, "nonce_123", []byte("active-secret"))

	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}

	var body verifyPasswordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Result != "success" {
		t.Fatalf("Result = %q", body.Result)
	}
	if body.Subject == nil || body.Subject.DirectoryID != "uid=alice,ou=People,dc=example,dc=com" {
		t.Fatalf("Subject = %#v", body.Subject)
	}
	if body.Attributes["mail"][0] != "alice@example.com" {
		t.Fatalf("Attributes = %#v", body.Attributes)
	}
}

func TestVerifyPasswordInvalidCredentials(t *testing.T) {
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"wrong",
		"attribute_names":["uid"]
	}`, "nonce_123", []byte("active-secret"))

	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}

	var body verifyPasswordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Result != "failure" || body.Reason != "invalid_credentials" {
		t.Fatalf("body = %#v", body)
	}
}

func TestVerifyPasswordRejectsBadSignature(t *testing.T) {
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`, "nonce_123", []byte("wrong-secret"))

	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestVerifyPasswordRejectsReplay(t *testing.T) {
	handler := newTestHandler()
	body := `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`

	req1 := signedVerifyPasswordRequest(t, body, "nonce_123", []byte("active-secret"))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status = %d body = %s", rec1.Code, rec1.Body.String())
	}

	req2 := signedVerifyPasswordRequest(t, body, "nonce_123", []byte("active-secret"))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second status = %d body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestVerifyPasswordWritesRedactedAuditEvent(t *testing.T) {
	sink := &memoryAuditSink{}
	handler := newTestHandlerWithAudit(sink)
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`, "nonce_123", []byte("active-secret"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if len(sink.events) != 1 {
		t.Fatalf("audit events = %d", len(sink.events))
	}
	event := sink.events[0]
	if event.EventType != audit.EventVerifySuccess {
		t.Fatalf("EventType = %q", event.EventType)
	}
	if event.UsernameHash == "" {
		t.Fatal("UsernameHash is empty")
	}
	if event.UsernameHash == "alice" {
		t.Fatal("UsernameHash contains raw username")
	}
}

func newTestHandler() http.Handler {
	return newTestHandlerWithAudit(audit.DiscardSink{})
}

func newTestHandlerWithAudit(sink audit.Sink) http.Handler {
	now := fixedHMACTime()
	verifier := hmacadapter.NewVerifier(hmacadapter.KeySet{
		Active: hmacadapter.Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })

	return NewHandler("test-version", HandlerOptions{
		Tenants: map[string]TenantRuntime{
			"ww_tenant_a": {
				TenantID:        "tenant-a",
				ConnectorID:     "ww_tenant_a",
				HMACVerifier:    verifier,
				Directory:       fakeDirectory{},
				AuditHashSecret: []byte("audit-secret"),
			},
		},
		Audit: sink,
	})
}

func signedVerifyPasswordRequest(t *testing.T, body string, nonce string, secret []byte) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hmacadapter.HeaderConnectorID, "ww_tenant_a")
	req.Header.Set(hmacadapter.HeaderKeyID, "kid-active")
	req.Header.Set(hmacadapter.HeaderRequestID, "req_123")
	req.Header.Set(hmacadapter.HeaderTimestamp, fixedHMACTime().Format(time.RFC3339))
	req.Header.Set(hmacadapter.HeaderNonce, nonce)
	req.Header.Set(hmacadapter.HeaderSignedHeaders, "content-type;x-authrim-connector-id;x-authrim-key-id;x-authrim-request-id;x-authrim-timestamp;x-authrim-nonce")

	canonical, err := hmacadapter.CanonicalRequest(
		req,
		[]byte(body),
		[]string{"content-type", "x-authrim-connector-id", "x-authrim-key-id", "x-authrim-nonce", "x-authrim-request-id", "x-authrim-timestamp"},
		req.Header.Get(hmacadapter.HeaderTimestamp),
		nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(hmacadapter.HeaderSignature, hmacadapter.SignCanonical(canonical, secret))
	return req
}

func fixedHMACTime() time.Time {
	return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
}

type fakeDirectory struct{}

func (fakeDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

type memoryAuditSink struct {
	events []audit.Event
}

func (s *memoryAuditSink) WriteEvent(_ context.Context, event audit.Event) error {
	s.events = append(s.events, event)
	return nil
}

func (fakeDirectory) VerifyPassword(_ context.Context, request directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	if request.Password != "correct" {
		return directory.VerifyPasswordResult{Success: false, Reason: "invalid_credentials"}, nil
	}
	attrs := map[string][]string{}
	for _, name := range request.AttributeNames {
		switch name {
		case "uid":
			attrs[name] = []string{"alice"}
		case "mail":
			attrs[name] = []string{"alice@example.com"}
		}
	}
	return directory.VerifyPasswordResult{
		Success: true,
		Subject: directory.Subject{
			DirectoryID: "uid=alice,ou=People,dc=example,dc=com",
			Username:    request.Username,
		},
		Attributes: attrs,
	}, nil
}
