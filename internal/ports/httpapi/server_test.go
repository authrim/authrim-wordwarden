package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestVersionEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()

	NewHandler("test-version").ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body["connector"] != "authrim-wordwarden" {
		t.Fatalf("connector = %v", body["connector"])
	}
	if body["version"] != "test-version" {
		t.Fatalf("version = %v", body["version"])
	}
	if _, ok := body["directory"]; ok {
		t.Fatal("version response must not include directory reachability")
	}
}

func TestHealthDetailsDoesNotExposeSecretsOrDirectoryReachability(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz/details", nil)
	rec := httptest.NewRecorder()

	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body healthDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(body.Tenants) != 1 {
		t.Fatalf("Tenants len = %d", len(body.Tenants))
	}
	if body.Tenants[0].ConnectorID != "ww_tenant_a" {
		t.Fatalf("ConnectorID = %q", body.Tenants[0].ConnectorID)
	}
	if strings.Contains(rec.Body.String(), "active-secret") || strings.Contains(rec.Body.String(), "audit-secret") {
		t.Fatal("health details leaked secret material")
	}
}

func TestOperationsEndpointsRequireLoopbackOrExplicitExposure(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "203.0.113.10:49152"
	rec := httptest.NewRecorder()

	NewHandler("test-version").ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	loopbackReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	loopbackReq.RemoteAddr = "127.0.0.1:49152"
	loopbackRec := httptest.NewRecorder()
	NewHandler("test-version").ServeHTTP(loopbackRec, loopbackReq)
	if loopbackRec.Code != http.StatusOK {
		t.Fatalf("loopback status = %d, want %d", loopbackRec.Code, http.StatusOK)
	}
}

func TestMetricsEndpointCountsVerifyEventsWithoutUserIdentifiers(t *testing.T) {
	handler := newTestHandler()
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"wrong",
		"attribute_names":["uid"]
	}`, "nonce_123", []byte("active-secret"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body = %s", rec.Code, rec.Body.String())
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	handler.ServeHTTP(metricsRec, metricsReq)

	if metricsRec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", metricsRec.Code)
	}
	body := metricsRec.Body.String()
	if !strings.Contains(body, `wordwarden_events_total{event_type="directory_password.verify.failure"`) {
		t.Fatalf("metrics body missing failure counter: %s", body)
	}
	if strings.Contains(body, "alice") || strings.Contains(body, "wrong") || strings.Contains(body, "active-secret") {
		t.Fatalf("metrics leaked sensitive request data: %s", body)
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

func TestVerifyPasswordPolicyRequired(t *testing.T) {
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"must-change",
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
	if body.Result != "policy_required" || body.Reason != "must_change_password" {
		t.Fatalf("body = %#v", body)
	}
	if body.Subject != nil {
		t.Fatalf("policy_required response must not include subject: %#v", body.Subject)
	}
}

func TestVerifyPasswordSourceUnavailable(t *testing.T) {
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"source-down",
		"attribute_names":["uid"]
	}`, "nonce_123", []byte("active-secret"))

	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}

	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error.Code != "directory_unavailable" || !body.Error.Retryable {
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

func TestVerifyPasswordRejectsUnknownJSONField(t *testing.T) {
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct",
		"unexpected":true
	}`, "nonce_123", []byte("active-secret"))
	directory := &countingDirectory{}
	handler := newTestHandlerWithRuntime(TenantRuntime{
		TenantID:        "tenant-a",
		ConnectorID:     "ww_tenant_a",
		HMACVerifier:    testVerifier(),
		Directory:       directory,
		AuditHashSecret: []byte("audit-secret"),
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if directory.calls != 0 {
		t.Fatalf("directory calls = %d, want 0", directory.calls)
	}
	assertErrorCode(t, rec.Body.Bytes(), "malformed_request")
}

func TestVerifyPasswordRejectsEmptyPasswordBeforeDirectory(t *testing.T) {
	req := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":""
	}`, "nonce_123", []byte("active-secret"))
	directory := &countingDirectory{}
	handler := newTestHandlerWithRuntime(TenantRuntime{
		TenantID:        "tenant-a",
		ConnectorID:     "ww_tenant_a",
		HMACVerifier:    testVerifier(),
		Directory:       directory,
		AuditHashSecret: []byte("audit-secret"),
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if directory.calls != 0 {
		t.Fatalf("directory calls = %d, want 0", directory.calls)
	}
	assertErrorCode(t, rec.Body.Bytes(), "malformed_request")
}

func TestVerifyPasswordRejectsOversizedBody(t *testing.T) {
	body := `{"request_id":"req_123","tenant_id":"tenant-a","connector_id":"ww_tenant_a","username":"alice","password":"` +
		strings.Repeat("a", maxVerifyPasswordBodyBytes) + `"}`
	req := signedVerifyPasswordRequest(t, body, "nonce_123", []byte("active-secret"))

	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), "payload_too_large")
}

func TestVerifyPasswordUsesConfiguredRequestTimeout(t *testing.T) {
	deadline := make(chan time.Time, 1)
	handler := newTestHandlerWithRuntime(TenantRuntime{
		TenantID:         "tenant-a",
		ConnectorID:      "ww_tenant_a",
		HMACVerifier:     testVerifier(),
		Directory:        deadlineDirectory{deadline: deadline},
		AuditHashSecret:  []byte("audit-secret"),
		RequestTimeoutMS: 25,
	})
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
	got := <-deadline
	if got.IsZero() {
		t.Fatal("directory context deadline is not set")
	}
	remaining := time.Until(got)
	if remaining <= 0 || remaining > time.Second {
		t.Fatalf("deadline remaining = %s, want a short positive timeout", remaining)
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

func TestVerifyPasswordScopesReplayByConnectorAndKey(t *testing.T) {
	handler := NewHandler("test-version", HandlerOptions{
		Tenants: map[string]TenantRuntime{
			"ww_tenant_a": {
				TenantID:        "tenant-a",
				ConnectorID:     "ww_tenant_a",
				HMACVerifier:    testVerifier(),
				Directory:       fakeDirectory{},
				AuditHashSecret: []byte("audit-secret-a"),
			},
			"ww_tenant_b": {
				TenantID:        "tenant-b",
				ConnectorID:     "ww_tenant_b",
				HMACVerifier:    testVerifier(),
				Directory:       fakeDirectory{},
				AuditHashSecret: []byte("audit-secret-b"),
			},
		},
		Audit: audit.DiscardSink{},
	})

	bodyA := `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`
	reqA := signedVerifyPasswordRequestForConnector(t, bodyA, "req_123", "nonce_123", "ww_tenant_a", []byte("active-secret"))
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("tenant A status = %d body = %s", recA.Code, recA.Body.String())
	}

	bodyB := `{
		"request_id":"req_123",
		"tenant_id":"tenant-b",
		"connector_id":"ww_tenant_b",
		"username":"alice",
		"password":"correct"
	}`
	reqB := signedVerifyPasswordRequestForConnector(t, bodyB, "req_123", "nonce_123", "ww_tenant_b", []byte("active-secret"))
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("tenant B status = %d body = %s", recB.Code, recB.Body.String())
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
	rawEvent, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	if bytes.Contains(rawEvent, []byte("correct")) {
		t.Fatalf("audit event contains raw password: %s", rawEvent)
	}
	if bytes.Contains(rawEvent, []byte(`"username":"alice"`)) || bytes.Contains(rawEvent, []byte("alice")) {
		t.Fatalf("audit event contains raw username: %s", rawEvent)
	}
}

func BenchmarkVerifyPasswordSuccess(b *testing.B) {
	handler := newTestHandler()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		requestID := fmt.Sprintf("req_bench_%d", i)
		nonce := fmt.Sprintf("nonce_bench_%d", i)
		body := fmt.Sprintf(`{
			"request_id":%q,
			"tenant_id":"tenant-a",
			"connector_id":"ww_tenant_a",
			"username":"alice",
			"password":"correct",
			"attribute_names":["uid","mail"]
		}`, requestID)
		req := signedVerifyPasswordRequestWithID(
			b,
			body,
			requestID,
			nonce,
			[]byte("active-secret"),
		)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
	}
}

func TestVerifyPasswordEnforcesConnectorConcurrencyLimit(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	handler := newTestHandlerWithRuntime(TenantRuntime{
		TenantID:         "tenant-a",
		ConnectorID:      "ww_tenant_a",
		HMACVerifier:     testVerifier(),
		Directory:        blockingDirectory{started: started, release: release},
		AuditHashSecret:  []byte("audit-secret"),
		ConcurrencyLimit: 1,
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
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
			t.Errorf("first status = %d body = %s", rec.Code, rec.Body.String())
		}
	}()

	<-started

	body := `{
		"request_id":"req_456",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`
	req := signedVerifyPasswordRequest(t, body, "nonce_456", []byte("active-secret"))
	req.Header.Set(hmacadapter.HeaderRequestID, "req_456")
	resignRequest(t, req, []byte(body), []byte("active-secret"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d body = %s", rec.Code, rec.Body.String())
	}

	close(release)
	wg.Wait()
}

func TestVerifyPasswordDoesNotConnectorBlockAfterHMACFailures(t *testing.T) {
	handler := newTestHandlerWithRuntime(TenantRuntime{
		TenantID:        "tenant-a",
		ConnectorID:     "ww_tenant_a",
		HMACVerifier:    testVerifier(),
		Directory:       fakeDirectory{},
		AuditHashSecret: []byte("audit-secret"),
		StormProtection: StormProtectionPolicy{
			WindowMS: 60000,
			BlockMS:  60000,
		},
	})

	badReq := signedVerifyPasswordRequest(t, `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`, "nonce_123", []byte("wrong-secret"))
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d body = %s", badRec.Code, badRec.Body.String())
	}

	goodBody := `{
		"request_id":"req_456",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`
	goodReq := signedVerifyPasswordRequestWithID(t, goodBody, "req_456", "nonce_456", []byte("active-secret"))
	goodRec := httptest.NewRecorder()
	handler.ServeHTTP(goodRec, goodReq)
	if goodRec.Code != http.StatusOK {
		t.Fatalf("good request status = %d body = %s", goodRec.Code, goodRec.Body.String())
	}
}

func TestVerifyPasswordLimitsDirectoryErrorStorm(t *testing.T) {
	handler := newTestHandlerWithRuntime(TenantRuntime{
		TenantID:        "tenant-a",
		ConnectorID:     "ww_tenant_a",
		HMACVerifier:    testVerifier(),
		Directory:       errorDirectory{err: directory.ErrDirectoryUnavailable},
		AuditHashSecret: []byte("audit-secret"),
		StormProtection: StormProtectionPolicy{
			DirectoryErrorLimit: 1,
			WindowMS:            60000,
			BlockMS:             60000,
		},
	})

	firstBody := `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`
	firstReq := signedVerifyPasswordRequestWithID(t, firstBody, "req_123", "nonce_123", []byte("active-secret"))
	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, firstReq)
	if firstRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("first status = %d body = %s", firstRec.Code, firstRec.Body.String())
	}

	secondBody := `{
		"request_id":"req_456",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`
	secondReq := signedVerifyPasswordRequestWithID(t, secondBody, "req_456", "nonce_456", []byte("active-secret"))
	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d body = %s", secondRec.Code, secondRec.Body.String())
	}

	var body errorResponse
	if err := json.Unmarshal(secondRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error.Code != "directory_error_storm_limited" || !body.Error.Retryable {
		t.Fatalf("body = %#v", body)
	}
}

func TestVerifyPasswordLimitsSourceUnavailableStorm(t *testing.T) {
	handler := newTestHandlerWithRuntime(TenantRuntime{
		TenantID:        "tenant-a",
		ConnectorID:     "ww_tenant_a",
		HMACVerifier:    testVerifier(),
		Directory:       sourceUnavailableDirectory{},
		AuditHashSecret: []byte("audit-secret"),
		StormProtection: StormProtectionPolicy{
			DirectoryErrorLimit: 1,
			WindowMS:            60000,
			BlockMS:             60000,
		},
	})

	firstBody := `{
		"request_id":"req_123",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`
	firstReq := signedVerifyPasswordRequestWithID(t, firstBody, "req_123", "nonce_123", []byte("active-secret"))
	firstRec := httptest.NewRecorder()
	handler.ServeHTTP(firstRec, firstReq)
	if firstRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("first status = %d body = %s", firstRec.Code, firstRec.Body.String())
	}

	secondBody := `{
		"request_id":"req_456",
		"tenant_id":"tenant-a",
		"connector_id":"ww_tenant_a",
		"username":"alice",
		"password":"correct"
	}`
	secondReq := signedVerifyPasswordRequestWithID(t, secondBody, "req_456", "nonce_456", []byte("active-secret"))
	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d body = %s", secondRec.Code, secondRec.Body.String())
	}

	var body errorResponse
	if err := json.Unmarshal(secondRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error.Code != "directory_error_storm_limited" || !body.Error.Retryable {
		t.Fatalf("body = %#v", body)
	}
}

func assertErrorCode(t *testing.T, raw []byte, want string) {
	t.Helper()

	var body errorResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Error.Code != want {
		t.Fatalf("error code = %q, want %q", body.Error.Code, want)
	}
}

func newTestHandler() http.Handler {
	return newTestHandlerWithAudit(audit.DiscardSink{})
}

func newTestHandlerWithAudit(sink audit.Sink) http.Handler {
	return NewHandler("test-version", HandlerOptions{
		Tenants: map[string]TenantRuntime{
			"ww_tenant_a": {
				TenantID:        "tenant-a",
				ConnectorID:     "ww_tenant_a",
				HMACVerifier:    testVerifier(),
				Directory:       fakeDirectory{},
				AuditHashSecret: []byte("audit-secret"),
			},
		},
		Audit:            sink,
		ExposeOperations: true,
	})
}

func newTestHandlerWithRuntime(runtime TenantRuntime) http.Handler {
	return NewHandler("test-version", HandlerOptions{
		Tenants:          map[string]TenantRuntime{"ww_tenant_a": runtime},
		Audit:            audit.DiscardSink{},
		ExposeOperations: true,
	})
}

func testVerifier() hmacadapter.Verifier {
	now := fixedHMACTime()
	return hmacadapter.NewVerifier(hmacadapter.KeySet{
		Active: hmacadapter.Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })
}

type testHelper interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func signedVerifyPasswordRequest(t testHelper, body string, nonce string, secret []byte) *http.Request {
	return signedVerifyPasswordRequestWithID(t, body, "req_123", nonce, secret)
}

func signedVerifyPasswordRequestWithID(t testHelper, body string, requestID string, nonce string, secret []byte) *http.Request {
	return signedVerifyPasswordRequestForConnector(t, body, requestID, nonce, "ww_tenant_a", secret)
}

func signedVerifyPasswordRequestForConnector(t testHelper, body string, requestID string, nonce string, connectorID string, secret []byte) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hmacadapter.HeaderConnectorID, connectorID)
	req.Header.Set(hmacadapter.HeaderKeyID, "kid-active")
	req.Header.Set(hmacadapter.HeaderRequestID, requestID)
	req.Header.Set(hmacadapter.HeaderTimestamp, fixedHMACTime().Format(time.RFC3339))
	req.Header.Set(hmacadapter.HeaderNonce, nonce)
	req.Header.Set(hmacadapter.HeaderSignedHeaders, "content-type;x-authrim-connector-id;x-authrim-key-id;x-authrim-request-id;x-authrim-timestamp;x-authrim-nonce")

	resignRequest(t, req, []byte(body), secret)
	return req
}

func resignRequest(t testHelper, req *http.Request, body []byte, secret []byte) {
	t.Helper()
	canonical, err := hmacadapter.CanonicalRequest(
		req,
		body,
		[]string{"content-type", "x-authrim-connector-id", "x-authrim-key-id", "x-authrim-nonce", "x-authrim-request-id", "x-authrim-timestamp"},
		req.Header.Get(hmacadapter.HeaderTimestamp),
		req.Header.Get(hmacadapter.HeaderNonce),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(hmacadapter.HeaderSignature, hmacadapter.SignCanonical(canonical, secret))
}

func fixedHMACTime() time.Time {
	return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
}

type fakeDirectory struct{}

func (fakeDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

type blockingDirectory struct {
	started chan struct{}
	release chan struct{}
}

func (blockingDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

func (d blockingDirectory) VerifyPassword(context.Context, directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	close(d.started)
	<-d.release
	return directory.VerifyPasswordResult{Success: true}, nil
}

type errorDirectory struct {
	err error
}

func (errorDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

func (d errorDirectory) VerifyPassword(context.Context, directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	if d.err == nil {
		return directory.VerifyPasswordResult{}, errors.New("directory error")
	}
	return directory.VerifyPasswordResult{}, d.err
}

type sourceUnavailableDirectory struct{}

func (sourceUnavailableDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

func (sourceUnavailableDirectory) VerifyPassword(context.Context, directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	return directory.SourceUnavailableVerification(""), nil
}

type countingDirectory struct {
	calls int
}

func (*countingDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

func (d *countingDirectory) VerifyPassword(context.Context, directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	d.calls++
	return directory.VerifyPasswordResult{Success: true}, nil
}

type deadlineDirectory struct {
	deadline chan time.Time
}

func (deadlineDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

func (d deadlineDirectory) VerifyPassword(ctx context.Context, _ directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	deadline, _ := ctx.Deadline()
	d.deadline <- deadline
	return directory.VerifyPasswordResult{Success: true}, nil
}

type memoryAuditSink struct {
	events []audit.Event
}

func (s *memoryAuditSink) WriteEvent(_ context.Context, event audit.Event) error {
	s.events = append(s.events, event)
	return nil
}

func (fakeDirectory) VerifyPassword(_ context.Context, request directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	if request.Password == "source-down" {
		return directory.SourceUnavailableVerification(""), nil
	}
	if request.Password == "must-change" {
		return directory.PolicyRequiredVerification(directory.ReasonMustChangePassword), nil
	}
	if request.Password != "correct" {
		return directory.FailedVerification(directory.ReasonInvalidCredentials), nil
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
	return directory.SuccessfulVerification(
		directory.Subject{
			DirectoryID: "uid=alice,ou=People,dc=example,dc=com",
			Username:    request.Username,
		},
		attrs,
	), nil
}
