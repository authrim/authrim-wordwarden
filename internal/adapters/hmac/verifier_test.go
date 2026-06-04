package hmacadapter

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestVerifierAcceptsActiveKey(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	req := signedRequest(t, "kid-active", []byte("active-secret"), now)

	verifier := NewVerifier(KeySet{
		Active: Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })

	result, body, err := verifier.Verify(req)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.KeyID != "kid-active" {
		t.Fatalf("KeyID = %q", result.KeyID)
	}
	if string(body) != `{"username":"alice"}` {
		t.Fatalf("body = %q", body)
	}
}

func TestVerifierAcceptsPreviousKey(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	req := signedRequest(t, "kid-previous", []byte("previous-secret"), now)
	previous := Key{KID: "kid-previous", Secret: []byte("previous-secret")}

	verifier := NewVerifier(KeySet{
		Active:   Key{KID: "kid-active", Secret: []byte("active-secret")},
		Previous: &previous,
	}).WithClock(func() time.Time { return now })

	if _, _, err := verifier.Verify(req); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifierRejectsBadSignature(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	req := signedRequest(t, "kid-active", []byte("wrong-secret"), now)

	verifier := NewVerifier(KeySet{
		Active: Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })

	if _, _, err := verifier.Verify(req); err != ErrInvalidSignature {
		t.Fatalf("Verify() error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestVerifierRejectsSignedHeaderTampering(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	req := signedRequest(t, "kid-active", []byte("active-secret"), now)
	req.Header.Set(HeaderRequestID, "req_tampered")

	verifier := NewVerifier(KeySet{
		Active: Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })

	if _, _, err := verifier.Verify(req); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestVerifierRejectsUnsignedRequiredHeader(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	req := signedRequest(t, "kid-active", []byte("active-secret"), now)
	req.Header.Set(HeaderSignedHeaders, "content-type;x-authrim-connector-id;x-authrim-key-id;x-authrim-timestamp;x-authrim-nonce")

	verifier := NewVerifier(KeySet{
		Active: Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })

	if _, _, err := verifier.Verify(req); !errors.Is(err, ErrUnsignedHeader) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrUnsignedHeader)
	}
}

func TestVerifierRejectsDuplicateSignedHeaderValue(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	req := signedRequest(t, "kid-active", []byte("active-secret"), now)
	req.Header.Add(HeaderRequestID, "req_456")

	verifier := NewVerifier(KeySet{
		Active: Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })

	if _, _, err := verifier.Verify(req); !errors.Is(err, ErrMalformedSignedField) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrMalformedSignedField)
	}
}

func TestVerifierRejectsStaleTimestamp(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	req := signedRequest(t, "kid-active", []byte("active-secret"), now.Add(-10*time.Minute))

	verifier := NewVerifier(KeySet{
		Active: Key{KID: "kid-active", Secret: []byte("active-secret")},
	}).WithClock(func() time.Time { return now })

	if _, _, err := verifier.Verify(req); err != ErrStaleTimestamp {
		t.Fatalf("Verify() error = %v, want %v", err, ErrStaleTimestamp)
	}
}

func signedRequest(t *testing.T, kid string, secret []byte, now time.Time) *http.Request {
	t.Helper()

	body := []byte(`{"username":"alice"}`)
	req, err := http.NewRequest(http.MethodPost, "https://wordwarden.example.com/v1/auth/verify-password?b=2&a=1", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderConnectorID, "ww_tenant_a")
	req.Header.Set(HeaderKeyID, kid)
	req.Header.Set(HeaderRequestID, "req_123")
	req.Header.Set(HeaderTimestamp, now.Format(time.RFC3339))
	req.Header.Set(HeaderNonce, "nonce_123")
	req.Header.Set(HeaderSignedHeaders, "content-type;x-authrim-connector-id;x-authrim-key-id;x-authrim-request-id;x-authrim-timestamp;x-authrim-nonce")

	signedHeaders := parseSignedHeaders(req.Header.Get(HeaderSignedHeaders))
	canonical, err := CanonicalRequest(req, body, signedHeaders, req.Header.Get(HeaderTimestamp), req.Header.Get(HeaderNonce))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderSignature, SignCanonical(canonical, secret))
	return req
}
