package relay

import (
	"testing"
)

func TestAuthCanonicalAndSignature(t *testing.T) {
	canonical := AuthCanonical(AuthCanonicalInput{
		TenantID:    "tenant-a",
		ConnectorID: "ww_tenant_a",
		KeyID:       "kid-active",
		ChallengeID: "challenge-123",
		Nonce:       "nonce-123",
		Timestamp:   "2026-06-23T00:00:00.000Z",
	})

	want := "AUTHRIM-WORDWARDEN-RELAY-HMAC-SHA256\n" +
		"tenant-a\n" +
		"ww_tenant_a\n" +
		"kid-active\n" +
		"challenge-123\n" +
		"nonce-123\n" +
		"2026-06-23T00:00:00.000Z"
	if canonical != want {
		t.Fatalf("canonical = %q, want %q", canonical, want)
	}

	signature := SignCanonical(canonical, []byte("active-secret"))
	tampered := SignCanonical(canonical+"x", []byte("active-secret"))
	if len(signature) != 64 {
		t.Fatalf("signature length = %d, want 64", len(signature))
	}
	if signature == tampered {
		t.Fatal("signature did not change after canonical tampering")
	}
}

func TestParseRelayURLRequiresWSSExceptLocalhost(t *testing.T) {
	if _, err := parseRelayURL("wss://login.example.com/api/auth/directory-relay/connect/tenant-a/ww"); err != nil {
		t.Fatalf("parseRelayURL(wss) error = %v", err)
	}
	if _, err := parseRelayURL("ws://localhost:8787/api/auth/directory-relay/connect/tenant-a/ww"); err != nil {
		t.Fatalf("parseRelayURL(localhost ws) error = %v", err)
	}
	if _, err := parseRelayURL("ws://login.example.com/api/auth/directory-relay/connect/tenant-a/ww"); err == nil {
		t.Fatal("parseRelayURL(non-local ws) error = nil, want error")
	}
}
