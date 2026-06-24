package relay

import (
	"testing"
)

func TestAuthCanonicalAndSignature(t *testing.T) {
	canonical := AuthCanonical(AuthCanonicalInput{
		TenantID:            "tenant-a",
		ConnectorID:         "wwcon_8K4M2Q9F7D3H6P1X",
		KeyID:               "kid-active",
		ProtocolVersion:     ProtocolVersion,
		MinSupportedVersion: MinSupportedVersion,
		ChallengeID:         "challenge-123",
		Nonce:               "nonce-123",
		Timestamp:           "2026-06-23T00:00:00.000Z",
	})

	want := "AUTHRIM-WORDWARDEN-RELAY-HMAC-SHA256\n" +
		"tenant-a\n" +
		"wwcon_8K4M2Q9F7D3H6P1X\n" +
		"kid-active\n" +
		"1\n" +
		"1\n" +
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

func TestRelayProtocolCompatibility(t *testing.T) {
	if !relayProtocolCompatible(envelope{ProtocolVersion: 1, MinSupportedVersion: 1}) {
		t.Fatal("protocol v1 should be compatible")
	}
	if relayProtocolCompatible(envelope{ProtocolVersion: 0, MinSupportedVersion: 1}) {
		t.Fatal("protocol version below minimum should be incompatible")
	}
	if relayProtocolCompatible(envelope{ProtocolVersion: 1, MinSupportedVersion: 2}) {
		t.Fatal("minimum supported version above local version should be incompatible")
	}
}

func TestValidateRelayURLBinding(t *testing.T) {
	err := validateRelayURLBinding(
		"wss://login.example.com/api/auth/directory-relay/connect/tenant-a/wwcon_8K4M2Q9F7D3H6P1X",
		"tenant-a",
		"wwcon_8K4M2Q9F7D3H6P1X",
	)
	if err != nil {
		t.Fatalf("validateRelayURLBinding() error = %v", err)
	}
	if err := validateRelayURLBinding(
		"wss://login.example.com/api/auth/directory-relay/connect/tenant-b/wwcon_8K4M2Q9F7D3H6P1X",
		"tenant-a",
		"wwcon_8K4M2Q9F7D3H6P1X",
	); err == nil {
		t.Fatal("validateRelayURLBinding(tenant mismatch) error = nil, want error")
	}
	if err := validateRelayURLBinding(
		"wss://login.example.com/api/auth/directory-relay/connect/tenant-a/other",
		"tenant-a",
		"wwcon_8K4M2Q9F7D3H6P1X",
	); err == nil {
		t.Fatal("validateRelayURLBinding(connector mismatch) error = nil, want error")
	}
}
