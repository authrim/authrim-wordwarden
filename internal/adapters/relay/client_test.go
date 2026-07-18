package relay

import (
	"context"
	"testing"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/core/audit"
	"github.com/authrim/authrim-wordwarden/internal/core/directory"
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

func TestProcessVerifyRequestAuditsAndRejectsReplay(t *testing.T) {
	sink := &memoryAuditSink{}
	client := newTestClient(t, fakeDirectory{}, sink)
	request := validVerifyRequest()
	first := client.processVerifyRequest(context.Background(), request)
	if response, ok := first.(verifyResponseMessage); !ok || response.Result != string(directory.CredentialResultFailure) {
		t.Fatalf("first response = %#v", first)
	}
	second := client.processVerifyRequest(context.Background(), request)
	errorResponse, ok := second.(verifyErrorMessage)
	if !ok {
		t.Fatalf("second response = %#v", second)
	}
	if errorResponse.Error.Code != "replay_detected" || errorResponse.Error.Retryable {
		t.Fatalf("replay error = %#v", errorResponse.Error)
	}
	if len(sink.events) != 2 {
		t.Fatalf("audit events = %d", len(sink.events))
	}
	if sink.events[0].EventType != audit.EventVerifyFailure {
		t.Fatalf("first audit event = %#v", sink.events[0])
	}
	if sink.events[1].EventType != audit.EventReplayDetected {
		t.Fatalf("second audit event = %#v", sink.events[1])
	}
	if sink.events[0].UsernameHash == "" || sink.events[0].UsernameHash == "alice" {
		t.Fatalf("username hash was not recorded safely: %#v", sink.events[0])
	}
}

func TestProcessVerifyRequestRejectsSameRequestIDDifferentMessageID(t *testing.T) {
	client := newTestClient(t, fakeDirectory{}, &memoryAuditSink{})
	first := validVerifyRequest()
	first.ID = "msg-1"
	first.RequestID = "req-replay"
	if response, ok := client.processVerifyRequest(context.Background(), first).(verifyResponseMessage); !ok || response.Result != string(directory.CredentialResultFailure) {
		t.Fatalf("first response = %#v", response)
	}
	second := validVerifyRequest()
	second.ID = "msg-2"
	second.RequestID = "req-replay"
	response := client.processVerifyRequest(context.Background(), second).(verifyErrorMessage)
	if response.Error.Code != "replay_detected" {
		t.Fatalf("second response = %#v", response.Error)
	}
}

func TestProcessVerifyRequestStormLimitsDirectoryErrors(t *testing.T) {
	client := newTestClient(t, errorDirectory{}, &memoryAuditSink{})
	client.config.Protection = ProtectionPolicy{WindowMS: 10000, BlockMS: 30000, DirectoryErrorLimit: 2}
	client.storms = newRelayStorms(client.config.Protection)

	first := validVerifyRequest()
	first.ID = "msg-1"
	first.RequestID = "req-1"
	if response := client.processVerifyRequest(context.Background(), first).(verifyErrorMessage); response.Error.Code != "directory_unavailable" {
		t.Fatalf("first error = %#v", response.Error)
	}
	second := validVerifyRequest()
	second.ID = "msg-2"
	second.RequestID = "req-2"
	if response := client.processVerifyRequest(context.Background(), second).(verifyErrorMessage); response.Error.Code != "directory_unavailable" {
		t.Fatalf("second error = %#v", response.Error)
	}
	third := validVerifyRequest()
	third.ID = "msg-3"
	third.RequestID = "req-3"
	response := client.processVerifyRequest(context.Background(), third).(verifyErrorMessage)
	if response.Error.Code != "directory_error_storm_limited" || !response.Error.Retryable {
		t.Fatalf("storm response = %#v", response.Error)
	}
}

func TestProcessVerifyRequestStormLimitsMalformedRequests(t *testing.T) {
	client := newTestClient(t, fakeDirectory{}, &memoryAuditSink{})
	client.config.Protection = ProtectionPolicy{WindowMS: 10000, BlockMS: 30000, MalformedRequestLimit: 1}
	client.storms = newRelayStorms(client.config.Protection)

	invalid := verifyRequestMessage{Type: "verify.request", Protocol: Protocol, ProtocolVersion: ProtocolVersion, MinSupportedVersion: MinSupportedVersion}
	if response := client.processVerifyRequest(context.Background(), invalid).(verifyErrorMessage); response.Error.Code != "invalid_relay_request" {
		t.Fatalf("first malformed response = %#v", response.Error)
	}
	response := client.processVerifyRequest(context.Background(), invalid).(verifyErrorMessage)
	if response.Error.Code != "malformed_request_storm_limited" || !response.Error.Retryable {
		t.Fatalf("storm response = %#v", response.Error)
	}
}

func newTestClient(t *testing.T, dir directory.Client, sink audit.Sink) *Client {
	t.Helper()
	client, err := NewClient(Config{
		URL:             "wss://login.example.com/api/auth/directory-relay/connect/tenant-a/wwcon_8K4M2Q9F7D3H6P1X",
		TenantID:        "tenant-a",
		ConnectorID:     "wwcon_8K4M2Q9F7D3H6P1X",
		InstanceID:      "wwi_1234567890123456789012",
		KeyID:           "kid-active",
		Secret:          []byte("active-secret"),
		Directory:       dir,
		Audit:           sink,
		AuditHashSecret: []byte("audit-secret"),
		RequestTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

func validVerifyRequest() verifyRequestMessage {
	return verifyRequestMessage{
		Type:                "verify.request",
		Protocol:            Protocol,
		ProtocolVersion:     ProtocolVersion,
		MinSupportedVersion: MinSupportedVersion,
		ID:                  "msg-1",
		RequestID:           "req-1",
		TenantID:            "tenant-a",
		ConnectorID:         "wwcon_8K4M2Q9F7D3H6P1X",
		Username:            "alice",
		Password:            "wrong",
	}
}

type memoryAuditSink struct {
	events []audit.Event
}

func (s *memoryAuditSink) WriteEvent(_ context.Context, event audit.Event) error {
	s.events = append(s.events, event)
	return nil
}

type fakeDirectory struct{}

func (fakeDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

func (fakeDirectory) VerifyPassword(context.Context, directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	return directory.FailedVerification(directory.ReasonInvalidCredentials), nil
}

type errorDirectory struct{}

func (errorDirectory) TestConnection(context.Context, directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	return directory.TestConnectionResult{}, nil
}

func (errorDirectory) VerifyPassword(context.Context, directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	return directory.VerifyPasswordResult{}, directory.ErrDirectoryUnavailable
}

var _ directory.Client = fakeDirectory{}
var _ directory.Client = errorDirectory{}
