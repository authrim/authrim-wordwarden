package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/ports/config"
)

func TestHeartbeatClientSendsSignedHeartbeat(t *testing.T) {
	var capturedBody []byte
	var capturedKeyID string
	var capturedTimestamp string
	var capturedSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/directory-connectors/heartbeat/tenant-a/wwcon_8K4M2Q9F7D3H6P1X" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		capturedKeyID = r.Header.Get("X-Authrim-Heartbeat-Key-Id")
		capturedTimestamp = r.Header.Get("X-Authrim-Heartbeat-Timestamp")
		capturedSignature = r.Header.Get("X-Authrim-Heartbeat-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tenant := config.TenantConfig{
		TenantID:    "tenant-a",
		ConnectorID: "wwcon_8K4M2Q9F7D3H6P1X",
		Authrim: config.AuthrimConfig{
			Heartbeat: config.HeartbeatConfig{
				Enabled:     true,
				URL:         server.URL + "/api/auth/directory-connectors/heartbeat/tenant-a/wwcon_8K4M2Q9F7D3H6P1X",
				Transport:   "direct",
				DisplayName: "campus a",
				Key:         config.HMACKeyConfig{KID: "hb-active"},
				TimeoutMS:   1000,
			},
		},
		LDAP: config.LDAPConfig{
			URL: "ldaps://ldap.example.com:636",
			TLS: config.LDAPTLSConfig{Verify: true},
			DirectoryProfile: config.DirectoryProfileConfig{
				Name:             "openldap",
				SubjectAttribute: "entryUUID",
			},
			LookupMode: "search_then_bind",
			Attributes: []string{"uid", "mail"},
		},
	}
	client := heartbeatClient{
		tenant:     tenant,
		instanceID: "wwi_1234567890123456789012",
		startedAt:  time.Date(2026, 6, 24, 1, 2, 3, 0, time.UTC),
		keyID:      "hb-active",
		secret:     []byte("heartbeat-secret"),
		httpClient: server.Client(),
	}

	if err := client.send(context.Background()); err != nil {
		t.Fatalf("send() error = %v", err)
	}
	if capturedKeyID != "hb-active" {
		t.Fatalf("key id = %q", capturedKeyID)
	}
	canonical := buildHeartbeatCanonical(
		"tenant-a",
		"wwcon_8K4M2Q9F7D3H6P1X",
		"wwi_1234567890123456789012",
		"hb-active",
		capturedTimestamp,
		capturedBody,
	)
	if capturedSignature != "sha256="+signHeartbeatCanonical(canonical, []byte("heartbeat-secret")) {
		t.Fatalf("signature mismatch")
	}
	var payload heartbeatPayload
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	if payload.InstanceID != "wwi_1234567890123456789012" || payload.DisplayName != "campus a" {
		t.Fatalf("payload identity = %#v", payload)
	}
	if !strings.HasPrefix(payload.ConfigFingerprint, "sha256:") {
		t.Fatalf("fingerprint = %q", payload.ConfigFingerprint)
	}
}
