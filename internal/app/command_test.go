package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testConfig = `
deployment:
  mode: "single_tenant"
server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.com"
tenants:
  - tenant_id: "tenant-a"
    connector_id: "wwcon_8K4M2Q9F7D3H6P1X"
    authrim:
      hmac_keys:
        active:
          kid: "kid_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
    ldap:
      url: "ldaps://ldap.example.com:636"
      tls:
        verify: true
        server_name: "ldap.example.com"
      lookup_mode: "search_then_bind"
      username:
        allowed_formats: ["local_part"]
        allowed_domains: ["example.com"]
        normalization:
          trim: true
          unicode: "NFKC"
          case: "lower"
          reject_domain_mismatch: true
      bind_dn: "uid=authrim,ou=system,dc=example,dc=com"
      bind_password_ref: "env:LDAP_BIND_PASSWORD"
      base_dn: "dc=example,dc=com"
      user_filter: "(uid={username})"
      attributes: ["uid"]
`

func TestDoctorCommandPrintsRedactedReadinessChecks(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--config", configPath, "doctor"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"ok\tconfig.tenants\t1 tenant(s)",
		"ok\ttenant.tenant-a.connector_id\twwcon_8K4M2Q9F7D3H6P1X",
		"secret reference configured",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("doctor output = %q, want %q", text, want)
		}
	}
	if strings.Contains(text, "LDAP_BIND_PASSWORD") {
		t.Fatalf("doctor output leaked secret ref detail: %q", text)
	}
}

func TestUpdateCheckCommandReportsAffectedAdvisories(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "stable.json")
	feed := `{
  "channel": "stable",
  "latest_version": "0.1.0-beta.2",
  "release_url": "https://github.com/authrim/authrim-wordwarden/releases/tag/v0.1.0-beta.2",
  "advisories": [
    {
      "advisory_id": "WW-2026-0001",
      "affected_versions": ["<0.2.0"],
      "fixed_version": "0.1.0-beta.2",
      "severity": "high",
      "summary": "Test advisory"
    }
  ]
}`
	if err := os.WriteFile(feedPath, []byte(feed), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"update",
		"check",
		"--feed-url",
		feedPath,
		"--current-version",
		"0.1.0-beta.1",
		"--allow-unsigned-feed",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"current_version=0.1.0-beta.1",
		"latest_version=0.1.0-beta.2",
		"update_available=true",
		"security_advisories=1",
		"advisory=WW-2026-0001 severity=high fixed_version=0.1.0-beta.2",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("update check output = %q, want %q", text, want)
		}
	}
}

func TestUpdateCheckRequiresSignedFeedByDefault(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "stable.json")
	if err := os.WriteFile(feedPath, []byte(`{"channel":"stable","latest_version":"0.1.0-beta.2","advisories":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cmd := NewRootCommand()
	cmd.SetArgs([]string{"update", "check", "--feed-url", feedPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want trusted key requirement")
	}
	if !strings.Contains(err.Error(), "--trusted-feed-key is required") {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestUpdateCheckRejectsHTTPFeedURL(t *testing.T) {
	_, err := readAdvisoryFeed(contextWithTestTimeout(t), "http://updates.example.com/stable.json", time.Second)
	if err == nil {
		t.Fatal("readAdvisoryFeed() error = nil, want HTTPS requirement")
	}
	if !strings.Contains(err.Error(), "must use https://") {
		t.Fatalf("readAdvisoryFeed() error = %v", err)
	}
}

func TestUpdateCheckRejectsRemoteUnsignedFeed(t *testing.T) {
	cmd := NewRootCommand()
	cmd.SetArgs([]string{
		"update",
		"check",
		"--feed-url",
		"https://updates.example.com/stable.json",
		"--allow-unsigned-feed",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want local-only unsigned feed requirement")
	}
	if !strings.Contains(err.Error(), "local file feeds") {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestUpdateCheckAcceptsSignedFeedWithTrustedKey(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "stable.json")
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	feed := advisoryFeed{
		Channel:       "stable",
		LatestVersion: "0.1.0-beta.2",
		ReleaseURL:    "https://github.com/authrim/authrim-wordwarden/releases/tag/v0.1.0-beta.2",
		Advisories: []releaseAdvisory{{
			AdvisoryID:       "WW-2026-0001",
			AffectedVersions: []string{"<0.2.0"},
			FixedVersion:     "0.1.0-beta.2",
			Severity:         "high",
			Summary:          "Test advisory",
		}},
	}
	payload, err := json.Marshal(feed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	feed.Signature = &advisoryFeedSignature{
		Algorithm: "ed25519",
		KeyID:     "test-key",
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	data, err := json.Marshal(feed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(feedPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		"update",
		"check",
		"--feed-url",
		feedPath,
		"--trusted-feed-key",
		base64.RawURLEncoding.EncodeToString(publicKey),
		"--current-version",
		"0.1.0-beta.1",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(out.String(), "update_available=true") {
		t.Fatalf("update check output = %q", out.String())
	}
}

func TestVerifyAdvisoryFeedSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	feed := advisoryFeed{
		Channel:       "stable",
		LatestVersion: "0.1.0-beta.2",
		ReleaseURL:    "https://github.com/authrim/authrim-wordwarden/releases/tag/v0.1.0-beta.2",
		Advisories: []releaseAdvisory{{
			AdvisoryID:       "WW-2026-0001",
			AffectedVersions: []string{"<0.2.0"},
			FixedVersion:     "0.1.0-beta.2",
			Severity:         "high",
			Summary:          "Test advisory",
		}},
	}
	payload, err := json.Marshal(feed)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	feed.Signature = &advisoryFeedSignature{
		Algorithm: "ed25519",
		KeyID:     "test-key",
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}

	trustedKey := base64.RawURLEncoding.EncodeToString(publicKey)
	if err := verifyAdvisoryFeedTrust(feed, trustedKey, false); err != nil {
		t.Fatalf("verifyAdvisoryFeedTrust() error = %v", err)
	}

	feed.LatestVersion = "0.1.0-beta.3"
	if err := verifyAdvisoryFeedTrust(feed, trustedKey, false); err == nil {
		t.Fatal("verifyAdvisoryFeedTrust() error = nil, want tamper detection")
	}
}

func contextWithTestTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
