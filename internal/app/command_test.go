package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
