package config

import (
	"strings"
	"testing"
)

const validConfig = `
deployment:
  mode: "single_tenant"
server:
  listen: "127.0.0.1:8080"
  public_base_url: "https://wordwarden.example.com"
tenants:
  - tenant_id: "tenant-a"
    connector_id: "ww_tenant_a"
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
      filter_template_mode: "builtin_or_template"
      attributes: ["uid"]
`

func TestParseValidConfig(t *testing.T) {
	cfg, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Deployment.Mode != "single_tenant" {
		t.Fatalf("Deployment.Mode = %q", cfg.Deployment.Mode)
	}
	if cfg.Tenants[0].Timeouts.RequestMS != 2500 {
		t.Fatalf("default request timeout = %d", cfg.Tenants[0].Timeouts.RequestMS)
	}
	if cfg.Tenants[0].Protection.HMACFailureLimit != 30 {
		t.Fatalf("default hmac failure limit = %d", cfg.Tenants[0].Protection.HMACFailureLimit)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	_, err := Parse([]byte(validConfig + "\nunknown_field: true\n"))
	if err == nil {
		t.Fatal("Parse() error = nil, want unknown field error")
	}
	if !strings.Contains(err.Error(), "field unknown_field not found") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseAllowsExperimentalNamespace(t *testing.T) {
	_, err := Parse([]byte(validConfig + "\nexperimental:\n  future_flag: true\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsSingleTenantWithMultipleTenants(t *testing.T) {
	multi := strings.Replace(validConfig, `tenants:
  - tenant_id: "tenant-a"`, `tenants:
  - tenant_id: "tenant-a"`, 1)
	multi += `
  - tenant_id: "tenant-b"
    connector_id: "ww_tenant_b"
    authrim:
      hmac_keys:
        active:
          kid: "kid_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_SECRET_ACTIVE_B"
      audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET_B"
    ldap:
      url: "ldaps://ldap-b.example.com:636"
      tls:
        verify: true
      bind_dn: "uid=authrim,ou=system,dc=example,dc=com"
      bind_password_ref: "env:LDAP_BIND_PASSWORD_B"
      base_dn: "dc=example,dc=com"
      user_filter: "(uid={username})"
      attributes: ["uid"]
`
	_, err := Parse([]byte(multi))
	if err == nil {
		t.Fatal("Parse() error = nil, want single_tenant tenant count error")
	}
	if !strings.Contains(err.Error(), "single_tenant requires exactly one tenant") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsUnsupportedLookupMode(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `lookup_mode: "magic_bind"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want lookup_mode error")
	}
	if !strings.Contains(err.Error(), "lookup_mode must be search_then_bind, dn_template, or direct_bind") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRequiresDNTemplateForDNTemplateMode(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `lookup_mode: "dn_template"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want dn_template error")
	}
	if !strings.Contains(err.Error(), "dn_template is required when lookup_mode is dn_template") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseAllowsDirectBindWithoutServiceBind(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `lookup_mode: "direct_bind"`, 1)
	raw = strings.Replace(raw, `      bind_dn: "uid=authrim,ou=system,dc=example,dc=com"
      bind_password_ref: "env:LDAP_BIND_PASSWORD"
      base_dn: "dc=example,dc=com"
      user_filter: "(uid={username})"
`, "", 1)

	_, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsInvalidProtectionLimit(t *testing.T) {
	raw := validConfig + `
    protection:
      max_concurrent_requests: 8
      storm_window_ms: 10000
      storm_block_ms: 30000
      hmac_failure_limit: -1
      malformed_request_limit: 20
      replay_limit: 10
      directory_error_limit: 5
`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want protection error")
	}
	if !strings.Contains(err.Error(), "protection.hmac_failure_limit must be positive") {
		t.Fatalf("Parse() error = %v", err)
	}
}
