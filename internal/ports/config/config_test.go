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
	if cfg.Tenants[0].LDAP.DirectoryProfile.Name != "generic" {
		t.Fatalf("default directory profile = %q", cfg.Tenants[0].LDAP.DirectoryProfile.Name)
	}
	if cfg.Server.StateDir != ".authrim-wordwarden" {
		t.Fatalf("default state dir = %q", cfg.Server.StateDir)
	}
	if cfg.Tenants[0].Authrim.Heartbeat.IntervalMS != 300000 {
		t.Fatalf("default heartbeat interval = %d", cfg.Tenants[0].Authrim.Heartbeat.IntervalMS)
	}
}

func TestParseRejectsMutableConnectorIDFormat(t *testing.T) {
	raw := strings.Replace(validConfig, `connector_id: "wwcon_8K4M2Q9F7D3H6P1X"`, `connector_id: "campus"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want connector id format error")
	}
	if !strings.Contains(err.Error(), "connector_id must be wwcon_ followed by 16 alphanumeric characters") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseAppliesActiveDirectoryProfileDefaults(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `directory_profile:
        name: "active_directory"
      lookup_mode: "search_then_bind"`, 1)

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	profile := cfg.Tenants[0].LDAP.DirectoryProfile
	if profile.SubjectAttribute != "objectGUID" {
		t.Fatalf("SubjectAttribute = %q", profile.SubjectAttribute)
	}
	if profile.GroupStrategy != "ad_matching_rule" {
		t.Fatalf("GroupStrategy = %q", profile.GroupStrategy)
	}
	if cfg.Tenants[0].LDAP.Groups.SearchMemberAttribute != "member" {
		t.Fatalf("SearchMemberAttribute = %q", cfg.Tenants[0].LDAP.Groups.SearchMemberAttribute)
	}
}

func TestParseAllowsPagedSearchControls(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `directory_profile:
        name: "openldap"
        paged_search:
          enabled: true
          page_size: 250
          max_entries: 1000
          timeout_ms: 2000
      lookup_mode: "search_then_bind"`, 1)

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	paged := cfg.Tenants[0].LDAP.DirectoryProfile.PagedSearch
	if !paged.Enabled || paged.PageSize != 250 || paged.MaxEntries != 1000 || paged.TimeoutMS != 2000 {
		t.Fatalf("PagedSearch = %#v", paged)
	}
}

func TestParseRejectsExcessivePagedSearchControls(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `directory_profile:
        name: "openldap"
        paged_search:
          enabled: true
          page_size: 10001
          max_entries: 100001
          timeout_ms: 60001
      lookup_mode: "search_then_bind"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want paged search bounds errors")
	}
	for _, want := range []string{
		"paged_search.page_size must be 10000 or less",
		"paged_search.max_entries must be 100000 or less",
		"paged_search.timeout_ms must be 60000 or less",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Parse() error = %v, want %q", err, want)
		}
	}
}

func TestParseAllowsMultipleLDAPSURLs(t *testing.T) {
	raw := strings.Replace(validConfig, `url: "ldaps://ldap.example.com:636"`, `urls:
        - "ldaps://ldap-a.example.com:636"
        - "ldaps://ldap-b.example.com:636"`, 1)

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(cfg.Tenants[0].LDAP.URLs) != 2 {
		t.Fatalf("LDAP.URLs = %#v", cfg.Tenants[0].LDAP.URLs)
	}
}

func TestParseAllowsStartTLSLDAPURL(t *testing.T) {
	raw := strings.Replace(validConfig, `url: "ldaps://ldap.example.com:636"`, `url: "ldap://ldap.example.com:389"`, 1)
	raw = strings.Replace(raw, `server_name: "ldap.example.com"`, `server_name: "ldap.example.com"
        start_tls: true`, 1)

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.Tenants[0].LDAP.TLS.StartTLS {
		t.Fatal("LDAP.TLS.StartTLS = false")
	}
}

func TestParseRejectsLDAPURLWithoutStartTLS(t *testing.T) {
	raw := strings.Replace(validConfig, `url: "ldaps://ldap.example.com:636"`, `url: "ldap://ldap.example.com:389"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want ldap:// rejection")
	}
	if !strings.Contains(err.Error(), "must use ldaps:// unless tls.start_tls is true") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsLDAPURLWithoutHost(t *testing.T) {
	raw := strings.Replace(validConfig, `url: "ldaps://ldap.example.com:636"`, `url: "ldaps://"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want host validation error")
	}
	if !strings.Contains(err.Error(), "must include host") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsUnsupportedLDAPURLScheme(t *testing.T) {
	raw := strings.Replace(validConfig, `url: "ldaps://ldap.example.com:636"`, `url: "https://ldap.example.com"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want scheme validation error")
	}
	if !strings.Contains(err.Error(), "must use ldap:// or ldaps:// scheme") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseAllowsReferralAllowlist(t *testing.T) {
	raw := validConfig + `
      referrals:
        mode: "allowlist"
        allowed_urls:
          - "ldaps://ldap-referral.example.com:636"
        allow_service_bind_reuse: true
`

	_, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsReferralBindReuseWhenDisabled(t *testing.T) {
	raw := validConfig + `
      referrals:
        mode: "disabled"
        allow_service_bind_reuse: true
`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want bind reuse validation error")
	}
	if !strings.Contains(err.Error(), "allow_service_bind_reuse must be false when mode is disabled") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsReferralAllowlistURLWithoutHost(t *testing.T) {
	raw := validConfig + `
      referrals:
        mode: "allowlist"
        allowed_urls:
          - "ldaps://"
`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want referral host validation error")
	}
	if !strings.Contains(err.Error(), "referrals.allowed_urls[0] must include host") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsReferralAllowlistUnsupportedScheme(t *testing.T) {
	raw := validConfig + `
      referrals:
        mode: "allowlist"
        allowed_urls:
          - "https://ldap-referral.example.com"
`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want referral scheme validation error")
	}
	if !strings.Contains(err.Error(), "referrals.allowed_urls[0] must use ldap:// or ldaps://") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseAllowsGroupPrimitive(t *testing.T) {
	raw := validConfig + `
      groups:
        enabled: true
        member_attribute: "memberOf"
        response_attribute: "groups"
`

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.Tenants[0].LDAP.Groups.Enabled {
		t.Fatal("LDAP.Groups.Enabled = false")
	}
}

func TestParseRejectsUnsafeDirectoryProfileAttribute(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `directory_profile:
        name: "generic"
        subject_attribute: "uid)(|(objectClass=*)"
      lookup_mode: "search_then_bind"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want unsafe attribute validation error")
	}
	if !strings.Contains(err.Error(), "subject_attribute must be a safe LDAP attribute description") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsUnsafeGroupSearchAttribute(t *testing.T) {
	raw := validConfig + `
      groups:
        enabled: true
        member_attribute: "memberOf"
        search_member_attribute: "member)(|(objectClass=*)"
        response_attribute: "groups"
`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want unsafe group attribute validation error")
	}
	if !strings.Contains(err.Error(), "search_member_attribute must be a safe LDAP attribute description") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsExcessiveGroupLimits(t *testing.T) {
	raw := validConfig + `
      groups:
        enabled: true
        member_attribute: "memberOf"
        search_member_attribute: "member"
        response_attribute: "groups"
        max_depth: 21
        max_groups: 10001
        timeout_ms: 60001
`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want group limit validation errors")
	}
	for _, want := range []string{
		"groups.max_depth must be 20 or less",
		"groups.max_groups must be 10000 or less",
		"groups.timeout_ms must be 60000 or less",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Parse() error = %v, want %q", err, want)
		}
	}
}

func TestParseAllowsConnectionPool(t *testing.T) {
	raw := validConfig + `
      pool:
        max_idle: 2
`

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Tenants[0].LDAP.Pool.MaxIdle != 2 {
		t.Fatalf("LDAP.Pool.MaxIdle = %d", cfg.Tenants[0].LDAP.Pool.MaxIdle)
	}
}

func TestParseAllowsRelayConfig(t *testing.T) {
	raw := strings.Replace(validConfig, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"`, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
      relay:
        enabled: true
        url: "wss://login.example.com/api/auth/directory-relay/connect/tenant-a/wwcon_8K4M2Q9F7D3H6P1X"`, 1)

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.Tenants[0].Authrim.Relay.Enabled {
		t.Fatal("Authrim.Relay.Enabled = false")
	}
	if cfg.Tenants[0].Authrim.Relay.ReconnectMinMS != 1000 {
		t.Fatalf("ReconnectMinMS = %d", cfg.Tenants[0].Authrim.Relay.ReconnectMinMS)
	}
}

func TestParseRejectsRelayHTTPURL(t *testing.T) {
	raw := strings.Replace(validConfig, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"`, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
      relay:
        enabled: true
        url: "http://login.example.com/api/auth/directory-relay/connect/tenant-a/wwcon_8K4M2Q9F7D3H6P1X"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want relay URL validation error")
	}
	if !strings.Contains(err.Error(), "url must use wss://") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsRelayURLTenantOrConnectorMismatch(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "tenant",
			url:  "wss://login.example.com/api/auth/directory-relay/connect/tenant-b/wwcon_8K4M2Q9F7D3H6P1X",
			want: "url tenant_id must match tenant_id",
		},
		{
			name: "connector",
			url:  "wss://login.example.com/api/auth/directory-relay/connect/tenant-a/wwcon_4R7T9K2M6Q1F3D8H",
			want: "url connector_id must match connector_id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(validConfig, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"`, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
      relay:
        enabled: true
        url: "`+tc.url+`"`, 1)

			_, err := Parse([]byte(raw))
			if err == nil {
				t.Fatal("Parse() error = nil, want relay URL binding validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestParseAllowsHeartbeatConfig(t *testing.T) {
	raw := strings.Replace(validConfig, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"`, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
      heartbeat:
        enabled: true
        url: "https://login.example.com/api/auth/directory-connectors/heartbeat/tenant-a/wwcon_8K4M2Q9F7D3H6P1X"
        transport: "tunnel"
        display_name: "campus connector a"
        key:
          kid: "hb_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_HEARTBEAT_SECRET"
        previous:
          kid: "hb_2026_05"
          secret_ref: "env:AUTHRIM_WORDWARDEN_HEARTBEAT_SECRET_PREVIOUS"
        interval_ms: 60000
        timeout_ms: 3000`, 1)

	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	heartbeat := cfg.Tenants[0].Authrim.Heartbeat
	if !heartbeat.Enabled || heartbeat.Transport != "tunnel" || heartbeat.Key.KID != "hb_2026_06" {
		t.Fatalf("Heartbeat = %#v", heartbeat)
	}
	if heartbeat.Previous == nil || heartbeat.Previous.KID != "hb_2026_05" {
		t.Fatalf("Heartbeat.Previous = %#v", heartbeat.Previous)
	}
}

func TestParseRejectsHeartbeatURLBindingMismatch(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "tenant",
			url:  "https://login.example.com/api/auth/directory-connectors/heartbeat/tenant-b/wwcon_8K4M2Q9F7D3H6P1X",
			want: "authrim.heartbeat.url tenant_id must match tenant_id",
		},
		{
			name: "connector",
			url:  "https://login.example.com/api/auth/directory-connectors/heartbeat/tenant-a/wwcon_4R7T9K2M6Q1F3D8H",
			want: "authrim.heartbeat.url connector_id must match connector_id",
		},
		{
			name: "scheme",
			url:  "http://login.example.com/api/auth/directory-connectors/heartbeat/tenant-a/wwcon_8K4M2Q9F7D3H6P1X",
			want: "authrim.heartbeat.url must use https://",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(validConfig, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"`, `audit_hash_secret_ref: "env:AUTHRIM_WORDWARDEN_AUDIT_HASH_SECRET"
      heartbeat:
        enabled: true
        url: "`+tc.url+`"
        key:
          kid: "hb_2026_06"
          secret_ref: "env:AUTHRIM_WORDWARDEN_HEARTBEAT_SECRET"`, 1)

			_, err := Parse([]byte(raw))
			if err == nil {
				t.Fatal("Parse() error = nil, want heartbeat URL validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want %q", err, tc.want)
			}
		})
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
    connector_id: "wwcon_4R7T9K2M6Q1F3D8H"
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

func TestParseRequiresUsernamePlaceholderInSearchThenBindFilter(t *testing.T) {
	raw := strings.Replace(validConfig, `user_filter: "(uid={username})"`, `user_filter: "(objectClass=person)"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want user_filter placeholder error")
	}
	if !strings.Contains(err.Error(), "user_filter must contain {username}") {
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

func TestParseRequiresServiceSearchForDirectBind(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `lookup_mode: "direct_bind"`, 1)
	raw = strings.Replace(raw, `      bind_dn: "uid=authrim,ou=system,dc=example,dc=com"
      bind_password_ref: "env:LDAP_BIND_PASSWORD"
      base_dn: "dc=example,dc=com"
      user_filter: "(uid={username})"
`, "", 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want direct_bind service search error")
	}
	for _, want := range []string{
		"bind_dn is required when lookup_mode is direct_bind",
		"bind_password_ref: secret reference is empty",
		"base_dn is required when lookup_mode is direct_bind",
		"user_filter is required when lookup_mode is direct_bind",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Parse() error = %v, want %q", err, want)
		}
	}
}

func TestParseDirectBindRequiresUsernamePlaceholderInFilter(t *testing.T) {
	raw := strings.Replace(validConfig, `lookup_mode: "search_then_bind"`, `lookup_mode: "direct_bind"`, 1)
	raw = strings.Replace(raw, `user_filter: "(uid={username})"`, `user_filter: "(objectClass=person)"`, 1)

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want direct_bind user_filter placeholder error")
	}
	if !strings.Contains(err.Error(), "user_filter must contain {username}") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsInvalidProtectionLimit(t *testing.T) {
	raw := validConfig + `
    protection:
      max_concurrent_requests: 8
      storm_window_ms: 10000
      storm_block_ms: 30000
      malformed_request_limit: -1
      replay_limit: 10
      directory_error_limit: 5
`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("Parse() error = nil, want protection error")
	}
	if !strings.Contains(err.Error(), "protection.malformed_request_limit must be positive") {
		t.Fatalf("Parse() error = %v", err)
	}
}
