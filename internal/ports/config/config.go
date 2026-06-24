package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/authrim/authrim-wordwarden/internal/ports/secrets"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Deployment   DeploymentConfig `yaml:"deployment"`
	Server       ServerConfig     `yaml:"server"`
	Tenants      []TenantConfig   `yaml:"tenants"`
	Experimental map[string]any   `yaml:"experimental,omitempty"`
}

type DeploymentConfig struct {
	Mode string `yaml:"mode"`
}

type ServerConfig struct {
	Listen           string          `yaml:"listen"`
	PublicBaseURL    string          `yaml:"public_base_url"`
	ExposeOperations bool            `yaml:"expose_operations"`
	TLS              ServerTLSConfig `yaml:"tls"`
}

type ServerTLSConfig struct {
	Enabled     bool   `yaml:"enabled"`
	CertFileRef string `yaml:"cert_file_ref"`
	KeyFileRef  string `yaml:"key_file_ref"`
}

type TenantConfig struct {
	TenantID    string           `yaml:"tenant_id"`
	ConnectorID string           `yaml:"connector_id"`
	Authrim     AuthrimConfig    `yaml:"authrim"`
	LDAP        LDAPConfig       `yaml:"ldap"`
	Timeouts    TimeoutConfig    `yaml:"timeouts"`
	Protection  ProtectionConfig `yaml:"protection"`
}

type AuthrimConfig struct {
	HMACKeys           HMACKeysConfig `yaml:"hmac_keys"`
	AuditHashSecretRef string         `yaml:"audit_hash_secret_ref"`
	Relay              RelayConfig    `yaml:"relay"`
}

type RelayConfig struct {
	Enabled        bool   `yaml:"enabled"`
	URL            string `yaml:"url"`
	ReconnectMinMS int    `yaml:"reconnect_min_ms"`
	ReconnectMaxMS int    `yaml:"reconnect_max_ms"`
}

type HMACKeysConfig struct {
	Active   HMACKeyConfig  `yaml:"active"`
	Previous *HMACKeyConfig `yaml:"previous"`
}

type HMACKeyConfig struct {
	KID       string `yaml:"kid"`
	SecretRef string `yaml:"secret_ref"`
}

type LDAPConfig struct {
	URL                string                 `yaml:"url"`
	URLs               []string               `yaml:"urls"`
	TLS                LDAPTLSConfig          `yaml:"tls"`
	DirectoryProfile   DirectoryProfileConfig `yaml:"directory_profile"`
	LookupMode         string                 `yaml:"lookup_mode"`
	Username           UsernameConfig         `yaml:"username"`
	BindDN             string                 `yaml:"bind_dn"`
	BindPasswordRef    string                 `yaml:"bind_password_ref"`
	BaseDN             string                 `yaml:"base_dn"`
	DNTemplate         string                 `yaml:"dn_template"`
	UserFilter         string                 `yaml:"user_filter"`
	FilterTemplateMode string                 `yaml:"filter_template_mode"`
	Attributes         []string               `yaml:"attributes"`
	Referrals          ReferralConfig         `yaml:"referrals"`
	Groups             GroupConfig            `yaml:"groups"`
	Pool               PoolConfig             `yaml:"pool"`
}

type DirectoryProfileConfig struct {
	Name                 string            `yaml:"name"`
	SubjectAttribute     string            `yaml:"subject_attribute"`
	IdentifierAttributes []string          `yaml:"identifier_attributes"`
	GroupStrategy        string            `yaml:"group_strategy"`
	StatusNormalization  string            `yaml:"status_normalization"`
	PagedSearch          PagedSearchConfig `yaml:"paged_search"`
}

type PagedSearchConfig struct {
	Enabled    bool `yaml:"enabled"`
	PageSize   int  `yaml:"page_size"`
	MaxEntries int  `yaml:"max_entries"`
	TimeoutMS  int  `yaml:"timeout_ms"`
}

type LDAPTLSConfig struct {
	Verify     bool   `yaml:"verify"`
	ServerName string `yaml:"server_name"`
	CAFileRef  string `yaml:"ca_file_ref"`
	StartTLS   bool   `yaml:"start_tls"`
}

type ReferralConfig struct {
	Mode                  string   `yaml:"mode"`
	AllowedURLs           []string `yaml:"allowed_urls"`
	AllowServiceBindReuse bool     `yaml:"allow_service_bind_reuse"`
}

type GroupConfig struct {
	Enabled               bool   `yaml:"enabled"`
	MemberAttribute       string `yaml:"member_attribute"`
	SearchMemberAttribute string `yaml:"search_member_attribute"`
	ResponseAttribute     string `yaml:"response_attribute"`
	IDAttribute           string `yaml:"id_attribute"`
	DisplayAttribute      string `yaml:"display_attribute"`
	SearchBaseDN          string `yaml:"search_base_dn"`
	MaxDepth              int    `yaml:"max_depth"`
	MaxGroups             int    `yaml:"max_groups"`
	TimeoutMS             int    `yaml:"timeout_ms"`
}

type PoolConfig struct {
	MaxIdle int `yaml:"max_idle"`
}

type UsernameConfig struct {
	AllowedFormats     []string                    `yaml:"allowed_formats"`
	AllowedDomains     []string                    `yaml:"allowed_domains"`
	AllowedUPNSuffixes []string                    `yaml:"allowed_upn_suffixes"`
	Normalization      UsernameNormalizationConfig `yaml:"normalization"`
}

type UsernameNormalizationConfig struct {
	Trim                 bool   `yaml:"trim"`
	Unicode              string `yaml:"unicode"`
	Case                 string `yaml:"case"`
	RejectDomainMismatch bool   `yaml:"reject_domain_mismatch"`
}

type TimeoutConfig struct {
	LDAPConnectMS int `yaml:"ldap_connect_ms"`
	LDAPBindMS    int `yaml:"ldap_bind_ms"`
	LDAPSearchMS  int `yaml:"ldap_search_ms"`
	RequestMS     int `yaml:"request_ms"`
}

type ProtectionConfig struct {
	MaxConcurrentRequests int `yaml:"max_concurrent_requests"`
	StormWindowMS         int `yaml:"storm_window_ms"`
	StormBlockMS          int `yaml:"storm_block_ms"`
	MalformedRequestLimit int `yaml:"malformed_request_limit"`
	ReplayLimit           int `yaml:"replay_limit"`
	DirectoryErrorLimit   int `yaml:"directory_error_limit"`
}

func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Deployment.Mode == "" {
		cfg.Deployment.Mode = "single_tenant"
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "127.0.0.1:8080"
	}
	for i := range cfg.Tenants {
		applyDirectoryProfileDefaults(&cfg.Tenants[i].LDAP)
		if cfg.Tenants[i].LDAP.LookupMode == "" {
			cfg.Tenants[i].LDAP.LookupMode = "search_then_bind"
		}
		if cfg.Tenants[i].LDAP.FilterTemplateMode == "" {
			cfg.Tenants[i].LDAP.FilterTemplateMode = "builtin_or_template"
		}
		if cfg.Tenants[i].LDAP.Referrals.Mode == "" {
			cfg.Tenants[i].LDAP.Referrals.Mode = "disabled"
		}
		if cfg.Tenants[i].LDAP.Groups.MemberAttribute == "" {
			cfg.Tenants[i].LDAP.Groups.MemberAttribute = "memberOf"
		}
		if cfg.Tenants[i].LDAP.Groups.SearchMemberAttribute == "" {
			if cfg.Tenants[i].LDAP.DirectoryProfile.GroupStrategy == "ad_matching_rule" {
				cfg.Tenants[i].LDAP.Groups.SearchMemberAttribute = "member"
			} else {
				cfg.Tenants[i].LDAP.Groups.SearchMemberAttribute = cfg.Tenants[i].LDAP.Groups.MemberAttribute
			}
		}
		if cfg.Tenants[i].LDAP.Groups.ResponseAttribute == "" {
			cfg.Tenants[i].LDAP.Groups.ResponseAttribute = "groups"
		}
		if cfg.Tenants[i].LDAP.Groups.IDAttribute == "" {
			cfg.Tenants[i].LDAP.Groups.IDAttribute = "cn"
		}
		if cfg.Tenants[i].LDAP.Groups.DisplayAttribute == "" {
			cfg.Tenants[i].LDAP.Groups.DisplayAttribute = "cn"
		}
		if cfg.Tenants[i].LDAP.Groups.MaxDepth == 0 {
			cfg.Tenants[i].LDAP.Groups.MaxDepth = 1
		}
		if cfg.Tenants[i].LDAP.Groups.MaxGroups == 0 {
			cfg.Tenants[i].LDAP.Groups.MaxGroups = 100
		}
		if cfg.Tenants[i].LDAP.Groups.TimeoutMS == 0 {
			cfg.Tenants[i].LDAP.Groups.TimeoutMS = 1000
		}
		if cfg.Tenants[i].LDAP.DirectoryProfile.PagedSearch.Enabled {
			if cfg.Tenants[i].LDAP.DirectoryProfile.PagedSearch.PageSize == 0 {
				cfg.Tenants[i].LDAP.DirectoryProfile.PagedSearch.PageSize = 500
			}
			if cfg.Tenants[i].LDAP.DirectoryProfile.PagedSearch.MaxEntries == 0 {
				cfg.Tenants[i].LDAP.DirectoryProfile.PagedSearch.MaxEntries = 5000
			}
			if cfg.Tenants[i].LDAP.DirectoryProfile.PagedSearch.TimeoutMS == 0 {
				cfg.Tenants[i].LDAP.DirectoryProfile.PagedSearch.TimeoutMS = 3000
			}
		}
		if cfg.Tenants[i].Timeouts.LDAPConnectMS == 0 {
			cfg.Tenants[i].Timeouts.LDAPConnectMS = 500
		}
		if cfg.Tenants[i].Timeouts.LDAPSearchMS == 0 {
			cfg.Tenants[i].Timeouts.LDAPSearchMS = 1000
		}
		if cfg.Tenants[i].Timeouts.LDAPBindMS == 0 {
			cfg.Tenants[i].Timeouts.LDAPBindMS = 1500
		}
		if cfg.Tenants[i].Timeouts.RequestMS == 0 {
			cfg.Tenants[i].Timeouts.RequestMS = 2500
		}
		if cfg.Tenants[i].Authrim.Relay.ReconnectMinMS == 0 {
			cfg.Tenants[i].Authrim.Relay.ReconnectMinMS = 1000
		}
		if cfg.Tenants[i].Authrim.Relay.ReconnectMaxMS == 0 {
			cfg.Tenants[i].Authrim.Relay.ReconnectMaxMS = 30000
		}
		if cfg.Tenants[i].Protection.MaxConcurrentRequests == 0 {
			cfg.Tenants[i].Protection.MaxConcurrentRequests = 8
		}
		if cfg.Tenants[i].Protection.StormWindowMS == 0 {
			cfg.Tenants[i].Protection.StormWindowMS = 10000
		}
		if cfg.Tenants[i].Protection.StormBlockMS == 0 {
			cfg.Tenants[i].Protection.StormBlockMS = 30000
		}
		if cfg.Tenants[i].Protection.MalformedRequestLimit == 0 {
			cfg.Tenants[i].Protection.MalformedRequestLimit = 20
		}
		if cfg.Tenants[i].Protection.ReplayLimit == 0 {
			cfg.Tenants[i].Protection.ReplayLimit = 10
		}
		if cfg.Tenants[i].Protection.DirectoryErrorLimit == 0 {
			cfg.Tenants[i].Protection.DirectoryErrorLimit = 5
		}
	}
}

func applyDirectoryProfileDefaults(ldap *LDAPConfig) {
	if ldap.DirectoryProfile.Name == "" {
		ldap.DirectoryProfile.Name = "generic"
	}
	switch ldap.DirectoryProfile.Name {
	case "active_directory":
		if ldap.DirectoryProfile.SubjectAttribute == "" {
			ldap.DirectoryProfile.SubjectAttribute = "objectGUID"
		}
		if len(ldap.DirectoryProfile.IdentifierAttributes) == 0 {
			ldap.DirectoryProfile.IdentifierAttributes = []string{"sAMAccountName", "userPrincipalName", "mail"}
		}
		if ldap.DirectoryProfile.GroupStrategy == "" {
			ldap.DirectoryProfile.GroupStrategy = "ad_matching_rule"
		}
		if ldap.DirectoryProfile.StatusNormalization == "" {
			ldap.DirectoryProfile.StatusNormalization = "active_directory"
		}
	case "openldap":
		if ldap.DirectoryProfile.SubjectAttribute == "" {
			ldap.DirectoryProfile.SubjectAttribute = "entryUUID"
		}
		if len(ldap.DirectoryProfile.IdentifierAttributes) == 0 {
			ldap.DirectoryProfile.IdentifierAttributes = []string{"uid", "mail"}
		}
		if ldap.DirectoryProfile.GroupStrategy == "" {
			ldap.DirectoryProfile.GroupStrategy = "member_attribute_only"
		}
		if ldap.DirectoryProfile.StatusNormalization == "" {
			ldap.DirectoryProfile.StatusNormalization = "generic"
		}
	case "generic":
		if ldap.DirectoryProfile.GroupStrategy == "" {
			ldap.DirectoryProfile.GroupStrategy = "member_attribute_only"
		}
		if ldap.DirectoryProfile.StatusNormalization == "" {
			ldap.DirectoryProfile.StatusNormalization = "generic"
		}
	}
}

func Validate(cfg *Config) error {
	var problems []string

	switch cfg.Deployment.Mode {
	case "single_tenant":
		if len(cfg.Tenants) != 1 {
			problems = append(problems, "deployment.mode single_tenant requires exactly one tenant")
		}
	case "multi_tenant":
		if len(cfg.Tenants) == 0 {
			problems = append(problems, "deployment.mode multi_tenant requires at least one tenant")
		}
	default:
		problems = append(problems, "deployment.mode must be single_tenant or multi_tenant")
	}

	if cfg.Server.TLS.Enabled {
		if cfg.Server.TLS.CertFileRef == "" {
			problems = append(problems, "server.tls.cert_file_ref is required when TLS is enabled")
		}
		if cfg.Server.TLS.KeyFileRef == "" {
			problems = append(problems, "server.tls.key_file_ref is required when TLS is enabled")
		}
	}

	seenTenants := map[string]struct{}{}
	seenConnectors := map[string]struct{}{}
	for i, tenant := range cfg.Tenants {
		prefix := fmt.Sprintf("tenants[%d]", i)
		if tenant.TenantID == "" {
			problems = append(problems, prefix+".tenant_id is required")
		}
		if tenant.ConnectorID == "" {
			problems = append(problems, prefix+".connector_id is required")
		}
		if _, ok := seenTenants[tenant.TenantID]; tenant.TenantID != "" && ok {
			problems = append(problems, prefix+".tenant_id must be unique")
		}
		if _, ok := seenConnectors[tenant.ConnectorID]; tenant.ConnectorID != "" && ok {
			problems = append(problems, prefix+".connector_id must be unique")
		}
		seenTenants[tenant.TenantID] = struct{}{}
		seenConnectors[tenant.ConnectorID] = struct{}{}

		validateSecretRef(&problems, prefix+".authrim.hmac_keys.active.secret_ref", tenant.Authrim.HMACKeys.Active.SecretRef)
		if tenant.Authrim.HMACKeys.Active.KID == "" {
			problems = append(problems, prefix+".authrim.hmac_keys.active.kid is required")
		}
		if tenant.Authrim.HMACKeys.Previous != nil {
			if tenant.Authrim.HMACKeys.Previous.KID == "" {
				problems = append(problems, prefix+".authrim.hmac_keys.previous.kid is required")
			}
			validateSecretRef(&problems, prefix+".authrim.hmac_keys.previous.secret_ref", tenant.Authrim.HMACKeys.Previous.SecretRef)
		}
		validateSecretRef(&problems, prefix+".authrim.audit_hash_secret_ref", tenant.Authrim.AuditHashSecretRef)
		validateRelay(&problems, prefix+".authrim.relay", tenant.Authrim.Relay, tenant.TenantID, tenant.ConnectorID)
		validateLDAP(&problems, prefix+".ldap", tenant.LDAP)
		validateTimeouts(&problems, prefix+".timeouts", tenant.Timeouts)
		if tenant.Protection.MaxConcurrentRequests <= 0 {
			problems = append(problems, prefix+".protection.max_concurrent_requests must be positive")
		}
		validateProtection(&problems, prefix+".protection", tenant.Protection)
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func validateProtection(problems *[]string, prefix string, protection ProtectionConfig) {
	if protection.StormWindowMS <= 0 {
		*problems = append(*problems, prefix+".storm_window_ms must be positive")
	}
	if protection.StormBlockMS <= 0 {
		*problems = append(*problems, prefix+".storm_block_ms must be positive")
	}
	if protection.MalformedRequestLimit <= 0 {
		*problems = append(*problems, prefix+".malformed_request_limit must be positive")
	}
	if protection.ReplayLimit <= 0 {
		*problems = append(*problems, prefix+".replay_limit must be positive")
	}
	if protection.DirectoryErrorLimit <= 0 {
		*problems = append(*problems, prefix+".directory_error_limit must be positive")
	}
}

func validateRelay(problems *[]string, prefix string, relay RelayConfig, tenantID string, connectorID string) {
	if !relay.Enabled {
		return
	}
	if relay.URL == "" {
		*problems = append(*problems, prefix+".url is required when relay is enabled")
		return
	}
	parsed, err := url.Parse(relay.URL)
	if err != nil || parsed.Host == "" {
		*problems = append(*problems, prefix+".url must be a valid URL")
		return
	}
	switch parsed.Scheme {
	case "wss":
	case "ws":
		if parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
			*problems = append(*problems, prefix+".url must use wss:// except ws://localhost for local development")
		}
	default:
		*problems = append(*problems, prefix+".url must use wss:// except ws://localhost for local development")
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) < 6 || strings.Join(parts[len(parts)-6:len(parts)-2], "/") != "api/auth/directory-relay/connect" {
		*problems = append(*problems, prefix+".url must include /api/auth/directory-relay/connect/{tenant_id}/{connector_id}")
	} else {
		rawTenantID, tenantErr := url.PathUnescape(parts[len(parts)-2])
		rawConnectorID, connectorErr := url.PathUnescape(parts[len(parts)-1])
		if tenantErr != nil {
			*problems = append(*problems, prefix+".url tenant_id path segment is invalid")
		} else if rawTenantID != tenantID {
			*problems = append(*problems, prefix+".url tenant_id must match tenant_id")
		}
		if connectorErr != nil {
			*problems = append(*problems, prefix+".url connector_id path segment is invalid")
		} else if rawConnectorID != connectorID {
			*problems = append(*problems, prefix+".url connector_id must match connector_id")
		}
	}
	if relay.ReconnectMinMS <= 0 {
		*problems = append(*problems, prefix+".reconnect_min_ms must be positive")
	}
	if relay.ReconnectMaxMS <= 0 {
		*problems = append(*problems, prefix+".reconnect_max_ms must be positive")
	}
	if relay.ReconnectMinMS > relay.ReconnectMaxMS {
		*problems = append(*problems, prefix+".reconnect_min_ms must be less than or equal to reconnect_max_ms")
	}
}

func validateLDAP(problems *[]string, prefix string, ldap LDAPConfig) {
	validateLDAPURLs(problems, prefix, ldap)
	validateDirectoryProfile(problems, prefix+".directory_profile", ldap.DirectoryProfile)
	if !ldap.TLS.Verify {
		*problems = append(*problems, prefix+".tls.verify must be true")
	}
	validateFileRef(problems, prefix+".tls.ca_file_ref", ldap.TLS.CAFileRef, false)
	validateReferrals(problems, prefix+".referrals", ldap.Referrals)
	validateGroups(problems, prefix+".groups", ldap.Groups)
	validatePool(problems, prefix+".pool", ldap.Pool)

	switch ldap.LookupMode {
	case "search_then_bind":
		validateSecretRef(problems, prefix+".bind_password_ref", ldap.BindPasswordRef)
		if ldap.BindDN == "" {
			*problems = append(*problems, prefix+".bind_dn is required")
		}
		if ldap.BaseDN == "" {
			*problems = append(*problems, prefix+".base_dn is required")
		}
		if ldap.UserFilter == "" {
			*problems = append(*problems, prefix+".user_filter is required")
		}
		if ldap.UserFilter != "" && !strings.Contains(ldap.UserFilter, "{username}") {
			*problems = append(*problems, prefix+".user_filter must contain {username}")
		}
	case "dn_template":
		if ldap.DNTemplate == "" {
			*problems = append(*problems, prefix+".dn_template is required when lookup_mode is dn_template")
		}
		validateOptionalSecretRef(problems, prefix+".bind_password_ref", ldap.BindPasswordRef)
	case "direct_bind":
		validateSecretRef(problems, prefix+".bind_password_ref", ldap.BindPasswordRef)
		if ldap.BindDN == "" {
			*problems = append(*problems, prefix+".bind_dn is required when lookup_mode is direct_bind")
		}
		if ldap.BaseDN == "" {
			*problems = append(*problems, prefix+".base_dn is required when lookup_mode is direct_bind")
		}
		if ldap.UserFilter == "" {
			*problems = append(*problems, prefix+".user_filter is required when lookup_mode is direct_bind")
		}
		if ldap.UserFilter != "" && !strings.Contains(ldap.UserFilter, "{username}") {
			*problems = append(*problems, prefix+".user_filter must contain {username}")
		}
	default:
		*problems = append(*problems, prefix+".lookup_mode must be search_then_bind, dn_template, or direct_bind")
	}

	if len(ldap.Attributes) == 0 {
		*problems = append(*problems, prefix+".attributes must contain at least one attribute")
	}
	validateUsername(problems, prefix+".username", ldap.Username)
}

func validateDirectoryProfile(problems *[]string, prefix string, profile DirectoryProfileConfig) {
	switch profile.Name {
	case "active_directory", "openldap", "generic":
	default:
		*problems = append(*problems, prefix+".name must be active_directory, openldap, or generic")
	}
	for i, attribute := range profile.IdentifierAttributes {
		if strings.TrimSpace(attribute) == "" {
			*problems = append(*problems, fmt.Sprintf("%s.identifier_attributes[%d] must not be empty", prefix, i))
		} else if !validLDAPAttributeDescription(attribute) {
			*problems = append(*problems, fmt.Sprintf("%s.identifier_attributes[%d] must be a safe LDAP attribute description", prefix, i))
		}
	}
	if profile.SubjectAttribute != "" && !validLDAPAttributeDescription(profile.SubjectAttribute) {
		*problems = append(*problems, prefix+".subject_attribute must be a safe LDAP attribute description")
	}
	switch profile.GroupStrategy {
	case "member_attribute_only", "ad_matching_rule", "bfs_member_search":
	default:
		*problems = append(*problems, prefix+".group_strategy must be member_attribute_only, ad_matching_rule, or bfs_member_search")
	}
	switch profile.StatusNormalization {
	case "generic", "active_directory":
	default:
		*problems = append(*problems, prefix+".status_normalization must be generic or active_directory")
	}
	if profile.PagedSearch.Enabled {
		if profile.PagedSearch.PageSize <= 0 {
			*problems = append(*problems, prefix+".paged_search.page_size must be positive when paged search is enabled")
		} else if profile.PagedSearch.PageSize > 10000 {
			*problems = append(*problems, prefix+".paged_search.page_size must be 10000 or less")
		}
		if profile.PagedSearch.MaxEntries <= 0 {
			*problems = append(*problems, prefix+".paged_search.max_entries must be positive when paged search is enabled")
		} else if profile.PagedSearch.MaxEntries > 100000 {
			*problems = append(*problems, prefix+".paged_search.max_entries must be 100000 or less")
		}
		if profile.PagedSearch.TimeoutMS <= 0 {
			*problems = append(*problems, prefix+".paged_search.timeout_ms must be positive when paged search is enabled")
		} else if profile.PagedSearch.TimeoutMS > 60000 {
			*problems = append(*problems, prefix+".paged_search.timeout_ms must be 60000 or less")
		}
	}
}

func validatePool(problems *[]string, prefix string, pool PoolConfig) {
	if pool.MaxIdle < 0 {
		*problems = append(*problems, prefix+".max_idle must be zero or positive")
	}
}

func validateLDAPURLs(problems *[]string, prefix string, ldap LDAPConfig) {
	urls := ldapEndpointURLs(ldap)
	if len(urls) == 0 {
		*problems = append(*problems, prefix+".url or "+prefix+".urls is required")
		return
	}
	seen := map[string]struct{}{}
	for i, rawURL := range urls {
		field := prefix + ".url"
		if i > 0 || len(ldap.URLs) > 0 {
			field = fmt.Sprintf("%s.urls[%d]", prefix, i)
		}
		if rawURL == "" {
			*problems = append(*problems, field+" must not be empty")
			continue
		}
		if _, ok := seen[rawURL]; ok {
			*problems = append(*problems, field+" must be unique")
			continue
		}
		seen[rawURL] = struct{}{}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme == "" {
			*problems = append(*problems, field+" must include ldap:// or ldaps:// scheme")
			continue
		}
		if parsed.Host == "" {
			*problems = append(*problems, field+" must include host")
			continue
		}
		if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
			*problems = append(*problems, field+" must use ldap:// or ldaps:// scheme")
			continue
		}
		if ldap.TLS.StartTLS {
			if parsed.Scheme != "ldap" {
				*problems = append(*problems, field+" must use ldap:// when tls.start_tls is true")
			}
			continue
		}
		if parsed.Scheme != "ldaps" {
			*problems = append(*problems, field+" must use ldaps:// unless tls.start_tls is true")
		}
	}
}

func ldapEndpointURLs(ldap LDAPConfig) []string {
	result := make([]string, 0, 1+len(ldap.URLs))
	if ldap.URL != "" {
		result = append(result, ldap.URL)
	}
	result = append(result, ldap.URLs...)
	return result
}

func validateReferrals(problems *[]string, prefix string, referrals ReferralConfig) {
	switch referrals.Mode {
	case "disabled":
		if len(referrals.AllowedURLs) > 0 {
			*problems = append(*problems, prefix+".allowed_urls must be empty when mode is disabled")
		}
		if referrals.AllowServiceBindReuse {
			*problems = append(*problems, prefix+".allow_service_bind_reuse must be false when mode is disabled")
		}
	case "allowlist":
		if len(referrals.AllowedURLs) == 0 {
			*problems = append(*problems, prefix+".allowed_urls is required when mode is allowlist")
		}
		for i, rawURL := range referrals.AllowedURLs {
			field := fmt.Sprintf("%s.allowed_urls[%d]", prefix, i)
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed.Scheme == "" {
				*problems = append(*problems, field+" must include ldap:// or ldaps:// scheme")
				continue
			}
			if parsed.Host == "" {
				*problems = append(*problems, field+" must include host")
				continue
			}
			if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
				*problems = append(*problems, field+" must use ldap:// or ldaps://")
			}
		}
	default:
		*problems = append(*problems, prefix+".mode must be disabled or allowlist")
	}
}

func validateGroups(problems *[]string, prefix string, groups GroupConfig) {
	if !groups.Enabled {
		return
	}
	if groups.MemberAttribute == "" {
		*problems = append(*problems, prefix+".member_attribute is required when groups.enabled is true")
	} else if !validLDAPAttributeDescription(groups.MemberAttribute) {
		*problems = append(*problems, prefix+".member_attribute must be a safe LDAP attribute description")
	}
	if groups.SearchMemberAttribute == "" {
		*problems = append(*problems, prefix+".search_member_attribute is required when groups.enabled is true")
	} else if !validLDAPAttributeDescription(groups.SearchMemberAttribute) {
		*problems = append(*problems, prefix+".search_member_attribute must be a safe LDAP attribute description")
	}
	if groups.ResponseAttribute == "" {
		*problems = append(*problems, prefix+".response_attribute is required when groups.enabled is true")
	} else if !validLDAPAttributeDescription(groups.ResponseAttribute) {
		*problems = append(*problems, prefix+".response_attribute must be a safe LDAP attribute description")
	}
	if groups.IDAttribute == "" {
		*problems = append(*problems, prefix+".id_attribute is required when groups.enabled is true")
	} else if !validLDAPAttributeDescription(groups.IDAttribute) {
		*problems = append(*problems, prefix+".id_attribute must be a safe LDAP attribute description")
	}
	if groups.DisplayAttribute == "" {
		*problems = append(*problems, prefix+".display_attribute is required when groups.enabled is true")
	} else if !validLDAPAttributeDescription(groups.DisplayAttribute) {
		*problems = append(*problems, prefix+".display_attribute must be a safe LDAP attribute description")
	}
	if groups.MaxDepth <= 0 {
		*problems = append(*problems, prefix+".max_depth must be positive when groups.enabled is true")
	} else if groups.MaxDepth > 20 {
		*problems = append(*problems, prefix+".max_depth must be 20 or less")
	}
	if groups.MaxGroups <= 0 {
		*problems = append(*problems, prefix+".max_groups must be positive when groups.enabled is true")
	} else if groups.MaxGroups > 10000 {
		*problems = append(*problems, prefix+".max_groups must be 10000 or less")
	}
	if groups.TimeoutMS <= 0 {
		*problems = append(*problems, prefix+".timeout_ms must be positive when groups.enabled is true")
	} else if groups.TimeoutMS > 60000 {
		*problems = append(*problems, prefix+".timeout_ms must be 60000 or less")
	}
}

var ldapAttributeDescriptionPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$`)

func validLDAPAttributeDescription(value string) bool {
	return ldapAttributeDescriptionPattern.MatchString(value)
}

func validateUsername(problems *[]string, prefix string, username UsernameConfig) {
	allowedFormats := map[string]struct{}{
		"local_part": {},
		"email":      {},
		"upn":        {},
	}
	for _, format := range username.AllowedFormats {
		if _, ok := allowedFormats[format]; !ok {
			*problems = append(*problems, prefix+".allowed_formats contains unsupported format "+format)
		}
	}
	switch username.Normalization.Unicode {
	case "", "NFKC":
	default:
		*problems = append(*problems, prefix+".normalization.unicode must be empty or NFKC")
	}
	switch username.Normalization.Case {
	case "", "lower":
	default:
		*problems = append(*problems, prefix+".normalization.case must be empty or lower")
	}
}

func validateTimeouts(problems *[]string, prefix string, timeouts TimeoutConfig) {
	if timeouts.LDAPConnectMS <= 0 {
		*problems = append(*problems, prefix+".ldap_connect_ms must be positive")
	}
	if timeouts.LDAPSearchMS <= 0 {
		*problems = append(*problems, prefix+".ldap_search_ms must be positive")
	}
	if timeouts.LDAPBindMS <= 0 {
		*problems = append(*problems, prefix+".ldap_bind_ms must be positive")
	}
	if timeouts.RequestMS <= 0 {
		*problems = append(*problems, prefix+".request_ms must be positive")
	}
}

func validateSecretRef(problems *[]string, field string, raw string) {
	if _, err := secrets.ParseRef(raw); err != nil {
		*problems = append(*problems, field+": "+err.Error())
	}
}

func validateOptionalSecretRef(problems *[]string, field string, raw string) {
	if raw == "" {
		return
	}
	validateSecretRef(problems, field, raw)
}

func validateFileRef(problems *[]string, field string, raw string, required bool) {
	if raw == "" {
		if required {
			*problems = append(*problems, field+" is required")
		}
		return
	}
	if !strings.HasPrefix(raw, "file:") || strings.TrimPrefix(raw, "file:") == "" {
		*problems = append(*problems, field+" must use file:<path>")
	}
}
