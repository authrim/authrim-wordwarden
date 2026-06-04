package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
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
	Listen        string          `yaml:"listen"`
	PublicBaseURL string          `yaml:"public_base_url"`
	TLS           ServerTLSConfig `yaml:"tls"`
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
	URL                string         `yaml:"url"`
	TLS                LDAPTLSConfig  `yaml:"tls"`
	LookupMode         string         `yaml:"lookup_mode"`
	Username           UsernameConfig `yaml:"username"`
	BindDN             string         `yaml:"bind_dn"`
	BindPasswordRef    string         `yaml:"bind_password_ref"`
	BaseDN             string         `yaml:"base_dn"`
	UserFilter         string         `yaml:"user_filter"`
	FilterTemplateMode string         `yaml:"filter_template_mode"`
	Attributes         []string       `yaml:"attributes"`
}

type LDAPTLSConfig struct {
	Verify     bool   `yaml:"verify"`
	ServerName string `yaml:"server_name"`
	CAFileRef  string `yaml:"ca_file_ref"`
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
		if cfg.Tenants[i].LDAP.LookupMode == "" {
			cfg.Tenants[i].LDAP.LookupMode = "search_then_bind"
		}
		if cfg.Tenants[i].LDAP.FilterTemplateMode == "" {
			cfg.Tenants[i].LDAP.FilterTemplateMode = "builtin_or_template"
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
		if cfg.Tenants[i].Protection.MaxConcurrentRequests == 0 {
			cfg.Tenants[i].Protection.MaxConcurrentRequests = 8
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
		validateLDAP(&problems, prefix+".ldap", tenant.LDAP)
		validateTimeouts(&problems, prefix+".timeouts", tenant.Timeouts)
		if tenant.Protection.MaxConcurrentRequests <= 0 {
			problems = append(problems, prefix+".protection.max_concurrent_requests must be positive")
		}
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func validateLDAP(problems *[]string, prefix string, ldap LDAPConfig) {
	if ldap.URL == "" {
		*problems = append(*problems, prefix+".url is required")
	}
	if strings.Contains(ldap.URL, "://") && !strings.HasPrefix(ldap.URL, "ldaps://") {
		*problems = append(*problems, prefix+".url must use ldaps:// in Alpha")
	}
	if !ldap.TLS.Verify {
		*problems = append(*problems, prefix+".tls.verify must be true")
	}
	validateFileRef(problems, prefix+".tls.ca_file_ref", ldap.TLS.CAFileRef, false)
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
	if len(ldap.Attributes) == 0 {
		*problems = append(*problems, prefix+".attributes must contain at least one attribute")
	}
	validateUsername(problems, prefix+".username", ldap.Username)
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
