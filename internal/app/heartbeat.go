package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	secretsadapter "github.com/authrim/authrim-wordwarden/internal/adapters/secrets"
	"github.com/authrim/authrim-wordwarden/internal/ports/config"
)

const heartbeatAlgorithm = "AUTHRIM-WORDWARDEN-HEARTBEAT-HMAC-SHA256"

type heartbeatPayload struct {
	InstanceID        string         `json:"instance_id"`
	DisplayName       string         `json:"display_name,omitempty"`
	Transport         string         `json:"transport"`
	Version           string         `json:"version"`
	StartedAt         string         `json:"started_at"`
	HealthStatus      string         `json:"health_status"`
	HealthSummary     map[string]any `json:"health_summary,omitempty"`
	ConfigFingerprint string         `json:"config_fingerprint"`
	ConfigCategories  []string       `json:"config_categories,omitempty"`
	DriftSeverity     string         `json:"drift_severity"`
}

func startHeartbeatClients(
	ctx context.Context,
	cfg *config.Config,
	instanceID string,
	startedAt time.Time,
	logWriter io.Writer,
) error {
	resolver := secretsadapter.NewResolver()
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo}))
	for _, tenant := range cfg.Tenants {
		if !tenant.Authrim.Heartbeat.Enabled {
			continue
		}
		activeSecret, err := resolveSecretBytes(ctx, resolver, tenant.Authrim.Heartbeat.Key.SecretRef)
		if err != nil {
			return fmt.Errorf("tenant %s heartbeat HMAC secret: %w", tenant.TenantID, err)
		}
		client := heartbeatClient{
			tenant:     tenant,
			instanceID: instanceID,
			startedAt:  startedAt,
			keyID:      tenant.Authrim.Heartbeat.Key.KID,
			secret:     activeSecret,
			httpClient: http.DefaultClient,
			logger:     logger,
		}
		go client.run(ctx)
	}
	return nil
}

type heartbeatClient struct {
	tenant     config.TenantConfig
	instanceID string
	startedAt  time.Time
	keyID      string
	secret     []byte
	httpClient *http.Client
	logger     *slog.Logger
}

func (c heartbeatClient) run(ctx context.Context) {
	interval := time.Duration(c.tenant.Authrim.Heartbeat.IntervalMS) * time.Millisecond
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := c.send(ctx); err != nil && c.logger != nil {
				c.logger.Warn("heartbeat failed", "tenant_id", c.tenant.TenantID, "connector_id", c.tenant.ConnectorID, "error", err)
			}
			timer.Reset(interval)
		}
	}
}

func (c heartbeatClient) send(ctx context.Context) error {
	timeout := time.Duration(c.tenant.Authrim.Heartbeat.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, err := json.Marshal(buildHeartbeatPayload(c.tenant, c.instanceID, c.startedAt))
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	canonical := buildHeartbeatCanonical(c.tenant.TenantID, c.tenant.ConnectorID, c.instanceID, c.keyID, timestamp, body)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.tenant.Authrim.Heartbeat.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authrim-Heartbeat-Key-Id", c.keyID)
	req.Header.Set("X-Authrim-Heartbeat-Timestamp", timestamp)
	req.Header.Set("X-Authrim-Heartbeat-Signature", "sha256="+signHeartbeatCanonical(canonical, c.secret))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat rejected with status %d", resp.StatusCode)
	}
	return nil
}

func buildHeartbeatPayload(tenant config.TenantConfig, instanceID string, startedAt time.Time) heartbeatPayload {
	categories := []string{"tenant", "connector", "ldap", "profile", "protection", "relay", "heartbeat"}
	return heartbeatPayload{
		InstanceID:        instanceID,
		DisplayName:       tenant.Authrim.Heartbeat.DisplayName,
		Transport:         tenant.Authrim.Heartbeat.Transport,
		Version:           version,
		StartedAt:         startedAt.UTC().Format(time.RFC3339),
		HealthStatus:      "healthy",
		HealthSummary:     map[string]any{"process": "ok"},
		ConfigFingerprint: configFingerprint(tenant),
		ConfigCategories:  categories,
		DriftSeverity:     "none",
	}
}

func configFingerprint(tenant config.TenantConfig) string {
	type fingerprintInput struct {
		TenantID            string                  `json:"tenant_id"`
		ConnectorID         string                  `json:"connector_id"`
		LDAPURLCount        int                     `json:"ldap_url_count"`
		LDAPSchemes         []string                `json:"ldap_schemes"`
		LDAPTLSVerify       bool                    `json:"ldap_tls_verify"`
		LDAPStartTLS        bool                    `json:"ldap_start_tls"`
		LookupMode          string                  `json:"lookup_mode"`
		Profile             map[string]any          `json:"profile"`
		Attributes          []string                `json:"attributes"`
		UsernameFormats     []string                `json:"username_formats"`
		UsernameDomains     []string                `json:"username_domains"`
		UsernameUPNSuffixes []string                `json:"username_upn_suffixes"`
		GroupsEnabled       bool                    `json:"groups_enabled"`
		ReferralsMode       string                  `json:"referrals_mode"`
		Timeouts            config.TimeoutConfig    `json:"timeouts"`
		Protection          config.ProtectionConfig `json:"protection"`
		RelayEnabled        bool                    `json:"relay_enabled"`
		HeartbeatTransport  string                  `json:"heartbeat_transport"`
		HeartbeatIntervalMS int                     `json:"heartbeat_interval_ms"`
		HeartbeatTimeoutMS  int                     `json:"heartbeat_timeout_ms"`
	}
	urls := ldapURLs(tenant.LDAP)
	schemes := make([]string, 0, len(urls))
	for _, rawURL := range urls {
		if len(rawURL) >= 6 && rawURL[:6] == "ldaps:" {
			schemes = append(schemes, "ldaps")
		} else if len(rawURL) >= 5 && rawURL[:5] == "ldap:" {
			schemes = append(schemes, "ldap")
		}
	}
	sort.Strings(schemes)
	input := fingerprintInput{
		TenantID:      tenant.TenantID,
		ConnectorID:   tenant.ConnectorID,
		LDAPURLCount:  len(urls),
		LDAPSchemes:   schemes,
		LDAPTLSVerify: tenant.LDAP.TLS.Verify,
		LDAPStartTLS:  tenant.LDAP.TLS.StartTLS,
		LookupMode:    tenant.LDAP.LookupMode,
		Profile: map[string]any{
			"name":                   tenant.LDAP.DirectoryProfile.Name,
			"subject_attribute":      tenant.LDAP.DirectoryProfile.SubjectAttribute,
			"identifier_attributes":  sortedStrings(tenant.LDAP.DirectoryProfile.IdentifierAttributes),
			"group_strategy":         tenant.LDAP.DirectoryProfile.GroupStrategy,
			"status_normalization":   tenant.LDAP.DirectoryProfile.StatusNormalization,
			"paged_search_enabled":   tenant.LDAP.DirectoryProfile.PagedSearch.Enabled,
			"paged_search_page_size": tenant.LDAP.DirectoryProfile.PagedSearch.PageSize,
		},
		Attributes:          sortedStrings(tenant.LDAP.Attributes),
		UsernameFormats:     sortedStrings(tenant.LDAP.Username.AllowedFormats),
		UsernameDomains:     sortedStrings(tenant.LDAP.Username.AllowedDomains),
		UsernameUPNSuffixes: sortedStrings(tenant.LDAP.Username.AllowedUPNSuffixes),
		GroupsEnabled:       tenant.LDAP.Groups.Enabled,
		ReferralsMode:       tenant.LDAP.Referrals.Mode,
		Timeouts:            tenant.Timeouts,
		Protection:          tenant.Protection,
		RelayEnabled:        tenant.Authrim.Relay.Enabled,
		HeartbeatTransport:  tenant.Authrim.Heartbeat.Transport,
		HeartbeatIntervalMS: tenant.Authrim.Heartbeat.IntervalMS,
		HeartbeatTimeoutMS:  tenant.Authrim.Heartbeat.TimeoutMS,
	}
	raw, _ := json.Marshal(input)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ldapURLs(ldap config.LDAPConfig) []string {
	result := make([]string, 0, 1+len(ldap.URLs))
	if ldap.URL != "" {
		result = append(result, ldap.URL)
	}
	result = append(result, ldap.URLs...)
	return result
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func buildHeartbeatCanonical(tenantID string, connectorID string, instanceID string, keyID string, timestamp string, body []byte) string {
	sum := sha256.Sum256(body)
	return heartbeatAlgorithm + "\n" +
		tenantID + "\n" +
		connectorID + "\n" +
		instanceID + "\n" +
		keyID + "\n" +
		timestamp + "\n" +
		hex.EncodeToString(sum[:])
}

func signHeartbeatCanonical(canonical string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}
