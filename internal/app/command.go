package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/adapters/auditlog"
	hmacadapter "github.com/authrim/authrim-wordwarden/internal/adapters/hmac"
	ldapadapter "github.com/authrim/authrim-wordwarden/internal/adapters/ldap"
	relayadapter "github.com/authrim/authrim-wordwarden/internal/adapters/relay"
	secretsadapter "github.com/authrim/authrim-wordwarden/internal/adapters/secrets"
	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"github.com/authrim/authrim-wordwarden/internal/ports/config"
	"github.com/authrim/authrim-wordwarden/internal/ports/httpapi"
	"github.com/authrim/authrim-wordwarden/internal/ports/secrets"
	"github.com/spf13/cobra"
)

var version = "0.1.0-beta.1"

func Execute() error {
	return NewRootCommand().Execute()
}

func NewRootCommand() *cobra.Command {
	var configPath string

	root := &cobra.Command{
		Use:           "wordwarden",
		Short:         "Authrim Wordwarden Directory Connector",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "config.yaml", "Path to Wordwarden config YAML")

	root.AddCommand(newServeCommand(&configPath))
	root.AddCommand(newConfigCommand(&configPath))
	root.AddCommand(newLDAPCommand(&configPath))
	root.AddCommand(newDiagnosticsCommand(&configPath))
	root.AddCommand(newDoctorCommand(&configPath))
	root.AddCommand(newUpdateCommand())
	root.AddCommand(newVersionCommand())

	return root
}

func newServeCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the Wordwarden HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadFile(*configPath)
			if err != nil {
				return err
			}
			runtimes, err := buildTenantRuntimes(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			instanceID, err := loadOrCreateInstanceID(cfg.Server.StateDir)
			if err != nil {
				return err
			}
			startedAt := time.Now().UTC()
			serveCtx, cancelServe := context.WithCancel(cmd.Context())
			defer cancelServe()
			if err := startRelayClients(serveCtx, cfg, runtimes, instanceID, startedAt, cmd.ErrOrStderr()); err != nil {
				return err
			}
			if err := startHeartbeatClients(serveCtx, cfg, instanceID, startedAt, cmd.ErrOrStderr()); err != nil {
				return err
			}

			server := &http.Server{
				Addr:              cfg.Server.Listen,
				Handler:           httpapi.NewHandler(version, httpapi.HandlerOptions{Tenants: runtimes, Audit: auditlog.NewJSONSink(os.Stdout), ExposeOperations: cfg.Server.ExposeOperations}),
				ReadHeaderTimeout: 5 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				if cfg.Server.TLS.Enabled {
					certPath, keyPath, err := tlsFilePaths(cfg.Server.TLS)
					if err != nil {
						errCh <- err
						return
					}
					errCh <- server.ListenAndServeTLS(certPath, keyPath)
					return
				}
				errCh <- server.ListenAndServe()
			}()

			stopCh := make(chan os.Signal, 1)
			signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)

			reloadCh := make(chan os.Signal, 1)
			signal.Notify(reloadCh, syscall.SIGHUP)

			for {
				select {
				case sig := <-reloadCh:
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "received %s, config reload is not supported in this beta; restart required\n", sig)
				case sig := <-stopCh:
					cancelServe()
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := server.Shutdown(shutdownCtx); err != nil {
						return err
					}
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "received %s, stopped\n", sig)
					return nil
				case err := <-errCh:
					if errors.Is(err, http.ErrServerClosed) {
						return nil
					}
					return err
				}
			}
		},
	}
}

func newConfigCommand(configPath *string) *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate Wordwarden configuration",
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate Wordwarden config without reading secret values",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := config.LoadFile(*configPath); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "config valid")
			return nil
		},
	}

	configCmd.AddCommand(validateCmd)
	return configCmd
}

func newLDAPCommand(configPath *string) *cobra.Command {
	var tenantID string
	var username string
	var passwordStdin bool
	var allowInsecure bool

	ldapCmd := &cobra.Command{
		Use:   "ldap",
		Short: "Run LDAP diagnostics",
	}

	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test LDAP TLS, service bind, filter, and optional user bind",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tenantID == "" {
				return errors.New("--tenant is required")
			}

			cfg, err := config.LoadFile(*configPath)
			if err != nil {
				return err
			}
			tenant, err := findTenant(cfg, tenantID)
			if err != nil {
				return err
			}

			resolver := secretsadapter.NewResolver()
			bindPassword, err := resolveOptionalSecretBytes(cmd.Context(), resolver, tenant.LDAP.BindPasswordRef)
			if err != nil {
				return fmt.Errorf("resolve LDAP bind password: %w", err)
			}

			password := ""
			if passwordStdin {
				password, err = readPassword(cmd.InOrStdin())
				if err != nil {
					return err
				}
				if username == "" {
					return errors.New("--username is required when --password-stdin is used")
				}
			}

			client := ldapadapter.NewClient(tenant.LDAP, string(bindPassword), tenant.Timeouts)
			result, err := client.TestConnection(cmd.Context(), directory.TestConnectionRequest{
				Username:      username,
				Password:      password,
				TestPassword:  passwordStdin,
				AllowInsecure: allowInsecure,
			})
			if err != nil {
				return err
			}

			printLDAPTestResult(cmd.OutOrStdout(), result)
			return nil
		},
	}

	testCmd.Flags().StringVar(&tenantID, "tenant", "", "Tenant id to test")
	testCmd.Flags().StringVar(&username, "username", "", "Optional username for user DN resolution")
	testCmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read user password from stdin and test user bind")
	testCmd.Flags().BoolVar(&allowInsecure, "insecure", false, "Diagnostic-only: skip LDAP TLS certificate verification")

	ldapCmd.AddCommand(testCmd)
	return ldapCmd
}

func newDiagnosticsCommand(configPath *string) *cobra.Command {
	diagnosticsCmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Create redacted diagnostic output",
	}

	bundleCmd := &cobra.Command{
		Use:   "bundle",
		Short: "Print a redacted diagnostic bundle",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadFile(*configPath)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(buildDiagnosticBundle(cfg))
		},
	}

	diagnosticsCmd.AddCommand(bundleCmd)
	return diagnosticsCmd
}

func newDoctorCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check local Wordwarden runtime readiness without printing secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadFile(*configPath)
			if err != nil {
				return err
			}
			report := buildDoctorReport(cfg)
			for _, check := range report.Checks {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", check.Status, check.Name, check.Detail)
			}
			if report.HasFailures {
				return errors.New("doctor found failed checks")
			}
			return nil
		},
	}
}

func newUpdateCommand() *cobra.Command {
	var feedURL string
	var currentVersion string
	var channel string
	var timeout time.Duration

	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Check signed update guidance",
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Check release advisory feed without installing updates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if feedURL == "" {
				return errors.New("--feed-url is required")
			}
			feed, err := readAdvisoryFeed(cmd.Context(), feedURL, timeout)
			if err != nil {
				return err
			}
			if channel != "" && feed.Channel != "" && channel != feed.Channel {
				return fmt.Errorf("feed channel %q does not match requested channel %q", feed.Channel, channel)
			}
			if currentVersion == "" {
				currentVersion = version
			}
			result := evaluateUpdateFeed(feed, currentVersion)
			printUpdateCheckResult(cmd.OutOrStdout(), result)
			return nil
		},
	}
	checkCmd.Flags().StringVar(&feedURL, "feed-url", "", "Release advisory JSON feed URL or file path")
	checkCmd.Flags().StringVar(&currentVersion, "current-version", version, "Current Wordwarden version")
	checkCmd.Flags().StringVar(&channel, "channel", "stable", "Expected release channel")
	checkCmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Feed fetch timeout")

	updateCmd.AddCommand(checkCmd)
	return updateCmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Wordwarden version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), version)
			return nil
		},
	}
}

type doctorReport struct {
	Checks      []doctorCheck
	HasFailures bool
}

type doctorCheck struct {
	Name   string
	Status string
	Detail string
}

func buildDoctorReport(cfg *config.Config) doctorReport {
	report := doctorReport{}
	addDoctorCheck := func(name string, ok bool, detail string) {
		status := "ok"
		if !ok {
			status = "fail"
			report.HasFailures = true
		}
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}
	addDoctorWarning := func(name string, warn bool, detail string) {
		status := "ok"
		if warn {
			status = "warn"
		}
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}

	addDoctorCheck("config.tenants", len(cfg.Tenants) > 0, fmt.Sprintf("%d tenant(s)", len(cfg.Tenants)))
	addDoctorCheck("server.listen", cfg.Server.Listen != "", cfg.Server.Listen)
	addDoctorWarning("server.state_dir", cfg.Server.StateDir == "", cfg.Server.StateDir)
	addDoctorWarning("server.tls", !cfg.Server.TLS.Enabled, "TLS disabled; use only behind a trusted local proxy or tunnel")

	for _, tenant := range cfg.Tenants {
		prefix := "tenant." + tenant.TenantID + "."
		addDoctorCheck(prefix+"connector_id", tenant.ConnectorID != "", tenant.ConnectorID)
		addDoctorCheck(prefix+"hmac.active_kid", tenant.Authrim.HMACKeys.Active.KID != "", tenant.Authrim.HMACKeys.Active.KID)
		addDoctorCheck(prefix+"hmac.active_secret_ref", isSecretRef(tenant.Authrim.HMACKeys.Active.SecretRef), "secret reference configured")
		addDoctorCheck(prefix+"audit_hash_secret_ref", isSecretRef(tenant.Authrim.AuditHashSecretRef), "secret reference configured")
		addDoctorWarning(prefix+"ldap.tls_verify", !tenant.LDAP.TLS.Verify, "LDAP TLS verification disabled")
		addDoctorCheck(prefix+"ldap.endpoint", len(tenant.LDAP.URLs) > 0 || tenant.LDAP.URL != "", "LDAP endpoint configured")
		if tenant.Authrim.Relay.Enabled {
			addDoctorCheck(prefix+"relay.url", tenant.Authrim.Relay.URL != "", "relay enabled")
		}
		if tenant.Authrim.Heartbeat.Enabled {
			addDoctorCheck(prefix+"heartbeat.key", isSecretRef(tenant.Authrim.Heartbeat.Key.SecretRef), "heartbeat key reference configured")
		}
	}
	return report
}

func isSecretRef(value string) bool {
	return strings.HasPrefix(value, "env:") || strings.HasPrefix(value, "file:")
}

type advisoryFeed struct {
	Channel       string            `json:"channel"`
	LatestVersion string            `json:"latest_version"`
	ReleaseURL    string            `json:"release_url"`
	Advisories    []releaseAdvisory `json:"advisories"`
}

type releaseAdvisory struct {
	AdvisoryID       string   `json:"advisory_id"`
	AffectedVersions []string `json:"affected_versions"`
	FixedVersion     string   `json:"fixed_version"`
	Severity         string   `json:"severity"`
	Summary          string   `json:"summary"`
	PublishedAt      string   `json:"published_at"`
	UpdatedAt        string   `json:"updated_at"`
	ReleaseURL       string   `json:"release_url"`
}

type updateCheckResult struct {
	CurrentVersion     string
	LatestVersion      string
	ReleaseURL         string
	UpdateAvailable    bool
	AffectedAdvisories []releaseAdvisory
}

func readAdvisoryFeed(ctx context.Context, rawURL string, timeout time.Duration) (advisoryFeed, error) {
	var data []byte
	parsed, err := url.Parse(rawURL)
	if err == nil && parsed.Scheme == "file" {
		data, err = os.ReadFile(parsed.Path)
	} else if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		httpClient := &http.Client{Timeout: timeout}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return advisoryFeed{}, err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return advisoryFeed{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return advisoryFeed{}, fmt.Errorf("release advisory feed returned HTTP %d", resp.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	} else {
		data, err = os.ReadFile(rawURL)
	}
	if err != nil {
		return advisoryFeed{}, err
	}

	var feed advisoryFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return advisoryFeed{}, err
	}
	return feed, nil
}

func evaluateUpdateFeed(feed advisoryFeed, current string) updateCheckResult {
	result := updateCheckResult{
		CurrentVersion: current,
		LatestVersion:  feed.LatestVersion,
		ReleaseURL:     feed.ReleaseURL,
	}
	result.UpdateAvailable = normalizeVersion(feed.LatestVersion) != "" &&
		normalizeVersion(feed.LatestVersion) != normalizeVersion(current)
	for _, advisory := range feed.Advisories {
		if advisoryAffectsVersion(advisory, current) {
			result.AffectedAdvisories = append(result.AffectedAdvisories, advisory)
		}
	}
	return result
}

func advisoryAffectsVersion(advisory releaseAdvisory, current string) bool {
	normalizedCurrent := normalizeVersion(current)
	for _, affected := range advisory.AffectedVersions {
		if advisoryVersionMatches(affected, normalizedCurrent) {
			return true
		}
	}
	return false
}

func advisoryVersionMatches(candidate string, normalizedCurrent string) bool {
	normalizedCandidate := normalizeVersion(candidate)
	if normalizedCandidate == "" {
		return false
	}
	if normalizedCandidate == "*" || normalizedCandidate == normalizedCurrent {
		return true
	}
	for _, operator := range []string{"<=", ">=", "<", ">"} {
		if strings.HasPrefix(normalizedCandidate, operator) {
			expected := normalizeVersion(strings.TrimPrefix(normalizedCandidate, operator))
			compared := compareVersions(normalizedCurrent, expected)
			switch operator {
			case "<=":
				return compared <= 0
			case ">=":
				return compared >= 0
			case "<":
				return compared < 0
			case ">":
				return compared > 0
			}
		}
	}
	if strings.HasSuffix(normalizedCandidate, ".*") {
		return strings.HasPrefix(normalizedCurrent, strings.TrimSuffix(normalizedCandidate, "*"))
	}
	return false
}

func normalizeVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}

func compareVersions(left string, right string) int {
	leftParts := versionParts(left)
	rightParts := versionParts(right)
	maxLen := len(leftParts)
	if len(rightParts) > maxLen {
		maxLen = len(rightParts)
	}
	for i := 0; i < maxLen; i++ {
		leftValue := 0
		rightValue := 0
		if i < len(leftParts) {
			leftValue = leftParts[i]
		}
		if i < len(rightParts) {
			rightValue = rightParts[i]
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}

func versionParts(value string) []int {
	core := strings.SplitN(value, "-", 2)[0]
	parts := strings.Split(core, ".")
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		var parsed int
		_, _ = fmt.Sscanf(part, "%d", &parsed)
		result = append(result, parsed)
	}
	return result
}

func printUpdateCheckResult(writer io.Writer, result updateCheckResult) {
	_, _ = fmt.Fprintf(writer, "current_version=%s\n", result.CurrentVersion)
	_, _ = fmt.Fprintf(writer, "latest_version=%s\n", result.LatestVersion)
	_, _ = fmt.Fprintf(writer, "update_available=%t\n", result.UpdateAvailable)
	_, _ = fmt.Fprintf(writer, "security_advisories=%d\n", len(result.AffectedAdvisories))
	for _, advisory := range result.AffectedAdvisories {
		_, _ = fmt.Fprintf(
			writer,
			"advisory=%s severity=%s fixed_version=%s summary=%q\n",
			advisory.AdvisoryID,
			advisory.Severity,
			advisory.FixedVersion,
			advisory.Summary,
		)
	}
	if result.ReleaseURL != "" {
		_, _ = fmt.Fprintf(writer, "release_url=%s\n", result.ReleaseURL)
	}
}

type diagnosticBundle struct {
	Connector string                    `json:"connector"`
	Version   string                    `json:"version"`
	Server    diagnosticServerSummary   `json:"server"`
	Tenants   []diagnosticTenantSummary `json:"tenants"`
}

type diagnosticServerSummary struct {
	Listen        string `json:"listen"`
	PublicBaseURL string `json:"public_base_url,omitempty"`
	TLSEnabled    bool   `json:"tls_enabled"`
}

type diagnosticTenantSummary struct {
	TenantID           string                 `json:"tenant_id"`
	ConnectorID        string                 `json:"connector_id"`
	HMACActiveKID      string                 `json:"hmac_active_kid"`
	HasPreviousHMACKey bool                   `json:"has_previous_hmac_key"`
	Relay              diagnosticRelaySummary `json:"relay"`
	LDAP               diagnosticLDAPSummary  `json:"ldap"`
	Timeouts           diagnosticTimeouts     `json:"timeouts"`
	Protection         diagnosticProtection   `json:"protection"`
}

type diagnosticRelaySummary struct {
	Enabled        bool   `json:"enabled"`
	URLHost        string `json:"url_host,omitempty"`
	URLPath        string `json:"url_path,omitempty"`
	ReconnectMinMS int    `json:"reconnect_min_ms"`
	ReconnectMaxMS int    `json:"reconnect_max_ms"`
}

type diagnosticLDAPSummary struct {
	URLCount      int      `json:"url_count"`
	LookupMode    string   `json:"lookup_mode"`
	StartTLS      bool     `json:"start_tls"`
	TLSVerify     bool     `json:"tls_verify"`
	Attributes    []string `json:"attributes"`
	GroupsEnabled bool     `json:"groups_enabled"`
	ReferralsMode string   `json:"referrals_mode"`
}

type diagnosticTimeouts struct {
	LDAPConnectMS int `json:"ldap_connect_ms"`
	LDAPBindMS    int `json:"ldap_bind_ms"`
	LDAPSearchMS  int `json:"ldap_search_ms"`
	RequestMS     int `json:"request_ms"`
}

type diagnosticProtection struct {
	MaxConcurrentRequests int `json:"max_concurrent_requests"`
	StormWindowMS         int `json:"storm_window_ms"`
	StormBlockMS          int `json:"storm_block_ms"`
	MalformedRequestLimit int `json:"malformed_request_limit"`
	ReplayLimit           int `json:"replay_limit"`
	DirectoryErrorLimit   int `json:"directory_error_limit"`
}

func buildDiagnosticBundle(cfg *config.Config) diagnosticBundle {
	bundle := diagnosticBundle{
		Connector: "authrim-wordwarden",
		Version:   version,
		Server: diagnosticServerSummary{
			Listen:        cfg.Server.Listen,
			PublicBaseURL: cfg.Server.PublicBaseURL,
			TLSEnabled:    cfg.Server.TLS.Enabled,
		},
		Tenants: make([]diagnosticTenantSummary, 0, len(cfg.Tenants)),
	}

	for _, tenant := range cfg.Tenants {
		urlHost, urlPath := relayURLSummary(tenant.Authrim.Relay.URL)
		urlCount := len(tenant.LDAP.URLs)
		if tenant.LDAP.URL != "" {
			urlCount++
		}
		bundle.Tenants = append(bundle.Tenants, diagnosticTenantSummary{
			TenantID:           tenant.TenantID,
			ConnectorID:        tenant.ConnectorID,
			HMACActiveKID:      tenant.Authrim.HMACKeys.Active.KID,
			HasPreviousHMACKey: tenant.Authrim.HMACKeys.Previous != nil,
			Relay: diagnosticRelaySummary{
				Enabled:        tenant.Authrim.Relay.Enabled,
				URLHost:        urlHost,
				URLPath:        urlPath,
				ReconnectMinMS: tenant.Authrim.Relay.ReconnectMinMS,
				ReconnectMaxMS: tenant.Authrim.Relay.ReconnectMaxMS,
			},
			LDAP: diagnosticLDAPSummary{
				URLCount:      urlCount,
				LookupMode:    tenant.LDAP.LookupMode,
				StartTLS:      tenant.LDAP.TLS.StartTLS,
				TLSVerify:     tenant.LDAP.TLS.Verify,
				Attributes:    append([]string(nil), tenant.LDAP.Attributes...),
				GroupsEnabled: tenant.LDAP.Groups.Enabled,
				ReferralsMode: tenant.LDAP.Referrals.Mode,
			},
			Timeouts: diagnosticTimeouts{
				LDAPConnectMS: tenant.Timeouts.LDAPConnectMS,
				LDAPBindMS:    tenant.Timeouts.LDAPBindMS,
				LDAPSearchMS:  tenant.Timeouts.LDAPSearchMS,
				RequestMS:     tenant.Timeouts.RequestMS,
			},
			Protection: diagnosticProtection{
				MaxConcurrentRequests: tenant.Protection.MaxConcurrentRequests,
				StormWindowMS:         tenant.Protection.StormWindowMS,
				StormBlockMS:          tenant.Protection.StormBlockMS,
				MalformedRequestLimit: tenant.Protection.MalformedRequestLimit,
				ReplayLimit:           tenant.Protection.ReplayLimit,
				DirectoryErrorLimit:   tenant.Protection.DirectoryErrorLimit,
			},
		})
	}
	return bundle
}

func relayURLSummary(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	return parsed.Host, parsed.EscapedPath()
}

func buildTenantRuntimes(ctx context.Context, cfg *config.Config) (map[string]httpapi.TenantRuntime, error) {
	resolver := secretsadapter.NewResolver()
	runtimes := make(map[string]httpapi.TenantRuntime, len(cfg.Tenants))

	for _, tenant := range cfg.Tenants {
		activeSecret, err := resolveSecretBytes(ctx, resolver, tenant.Authrim.HMACKeys.Active.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("tenant %s active HMAC secret: %w", tenant.TenantID, err)
		}
		keySet := hmacadapter.KeySet{
			Active: hmacadapter.Key{
				KID:    tenant.Authrim.HMACKeys.Active.KID,
				Secret: activeSecret,
			},
		}
		if tenant.Authrim.HMACKeys.Previous != nil {
			previousSecret, err := resolveSecretBytes(ctx, resolver, tenant.Authrim.HMACKeys.Previous.SecretRef)
			if err != nil {
				return nil, fmt.Errorf("tenant %s previous HMAC secret: %w", tenant.TenantID, err)
			}
			keySet.Previous = &hmacadapter.Key{
				KID:    tenant.Authrim.HMACKeys.Previous.KID,
				Secret: previousSecret,
			}
		}
		auditHashSecret, err := resolveSecretBytes(ctx, resolver, tenant.Authrim.AuditHashSecretRef)
		if err != nil {
			return nil, fmt.Errorf("tenant %s audit hash secret: %w", tenant.TenantID, err)
		}

		bindPassword, err := resolveOptionalSecretBytes(ctx, resolver, tenant.LDAP.BindPasswordRef)
		if err != nil {
			return nil, fmt.Errorf("tenant %s LDAP bind password: %w", tenant.TenantID, err)
		}

		runtimes[tenant.ConnectorID] = httpapi.TenantRuntime{
			TenantID:         tenant.TenantID,
			ConnectorID:      tenant.ConnectorID,
			HMACVerifier:     hmacadapter.NewVerifier(keySet),
			Directory:        ldapadapter.NewClient(tenant.LDAP, string(bindPassword), tenant.Timeouts),
			AuditHashSecret:  auditHashSecret,
			ConcurrencyLimit: tenant.Protection.MaxConcurrentRequests,
			RequestTimeoutMS: tenant.Timeouts.RequestMS,
			StormProtection: httpapi.StormProtectionPolicy{
				WindowMS:              tenant.Protection.StormWindowMS,
				BlockMS:               tenant.Protection.StormBlockMS,
				MalformedRequestLimit: tenant.Protection.MalformedRequestLimit,
				ReplayLimit:           tenant.Protection.ReplayLimit,
				DirectoryErrorLimit:   tenant.Protection.DirectoryErrorLimit,
			},
		}
	}

	return runtimes, nil
}

func startRelayClients(
	ctx context.Context,
	cfg *config.Config,
	runtimes map[string]httpapi.TenantRuntime,
	instanceID string,
	startedAt time.Time,
	logWriter io.Writer,
) error {
	resolver := secretsadapter.NewResolver()
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: slog.LevelInfo}))

	for _, tenant := range cfg.Tenants {
		if !tenant.Authrim.Relay.Enabled {
			continue
		}
		runtime, ok := runtimes[tenant.ConnectorID]
		if !ok {
			return fmt.Errorf("tenant %s relay runtime not found for connector %s", tenant.TenantID, tenant.ConnectorID)
		}
		activeSecret, err := resolveSecretBytes(ctx, resolver, tenant.Authrim.HMACKeys.Active.SecretRef)
		if err != nil {
			return fmt.Errorf("tenant %s relay HMAC secret: %w", tenant.TenantID, err)
		}
		client, err := relayadapter.NewClient(relayadapter.Config{
			URL:               tenant.Authrim.Relay.URL,
			TenantID:          tenant.TenantID,
			ConnectorID:       tenant.ConnectorID,
			InstanceID:        instanceID,
			DisplayName:       tenant.Authrim.Heartbeat.DisplayName,
			Version:           version,
			StartedAt:         startedAt,
			ConfigFingerprint: configFingerprint(tenant),
			ConfigCategories:  []string{"tenant", "connector", "ldap", "profile", "protection", "relay", "heartbeat"},
			KeyID:             tenant.Authrim.HMACKeys.Active.KID,
			Secret:            activeSecret,
			Directory:         runtime.Directory,
			RequestTimeout:    time.Duration(runtime.RequestTimeoutMS) * time.Millisecond,
			Concurrency:       runtime.ConcurrencyLimit,
			ReconnectMin:      time.Duration(tenant.Authrim.Relay.ReconnectMinMS) * time.Millisecond,
			ReconnectMax:      time.Duration(tenant.Authrim.Relay.ReconnectMaxMS) * time.Millisecond,
			Logger:            logger,
		})
		if err != nil {
			return fmt.Errorf("tenant %s relay client: %w", tenant.TenantID, err)
		}
		go func() {
			_ = client.Run(ctx)
		}()
	}
	return nil
}

func resolveSecretBytes(ctx context.Context, resolver secretsadapter.Resolver, raw string) ([]byte, error) {
	ref, err := secrets.ParseRef(raw)
	if err != nil {
		return nil, err
	}
	value, err := resolver.ResolveSecret(ctx, ref)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func resolveOptionalSecretBytes(ctx context.Context, resolver secretsadapter.Resolver, raw string) ([]byte, error) {
	if raw == "" {
		return nil, nil
	}
	return resolveSecretBytes(ctx, resolver, raw)
}

func findTenant(cfg *config.Config, tenantID string) (config.TenantConfig, error) {
	for _, tenant := range cfg.Tenants {
		if tenant.TenantID == tenantID {
			return tenant, nil
		}
	}
	return config.TenantConfig{}, fmt.Errorf("tenant %q not found", tenantID)
}

func readPassword(reader io.Reader) (string, error) {
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func printLDAPTestResult(writer io.Writer, result directory.TestConnectionResult) {
	_, _ = fmt.Fprintln(writer, "ldap test ok")
	_, _ = fmt.Fprintf(writer, "tls_verified=%t\n", result.TLSVerified)
	_, _ = fmt.Fprintf(writer, "service_bound=%t\n", result.ServiceBound)
	if result.UserResolved {
		_, _ = fmt.Fprintln(writer, "user_resolved=true")
	}
	if result.PasswordOK {
		_, _ = fmt.Fprintln(writer, "password_bind=true")
	}
}

func tlsFilePaths(tls config.ServerTLSConfig) (string, string, error) {
	if tls.CertFileRef == "" || tls.KeyFileRef == "" {
		return "", "", errors.New("server.tls.cert_file_ref and key_file_ref are required when server.tls.enabled is true")
	}

	certPath, err := fileRefPath(tls.CertFileRef)
	if err != nil {
		return "", "", fmt.Errorf("server.tls.cert_file_ref: %w", err)
	}
	keyPath, err := fileRefPath(tls.KeyFileRef)
	if err != nil {
		return "", "", fmt.Errorf("server.tls.key_file_ref: %w", err)
	}

	return certPath, keyPath, nil
}

func fileRefPath(ref string) (string, error) {
	const prefix = "file:"
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Errorf("must use %s reference", prefix)
	}
	path := strings.TrimPrefix(ref, prefix)
	if path == "" {
		return "", errors.New("file reference path is empty")
	}
	return path, nil
}
