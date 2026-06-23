package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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

const version = "0.1.0-beta.1"

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
			serveCtx, cancelServe := context.WithCancel(cmd.Context())
			defer cancelServe()
			if err := startRelayClients(serveCtx, cfg, runtimes, cmd.ErrOrStderr()); err != nil {
				return err
			}

			server := &http.Server{
				Addr:              cfg.Server.Listen,
				Handler:           httpapi.NewHandler(version, httpapi.HandlerOptions{Tenants: runtimes, Audit: auditlog.NewJSONSink(os.Stdout)}),
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
			URL:            tenant.Authrim.Relay.URL,
			TenantID:       tenant.TenantID,
			ConnectorID:    tenant.ConnectorID,
			KeyID:          tenant.Authrim.HMACKeys.Active.KID,
			Secret:         activeSecret,
			Directory:      runtime.Directory,
			RequestTimeout: time.Duration(runtime.RequestTimeoutMS) * time.Millisecond,
			Concurrency:    runtime.ConcurrencyLimit,
			ReconnectMin:   time.Duration(tenant.Authrim.Relay.ReconnectMinMS) * time.Millisecond,
			ReconnectMax:   time.Duration(tenant.Authrim.Relay.ReconnectMaxMS) * time.Millisecond,
			Logger:         logger,
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
