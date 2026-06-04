package ldapadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"github.com/authrim/authrim-wordwarden/internal/ports/config"
	"github.com/go-ldap/ldap/v3"
)

type Client struct {
	config       config.LDAPConfig
	bindPassword string
	timeouts     config.TimeoutConfig
}

func NewClient(cfg config.LDAPConfig, bindPassword string, timeouts config.TimeoutConfig) Client {
	return Client{
		config:       cfg,
		bindPassword: bindPassword,
		timeouts:     timeouts,
	}
}

func (c Client) TestConnection(ctx context.Context, request directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	conn, err := c.dial(ctx, request.AllowInsecure)
	if err != nil {
		return directory.TestConnectionResult{}, err
	}
	defer conn.Close()

	if err := conn.Bind(c.config.BindDN, c.bindPassword); err != nil {
		return directory.TestConnectionResult{}, normalizeLDAPError(err)
	}

	result := directory.TestConnectionResult{
		TLSVerified:  !request.AllowInsecure,
		ServiceBound: true,
	}

	if request.Username == "" {
		return result, nil
	}

	userDN, err := c.resolveUser(conn, request.Username)
	if err != nil {
		return result, err
	}
	result.UserResolved = true
	result.Subject = directory.Subject{
		DirectoryID: userDN,
		Username:    request.Username,
	}

	if request.TestPassword {
		if err := conn.Bind(userDN, request.Password); err != nil {
			return result, normalizeLDAPError(err)
		}
		result.PasswordOK = true
	}

	return result, nil
}

func (c Client) dial(_ context.Context, allowInsecure bool) (*ldap.Conn, error) {
	timeout := durationFromMS(c.timeouts.LDAPConnectMS, 500*time.Millisecond)
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig, err := c.tlsConfig(allowInsecure)
	if err != nil {
		return nil, err
	}

	conn, err := ldap.DialURL(
		c.config.URL,
		ldap.DialWithDialer(dialer),
		ldap.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", directory.ErrDirectoryUnavailable, err)
	}
	conn.SetTimeout(durationFromMS(c.timeouts.LDAPBindMS, 1500*time.Millisecond))
	return conn, nil
}

func (c Client) tlsConfig(allowInsecure bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.config.TLS.ServerName,
		InsecureSkipVerify: allowInsecure,
	}

	if c.config.TLS.CAFileRef == "" {
		return tlsConfig, nil
	}

	caPath := strings.TrimPrefix(c.config.TLS.CAFileRef, "file:")
	if caPath == c.config.TLS.CAFileRef || caPath == "" {
		return nil, fmt.Errorf("ldap.tls.ca_file_ref must use file:<path>")
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read CA file: %v", directory.ErrDirectoryTLS, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: CA file has no certificates", directory.ErrDirectoryTLS)
	}
	tlsConfig.RootCAs = pool

	return tlsConfig, nil
}

func (c Client) resolveUser(conn *ldap.Conn, username string) (string, error) {
	escapedUsername := ldap.EscapeFilter(username)
	filter := strings.ReplaceAll(c.config.UserFilter, "{username}", escapedUsername)
	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		int(durationFromMS(c.timeouts.LDAPSearchMS, time.Second).Seconds()),
		false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", normalizeLDAPError(err)
	}
	if len(result.Entries) == 0 {
		return "", directory.ErrUserNotFound
	}
	return result.Entries[0].DN, nil
}

func normalizeLDAPError(err error) error {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return directory.ErrInvalidCredentials
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultConnectError) {
		return directory.ErrDirectoryUnavailable
	}
	return err
}

func durationFromMS(value int, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}
