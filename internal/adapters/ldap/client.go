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

func (c Client) VerifyPassword(ctx context.Context, request directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	conn, err := c.dial(ctx, false)
	if err != nil {
		return directory.VerifyPasswordResult{}, err
	}
	defer conn.Close()

	if err := conn.Bind(c.config.BindDN, c.bindPassword); err != nil {
		return directory.VerifyPasswordResult{}, normalizeLDAPError(err)
	}

	user, err := c.resolveUserWithAttributes(conn, request.Username, request.AttributeNames)
	if err != nil {
		if err == directory.ErrUserNotFound {
			return directory.VerifyPasswordResult{
				Success: false,
				Reason:  "invalid_credentials",
			}, nil
		}
		return directory.VerifyPasswordResult{}, err
	}

	if err := conn.Bind(user.dn, request.Password); err != nil {
		if normalizeLDAPError(err) == directory.ErrInvalidCredentials {
			return directory.VerifyPasswordResult{
				Success: false,
				Reason:  "invalid_credentials",
			}, nil
		}
		return directory.VerifyPasswordResult{}, normalizeLDAPError(err)
	}

	return directory.VerifyPasswordResult{
		Success: true,
		Subject: directory.Subject{
			DirectoryID: user.dn,
			Username:    request.Username,
		},
		Attributes: user.attributes,
	}, nil
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
	user, err := c.resolveUserWithAttributes(conn, username, []string{"dn"})
	if err != nil {
		return "", err
	}
	return user.dn, nil
}

type resolvedUser struct {
	dn         string
	attributes map[string][]string
}

func (c Client) resolveUserWithAttributes(conn *ldap.Conn, username string, attributes []string) (resolvedUser, error) {
	escapedUsername := ldap.EscapeFilter(username)
	filter := strings.ReplaceAll(c.config.UserFilter, "{username}", escapedUsername)
	searchAttributes := requestedAttributes(attributes, c.config.Attributes)
	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		int(durationFromMS(c.timeouts.LDAPSearchMS, time.Second).Seconds()),
		false,
		filter,
		searchAttributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return resolvedUser{}, normalizeLDAPError(err)
	}
	if len(result.Entries) == 0 {
		return resolvedUser{}, directory.ErrUserNotFound
	}

	entry := result.Entries[0]
	return resolvedUser{
		dn:         entry.DN,
		attributes: entryAttributes(entry, searchAttributes),
	}, nil
}

func requestedAttributes(requested []string, allowed []string) []string {
	if len(requested) == 0 {
		return nil
	}

	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}

	result := make([]string, 0, len(requested))
	seen := map[string]struct{}{}
	for _, name := range requested {
		if _, ok := allowedSet[name]; !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func entryAttributes(entry *ldap.Entry, names []string) map[string][]string {
	attrs := make(map[string][]string)
	for _, name := range names {
		values := entry.GetAttributeValues(name)
		if len(values) > 0 {
			attrs[name] = values
		}
	}
	return attrs
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
