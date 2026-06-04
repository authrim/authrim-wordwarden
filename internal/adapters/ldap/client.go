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
	usernamecore "github.com/authrim/authrim-wordwarden/internal/core/username"
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

	result := directory.TestConnectionResult{
		TLSVerified: !request.AllowInsecure,
	}

	if request.Username == "" {
		if c.serviceSearchAvailable() {
			if err := c.bindService(ctx, conn); err != nil {
				return directory.TestConnectionResult{}, err
			}
			result.ServiceBound = true
		}
		return result, nil
	}

	processed, err := usernamecore.Preprocess(request.Username, c.config.Username)
	if err != nil {
		return result, err
	}

	switch c.lookupMode() {
	case "search_then_bind":
		if err := c.bindService(ctx, conn); err != nil {
			return directory.TestConnectionResult{}, err
		}
		result.ServiceBound = true

		userDN, err := c.resolveUser(ctx, conn, processed.Value)
		if err != nil {
			return result, err
		}
		result.UserResolved = true
		result.Subject = directory.Subject{
			DirectoryID: userDN,
			Username:    processed.Value,
		}

		if request.TestPassword {
			if err := c.bindUser(ctx, conn, userDN, request.Password); err != nil {
				return result, err
			}
			result.PasswordOK = true
		}
	case "dn_template":
		userDN := c.userDNFromTemplate(processed.Value)
		result.UserResolved = true
		result.Subject = directory.Subject{
			DirectoryID: userDN,
			Username:    processed.Value,
		}

		if request.TestPassword {
			if err := c.bindUser(ctx, conn, userDN, request.Password); err != nil {
				return result, err
			}
			result.PasswordOK = true
		}
	case "direct_bind":
		result.UserResolved = true
		result.Subject = directory.Subject{
			DirectoryID: processed.Value,
			Username:    processed.Value,
		}

		if request.TestPassword {
			if err := c.bindUser(ctx, conn, processed.Value, request.Password); err != nil {
				return result, err
			}
			result.PasswordOK = true
		}
	default:
		return result, fmt.Errorf("unsupported ldap lookup_mode %q", c.config.LookupMode)
	}

	return result, nil
}

func (c Client) VerifyPassword(ctx context.Context, request directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	if request.Password == "" {
		return directory.VerifyPasswordResult{
			Success: false,
			Reason:  "invalid_credentials",
		}, nil
	}

	processed, err := usernamecore.Preprocess(request.Username, c.config.Username)
	if err != nil {
		return directory.VerifyPasswordResult{
			Success: false,
			Reason:  "invalid_credentials",
		}, nil
	}

	conn, err := c.dial(ctx, false)
	if err != nil {
		return directory.VerifyPasswordResult{}, err
	}
	defer conn.Close()

	switch c.lookupMode() {
	case "search_then_bind":
		if err := c.bindService(ctx, conn); err != nil {
			return directory.VerifyPasswordResult{}, err
		}

		user, err := c.resolveUserWithAttributes(ctx, conn, processed.Value, request.AttributeNames)
		if err != nil {
			if err == directory.ErrUserNotFound {
				return directory.VerifyPasswordResult{
					Success: false,
					Reason:  "invalid_credentials",
				}, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		if err := c.bindUser(ctx, conn, user.dn, request.Password); err != nil {
			if err == directory.ErrInvalidCredentials {
				return directory.VerifyPasswordResult{
					Success: false,
					Reason:  "invalid_credentials",
				}, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		return directory.VerifyPasswordResult{
			Success: true,
			Subject: directory.Subject{
				DirectoryID: user.dn,
				Username:    processed.Value,
			},
			Attributes: user.attributes,
		}, nil
	case "dn_template":
		userDN := c.userDNFromTemplate(processed.Value)
		if err := c.bindUser(ctx, conn, userDN, request.Password); err != nil {
			if err == directory.ErrInvalidCredentials {
				return directory.VerifyPasswordResult{
					Success: false,
					Reason:  "invalid_credentials",
				}, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		attributes, err := c.resolveAttributesAfterSuccessfulBind(ctx, conn, userDN, processed.Value, request.AttributeNames)
		if err != nil {
			return directory.VerifyPasswordResult{}, err
		}

		return directory.VerifyPasswordResult{
			Success: true,
			Subject: directory.Subject{
				DirectoryID: userDN,
				Username:    processed.Value,
			},
			Attributes: attributes,
		}, nil
	case "direct_bind":
		if err := c.bindUser(ctx, conn, processed.Value, request.Password); err != nil {
			if err == directory.ErrInvalidCredentials {
				return directory.VerifyPasswordResult{
					Success: false,
					Reason:  "invalid_credentials",
				}, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		attributes, directoryID, err := c.resolveDirectBindAttributes(ctx, conn, processed.Value, request.AttributeNames)
		if err != nil {
			return directory.VerifyPasswordResult{}, err
		}

		return directory.VerifyPasswordResult{
			Success: true,
			Subject: directory.Subject{
				DirectoryID: directoryID,
				Username:    processed.Value,
			},
			Attributes: attributes,
		}, nil
	default:
		return directory.VerifyPasswordResult{}, fmt.Errorf("unsupported ldap lookup_mode %q", c.config.LookupMode)
	}
}

func (c Client) bindService(ctx context.Context, conn *ldap.Conn) error {
	if _, err := c.setOperationTimeout(ctx, conn, c.timeouts.LDAPBindMS, 1500*time.Millisecond); err != nil {
		return err
	}
	if err := conn.Bind(c.config.BindDN, c.bindPassword); err != nil {
		return normalizeLDAPError(err)
	}
	return nil
}

func (c Client) bindUser(ctx context.Context, conn *ldap.Conn, bindName string, password string) error {
	if password == "" {
		return directory.ErrInvalidCredentials
	}
	if _, err := c.setOperationTimeout(ctx, conn, c.timeouts.LDAPBindMS, 1500*time.Millisecond); err != nil {
		return err
	}
	if err := conn.Bind(bindName, password); err != nil {
		return normalizeLDAPError(err)
	}
	return nil
}

func (c Client) lookupMode() string {
	if c.config.LookupMode == "" {
		return "search_then_bind"
	}
	return c.config.LookupMode
}

func (c Client) serviceSearchAvailable() bool {
	return c.config.BindDN != "" &&
		c.bindPassword != "" &&
		c.config.BaseDN != "" &&
		c.config.UserFilter != ""
}

func (c Client) userDNFromTemplate(username string) string {
	return strings.ReplaceAll(c.config.DNTemplate, "{username}", ldap.EscapeDN(username))
}

func (c Client) resolveAttributesAfterSuccessfulBind(ctx context.Context, conn *ldap.Conn, userDN string, username string, requested []string) (map[string][]string, error) {
	searchAttributes := requestedAttributes(requested, c.config.Attributes)
	if len(searchAttributes) == 0 || !c.serviceSearchAvailable() {
		return nil, nil
	}

	if err := c.bindService(ctx, conn); err != nil {
		return nil, err
	}

	attributes, err := c.resolveAttributesByDN(ctx, conn, userDN, searchAttributes)
	if err == nil {
		return attributes, nil
	}
	if err != directory.ErrUserNotFound {
		return nil, err
	}

	user, err := c.resolveUserWithAttributes(ctx, conn, username, requested)
	if err == directory.ErrUserNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user.attributes, nil
}

func (c Client) resolveDirectBindAttributes(ctx context.Context, conn *ldap.Conn, username string, requested []string) (map[string][]string, string, error) {
	directoryID := username
	if len(requestedAttributes(requested, c.config.Attributes)) == 0 || !c.serviceSearchAvailable() {
		return nil, directoryID, nil
	}

	if err := c.bindService(ctx, conn); err != nil {
		return nil, "", err
	}

	user, err := c.resolveUserWithAttributes(ctx, conn, username, requested)
	if err == directory.ErrUserNotFound {
		return nil, directoryID, nil
	}
	if err != nil {
		return nil, "", err
	}
	return user.attributes, user.dn, nil
}

func (c Client) resolveAttributesByDN(ctx context.Context, conn *ldap.Conn, dn string, attributes []string) (map[string][]string, error) {
	timeout, err := c.setOperationTimeout(ctx, conn, c.timeouts.LDAPSearchMS, time.Second)
	if err != nil {
		return nil, err
	}
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		ldapTimeLimitSeconds(timeout),
		false,
		"(objectClass=*)",
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, normalizeLDAPError(err)
	}
	if len(result.Entries) == 0 {
		return nil, directory.ErrUserNotFound
	}

	return entryAttributes(result.Entries[0], attributes), nil
}

func (c Client) dial(ctx context.Context, allowInsecure bool) (*ldap.Conn, error) {
	timeout, err := timeoutWithinContext(ctx, c.timeouts.LDAPConnectMS, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
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

func (c Client) resolveUser(ctx context.Context, conn *ldap.Conn, username string) (string, error) {
	user, err := c.resolveUserWithAttributes(ctx, conn, username, []string{"dn"})
	if err != nil {
		return "", err
	}
	return user.dn, nil
}

type resolvedUser struct {
	dn         string
	attributes map[string][]string
}

func (c Client) resolveUserWithAttributes(ctx context.Context, conn *ldap.Conn, username string, attributes []string) (resolvedUser, error) {
	timeout, err := c.setOperationTimeout(ctx, conn, c.timeouts.LDAPSearchMS, time.Second)
	if err != nil {
		return resolvedUser{}, err
	}
	escapedUsername := ldap.EscapeFilter(username)
	filter := strings.ReplaceAll(c.config.UserFilter, "{username}", escapedUsername)
	searchAttributes := requestedAttributes(attributes, c.config.Attributes)
	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		ldapTimeLimitSeconds(timeout),
		false,
		filter,
		searchAttributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return resolvedUser{}, normalizeLDAPError(err)
	}
	entry, err := singleSearchEntry(result.Entries)
	if err != nil {
		return resolvedUser{}, err
	}

	return resolvedUser{
		dn:         entry.DN,
		attributes: entryAttributes(entry, searchAttributes),
	}, nil
}

func singleSearchEntry(entries []*ldap.Entry) (*ldap.Entry, error) {
	switch len(entries) {
	case 0:
		return nil, directory.ErrUserNotFound
	case 1:
		return entries[0], nil
	default:
		return nil, directory.ErrAmbiguousUser
	}
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

func (c Client) setOperationTimeout(ctx context.Context, conn *ldap.Conn, configuredMS int, fallback time.Duration) (time.Duration, error) {
	timeout, err := timeoutWithinContext(ctx, configuredMS, fallback)
	if err != nil {
		return 0, err
	}
	conn.SetTimeout(timeout)
	return timeout, nil
}

func durationFromMS(value int, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

func timeoutWithinContext(ctx context.Context, value int, fallback time.Duration) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %v", directory.ErrDirectoryUnavailable, err)
	}

	timeout := durationFromMS(value, fallback)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, fmt.Errorf("%w: %v", directory.ErrDirectoryUnavailable, context.DeadlineExceeded)
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	if timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	return timeout, nil
}

func ldapTimeLimitSeconds(timeout time.Duration) int {
	if timeout <= 0 {
		return 1
	}
	seconds := int(timeout / time.Second)
	if timeout%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return seconds
}
