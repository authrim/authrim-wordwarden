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
			if err := c.bindService(conn); err != nil {
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
		if err := c.bindService(conn); err != nil {
			return directory.TestConnectionResult{}, err
		}
		result.ServiceBound = true

		userDN, err := c.resolveUser(conn, processed.Value)
		if err != nil {
			return result, err
		}
		result.UserResolved = true
		result.Subject = directory.Subject{
			DirectoryID: userDN,
			Username:    processed.Value,
		}

		if request.TestPassword {
			if err := c.bindUser(conn, userDN, request.Password); err != nil {
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
			if err := c.bindUser(conn, userDN, request.Password); err != nil {
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
			if err := c.bindUser(conn, processed.Value, request.Password); err != nil {
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
	conn, err := c.dial(ctx, false)
	if err != nil {
		return directory.VerifyPasswordResult{}, err
	}
	defer conn.Close()

	processed, err := usernamecore.Preprocess(request.Username, c.config.Username)
	if err != nil {
		return directory.VerifyPasswordResult{
			Success: false,
			Reason:  "invalid_credentials",
		}, nil
	}

	switch c.lookupMode() {
	case "search_then_bind":
		if err := c.bindService(conn); err != nil {
			return directory.VerifyPasswordResult{}, err
		}

		user, err := c.resolveUserWithAttributes(conn, processed.Value, request.AttributeNames)
		if err != nil {
			if err == directory.ErrUserNotFound {
				return directory.VerifyPasswordResult{
					Success: false,
					Reason:  "invalid_credentials",
				}, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		if err := c.bindUser(conn, user.dn, request.Password); err != nil {
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
		if err := c.bindUser(conn, userDN, request.Password); err != nil {
			if err == directory.ErrInvalidCredentials {
				return directory.VerifyPasswordResult{
					Success: false,
					Reason:  "invalid_credentials",
				}, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		attributes, err := c.resolveAttributesAfterSuccessfulBind(conn, userDN, processed.Value, request.AttributeNames)
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
		if err := c.bindUser(conn, processed.Value, request.Password); err != nil {
			if err == directory.ErrInvalidCredentials {
				return directory.VerifyPasswordResult{
					Success: false,
					Reason:  "invalid_credentials",
				}, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		attributes, directoryID, err := c.resolveDirectBindAttributes(conn, processed.Value, request.AttributeNames)
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

func (c Client) bindService(conn *ldap.Conn) error {
	if err := conn.Bind(c.config.BindDN, c.bindPassword); err != nil {
		return normalizeLDAPError(err)
	}
	return nil
}

func (c Client) bindUser(conn *ldap.Conn, bindName string, password string) error {
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

func (c Client) resolveAttributesAfterSuccessfulBind(conn *ldap.Conn, userDN string, username string, requested []string) (map[string][]string, error) {
	searchAttributes := requestedAttributes(requested, c.config.Attributes)
	if len(searchAttributes) == 0 || !c.serviceSearchAvailable() {
		return nil, nil
	}

	if err := c.bindService(conn); err != nil {
		return nil, err
	}

	attributes, err := c.resolveAttributesByDN(conn, userDN, searchAttributes)
	if err == nil {
		return attributes, nil
	}
	if err != directory.ErrUserNotFound {
		return nil, err
	}

	user, err := c.resolveUserWithAttributes(conn, username, requested)
	if err == directory.ErrUserNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user.attributes, nil
}

func (c Client) resolveDirectBindAttributes(conn *ldap.Conn, username string, requested []string) (map[string][]string, string, error) {
	directoryID := username
	if len(requestedAttributes(requested, c.config.Attributes)) == 0 || !c.serviceSearchAvailable() {
		return nil, directoryID, nil
	}

	if err := c.bindService(conn); err != nil {
		return nil, "", err
	}

	user, err := c.resolveUserWithAttributes(conn, username, requested)
	if err == directory.ErrUserNotFound {
		return nil, directoryID, nil
	}
	if err != nil {
		return nil, "", err
	}
	return user.attributes, user.dn, nil
}

func (c Client) resolveAttributesByDN(conn *ldap.Conn, dn string, attributes []string) (map[string][]string, error) {
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		int(durationFromMS(c.timeouts.LDAPSearchMS, time.Second).Seconds()),
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
