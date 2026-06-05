package ldapadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
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
	pool         *connectionPool
}

func NewClient(cfg config.LDAPConfig, bindPassword string, timeouts config.TimeoutConfig) Client {
	client := Client{
		config:       cfg,
		bindPassword: bindPassword,
		timeouts:     timeouts,
	}
	if cfg.Pool.MaxIdle > 0 {
		client.pool = newConnectionPool(cfg.Pool.MaxIdle)
	}
	return client
}

func (c Client) TestConnection(ctx context.Context, request directory.TestConnectionRequest) (directory.TestConnectionResult, error) {
	conn, err := c.acquireConn(ctx, request.AllowInsecure)
	if err != nil {
		return directory.TestConnectionResult{}, err
	}
	reusable := false
	defer func() {
		c.releaseConn(conn, reusable)
	}()

	result := directory.TestConnectionResult{
		TLSVerified: !request.AllowInsecure,
	}

	if request.Username == "" {
		if c.serviceSearchAvailable() {
			if err := c.bindService(ctx, conn); err != nil {
				return directory.TestConnectionResult{}, err
			}
			result.ServiceBound = true
			reusable = true
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
			reusable = c.restoreServiceBindForReuse(ctx, conn) == nil
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
			reusable = c.restoreServiceBindForReuse(ctx, conn) == nil
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
			reusable = c.restoreServiceBindForReuse(ctx, conn) == nil
		}
	default:
		return result, fmt.Errorf("unsupported ldap lookup_mode %q", c.config.LookupMode)
	}

	return result, nil
}

func (c Client) VerifyPassword(ctx context.Context, request directory.VerifyPasswordRequest) (directory.VerifyPasswordResult, error) {
	if request.Password == "" {
		return directory.FailedVerification(directory.ReasonInvalidCredentials), nil
	}

	processed, err := usernamecore.Preprocess(request.Username, c.config.Username)
	if err != nil {
		return directory.FailedVerification(directory.ReasonInvalidCredentials), nil
	}

	conn, err := c.acquireConn(ctx, false)
	if err != nil {
		return directory.VerifyPasswordResult{}, err
	}
	reusable := false
	defer func() {
		c.releaseConn(conn, reusable)
	}()

	switch c.lookupMode() {
	case "search_then_bind":
		if err := c.bindService(ctx, conn); err != nil {
			return directory.VerifyPasswordResult{}, err
		}

		user, err := c.resolveUserWithAttributes(ctx, conn, processed.Value, request.AttributeNames)
		if err != nil {
			if err == directory.ErrUserNotFound {
				return directory.FailedVerification(directory.ReasonInvalidCredentials), nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		if err := c.bindUser(ctx, conn, user.dn, request.Password); err != nil {
			if result, ok := credentialVerdictFromBindError(err); ok {
				return result, nil
			}
			return directory.VerifyPasswordResult{}, err
		}
		reusable = c.restoreServiceBindForReuse(ctx, conn) == nil

		return directory.SuccessfulVerification(
			directory.Subject{
				DirectoryID: user.dn,
				Username:    processed.Value,
			},
			user.attributes,
		), nil
	case "dn_template":
		userDN := c.userDNFromTemplate(processed.Value)
		if err := c.bindUser(ctx, conn, userDN, request.Password); err != nil {
			if result, ok := credentialVerdictFromBindError(err); ok {
				return result, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		attributes, err := c.resolveAttributesAfterSuccessfulBind(ctx, conn, userDN, processed.Value, request.AttributeNames)
		if err != nil {
			return directory.VerifyPasswordResult{}, err
		}
		reusable = c.restoreServiceBindForReuse(ctx, conn) == nil

		return directory.SuccessfulVerification(
			directory.Subject{
				DirectoryID: userDN,
				Username:    processed.Value,
			},
			attributes,
		), nil
	case "direct_bind":
		if err := c.bindUser(ctx, conn, processed.Value, request.Password); err != nil {
			if result, ok := credentialVerdictFromBindError(err); ok {
				return result, nil
			}
			return directory.VerifyPasswordResult{}, err
		}

		attributes, directoryID, err := c.resolveDirectBindAttributes(ctx, conn, processed.Value, request.AttributeNames)
		if err != nil {
			return directory.VerifyPasswordResult{}, err
		}
		reusable = c.restoreServiceBindForReuse(ctx, conn) == nil

		return directory.SuccessfulVerification(
			directory.Subject{
				DirectoryID: directoryID,
				Username:    processed.Value,
			},
			attributes,
		), nil
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
	searchAttributes := c.searchAttributes(requested)
	if len(searchAttributes) == 0 || !c.serviceSearchAvailable() {
		return nil, nil
	}

	if err := c.bindService(ctx, conn); err != nil {
		return nil, err
	}

	attributes, err := c.resolveAttributesByDN(ctx, conn, userDN, requested)
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
	if len(c.searchAttributes(requested)) == 0 || !c.serviceSearchAvailable() {
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

func (c Client) resolveAttributesByDN(ctx context.Context, conn *ldap.Conn, dn string, requested []string) (map[string][]string, error) {
	timeout, err := c.setOperationTimeout(ctx, conn, c.timeouts.LDAPSearchMS, time.Second)
	if err != nil {
		return nil, err
	}
	searchAttributes := c.searchAttributes(requested)
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		ldapTimeLimitSeconds(timeout),
		false,
		"(objectClass=*)",
		searchAttributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, normalizeLDAPError(err)
	}
	if len(result.Entries) == 0 {
		return nil, directory.ErrUserNotFound
	}

	return c.entryAttributes(result.Entries[0], requested), nil
}

func (c Client) dial(ctx context.Context, allowInsecure bool) (*ldap.Conn, error) {
	var lastErr error
	var tlsErr error
	for _, endpoint := range c.endpointURLs() {
		conn, err := c.dialEndpoint(ctx, endpoint, allowInsecure)
		if err == nil {
			return conn, nil
		}
		if errors.Is(err, directory.ErrDirectoryTLS) && tlsErr == nil {
			tlsErr = err
		}
		lastErr = err
	}
	if tlsErr != nil {
		return nil, tlsErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no LDAP endpoints configured")
	}
	return nil, fmt.Errorf("%w: %v", directory.ErrDirectoryUnavailable, lastErr)
}

func (c Client) acquireConn(ctx context.Context, allowInsecure bool) (*ldap.Conn, error) {
	if allowInsecure || c.pool == nil {
		return c.dial(ctx, allowInsecure)
	}
	if conn, ok := c.pool.get(); ok {
		if err := c.validatePooledConn(ctx, conn); err == nil {
			return conn, nil
		}
		conn.Close()
	}
	return c.dial(ctx, false)
}

func (c Client) releaseConn(conn *ldap.Conn, reusable bool) {
	if conn == nil {
		return
	}
	if reusable && c.pool != nil && c.pool.put(conn) {
		return
	}
	conn.Close()
}

func (c Client) restoreServiceBindForReuse(ctx context.Context, conn *ldap.Conn) error {
	if c.pool == nil || !c.serviceSearchAvailable() {
		return fmt.Errorf("connection is not reusable without service bind settings")
	}
	return c.bindService(ctx, conn)
}

func (c Client) validatePooledConn(ctx context.Context, conn *ldap.Conn) error {
	if !c.serviceSearchAvailable() {
		return fmt.Errorf("pooled connection requires service bind settings")
	}
	return c.bindService(ctx, conn)
}

type connectionPool struct {
	idle chan *ldap.Conn
}

func newConnectionPool(maxIdle int) *connectionPool {
	return &connectionPool{idle: make(chan *ldap.Conn, maxIdle)}
}

func (p *connectionPool) get() (*ldap.Conn, bool) {
	select {
	case conn := <-p.idle:
		return conn, true
	default:
		return nil, false
	}
}

func (p *connectionPool) put(conn *ldap.Conn) bool {
	select {
	case p.idle <- conn:
		return true
	default:
		return false
	}
}

func (c Client) endpointURLs() []string {
	result := make([]string, 0, 1+len(c.config.URLs))
	if c.config.URL != "" {
		result = append(result, c.config.URL)
	}
	result = append(result, c.config.URLs...)
	return result
}

func (c Client) dialEndpoint(ctx context.Context, endpoint string, allowInsecure bool) (*ldap.Conn, error) {
	timeout, err := timeoutWithinContext(ctx, c.timeouts.LDAPConnectMS, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig, err := c.tlsConfig(endpoint, allowInsecure)
	if err != nil {
		return nil, err
	}

	if c.config.TLS.StartTLS {
		conn, err := ldap.DialURL(endpoint, ldap.DialWithDialer(dialer))
		if err != nil {
			return nil, err
		}
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, normalizeLDAPError(err)
		}
		return conn, nil
	}

	return ldap.DialURL(
		endpoint,
		ldap.DialWithDialer(dialer),
		ldap.DialWithTLSConfig(tlsConfig),
	)
}

func (c Client) tlsConfig(endpoint string, allowInsecure bool) (*tls.Config, error) {
	serverName := c.config.TLS.ServerName
	if serverName == "" {
		if parsed, err := url.Parse(endpoint); err == nil {
			serverName = parsed.Hostname()
		}
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
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
	searchAttributes := c.searchAttributes(attributes)
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
		attributes: c.entryAttributes(entry, attributes),
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

func (c Client) searchAttributes(requested []string) []string {
	attrs := requestedAttributes(requested, c.config.Attributes)
	if !c.config.Groups.Enabled || !requestedAttributeIncludes(requested, c.config.Groups.ResponseAttribute) {
		return attrs
	}
	if c.config.Groups.MemberAttribute == "" {
		return attrs
	}
	if stringSliceContains(attrs, c.config.Groups.MemberAttribute) {
		return attrs
	}
	return append(attrs, c.config.Groups.MemberAttribute)
}

func (c Client) entryAttributes(entry *ldap.Entry, requested []string) map[string][]string {
	names := requestedAttributes(requested, c.config.Attributes)
	attrs := make(map[string][]string)
	for _, name := range names {
		values := entry.GetAttributeValues(name)
		if len(values) > 0 {
			attrs[name] = values
		}
	}
	if c.config.Groups.Enabled && requestedAttributeIncludes(requested, c.config.Groups.ResponseAttribute) {
		values := entry.GetAttributeValues(c.config.Groups.MemberAttribute)
		if len(values) > 0 {
			attrs[c.config.Groups.ResponseAttribute] = values
		}
	}
	return attrs
}

func requestedAttributeIncludes(requested []string, name string) bool {
	if name == "" {
		return false
	}
	return stringSliceContains(requested, name)
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func normalizeLDAPError(err error) error {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		if mapped, ok := normalizeADInvalidCredentialsError(err); ok {
			return mapped
		}
		return directory.ErrInvalidCredentials
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultConnectError) {
		return directory.ErrDirectoryUnavailable
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultReferral) {
		return directory.ErrDirectoryReferral
	}
	return err
}

func credentialVerdictFromBindError(err error) (directory.VerifyPasswordResult, bool) {
	switch {
	case errors.Is(err, directory.ErrInvalidCredentials):
		return directory.FailedVerification(directory.ReasonInvalidCredentials), true
	case errors.Is(err, directory.ErrAccountDisabled):
		return directory.FailedVerification(directory.ReasonAccountDisabled), true
	case errors.Is(err, directory.ErrAccountLocked):
		return directory.FailedVerification(directory.ReasonAccountLocked), true
	case errors.Is(err, directory.ErrPasswordExpired):
		return directory.PolicyRequiredVerification(directory.ReasonPasswordExpired), true
	case errors.Is(err, directory.ErrMustChangePassword):
		return directory.PolicyRequiredVerification(directory.ReasonMustChangePassword), true
	default:
		return directory.VerifyPasswordResult{}, false
	}
}

var adDataCodePattern = regexp.MustCompile(`(?i)\bdata\s+([0-9a-f]+)\b`)

func normalizeADInvalidCredentialsError(err error) (error, bool) {
	matches := adDataCodePattern.FindStringSubmatch(err.Error())
	if len(matches) != 2 {
		return nil, false
	}

	switch strings.ToLower(matches[1]) {
	case "532":
		return directory.ErrPasswordExpired, true
	case "533":
		return directory.ErrAccountDisabled, true
	case "773":
		return directory.ErrMustChangePassword, true
	case "775":
		return directory.ErrAccountLocked, true
	default:
		return nil, false
	}
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
