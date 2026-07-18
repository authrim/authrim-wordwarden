package ldapadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
		if err := c.requireServiceSearch(); err != nil {
			return result, err
		}
		if err := c.bindService(ctx, conn); err != nil {
			return directory.TestConnectionResult{}, err
		}
		result.ServiceBound = true

		user, err := c.resolveUserWithAttributes(ctx, conn, processed.Value, nil)
		if err != nil {
			return result, err
		}
		result.UserResolved = true
		result.Subject = directory.Subject{
			DirectoryID: user.subjectID(),
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
			if result, ok := userResolutionFailureResult(err); ok {
				return result, nil
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
				DirectoryID: user.subjectID(),
				Username:    processed.Value,
			},
			user.attributes,
			user.groupFacts,
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

		user, err := c.resolveDirectBindUser(ctx, conn, processed.Value, request.AttributeNames)
		if err != nil {
			if result, ok := userResolutionFailureResult(err); ok {
				return result, nil
			}
			return directory.VerifyPasswordResult{}, err
		}
		reusable = c.restoreServiceBindForReuse(ctx, conn) == nil

		return directory.SuccessfulVerification(
			directory.Subject{
				DirectoryID: user.subjectID(),
				Username:    processed.Value,
			},
			user.attributes,
			user.groupFacts,
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
		return c.normalizeLDAPError(err)
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
		return c.normalizeLDAPError(err)
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

func (c Client) requireServiceSearch() error {
	if c.serviceSearchAvailable() {
		return nil
	}
	return fmt.Errorf("ldap direct_bind requires bind_dn, bind_password_ref, base_dn, and user_filter")
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

func (c Client) resolveDirectBindUser(ctx context.Context, conn *ldap.Conn, username string, requested []string) (resolvedUser, error) {
	if err := c.requireServiceSearch(); err != nil {
		return resolvedUser{}, err
	}
	if err := c.bindService(ctx, conn); err != nil {
		return resolvedUser{}, err
	}

	return c.resolveUserWithAttributes(ctx, conn, username, requested)
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

	result, err := c.search(ctx, conn, searchRequest)
	if err != nil {
		return nil, c.normalizeLDAPError(err)
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
			return nil, c.normalizeLDAPError(err)
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

func (c Client) search(ctx context.Context, conn *ldap.Conn, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	result, err := c.searchOnce(ctx, conn, request)
	if err != nil {
		return result, err
	}
	if result == nil || len(result.Referrals) == 0 {
		return result, nil
	}
	if c.config.Referrals.Mode != "allowlist" || !c.config.Referrals.AllowServiceBindReuse {
		return nil, directory.ErrDirectoryReferral
	}

	followed, err := c.followReferrals(ctx, request, result.Referrals)
	if err != nil {
		return nil, err
	}
	result.Entries = append(result.Entries, followed.Entries...)
	result.Referrals = append(result.Referrals, followed.Referrals...)
	return result, nil
}

func (c Client) searchOnce(ctx context.Context, conn *ldap.Conn, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if !c.config.DirectoryProfile.PagedSearch.Enabled {
		return conn.Search(request)
	}

	paged := c.config.DirectoryProfile.PagedSearch
	timeout, err := timeoutWithinContext(ctx, paged.TimeoutMS, time.Duration(paged.TimeoutMS)*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	request.TimeLimit = ldapTimeLimitSeconds(timeout)

	return c.searchWithPagingLimit(conn, request, uint32(paged.PageSize), paged.MaxEntries)
}

func (c Client) searchWithPagingLimit(conn *ldap.Conn, request *ldap.SearchRequest, pageSize uint32, maxEntries int) (*ldap.SearchResult, error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("%w: paged search max_entries must be positive", directory.ErrDirectoryUnavailable)
	}
	pagingControl := ldap.NewControlPaging(pageSize)
	request.Controls = append(withoutPagingControl(request.Controls), pagingControl)
	combined := &ldap.SearchResult{}

	for {
		result, err := conn.Search(request)
		if result != nil {
			combined.Entries = append(combined.Entries, result.Entries...)
			combined.Referrals = append(combined.Referrals, result.Referrals...)
			combined.Controls = append(combined.Controls, result.Controls...)
			if len(combined.Entries) > maxEntries {
				combined.Entries = combined.Entries[:maxEntries]
				return combined, fmt.Errorf("%w: paged search exceeded max_entries", directory.ErrDirectoryUnavailable)
			}
		}
		if err != nil {
			return combined, err
		}
		if result == nil {
			return combined, fmt.Errorf("%w: ldap search returned no result", directory.ErrDirectoryUnavailable)
		}
		control := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if control == nil {
			return combined, nil
		}
		pagingResult, ok := control.(*ldap.ControlPaging)
		if !ok || len(pagingResult.Cookie) == 0 {
			return combined, nil
		}
		pagingControl.SetCookie(pagingResult.Cookie)
	}
}

func withoutPagingControl(controls []ldap.Control) []ldap.Control {
	if len(controls) == 0 {
		return nil
	}
	result := make([]ldap.Control, 0, len(controls))
	for _, control := range controls {
		if control.GetControlType() == ldap.ControlTypePaging {
			continue
		}
		result = append(result, control)
	}
	return result
}

func (c Client) followReferrals(ctx context.Context, original *ldap.SearchRequest, referrals []string) (*ldap.SearchResult, error) {
	combined := &ldap.SearchResult{}
	for _, referral := range referrals {
		endpoint, baseDN, ok := c.allowedReferral(referral)
		if !ok {
			return nil, directory.ErrDirectoryReferral
		}
		conn, err := c.dialEndpoint(ctx, endpoint, false)
		if err != nil {
			return nil, err
		}
		func() {
			defer conn.Close()
			if err = c.bindService(ctx, conn); err != nil {
				return
			}
			request := cloneSearchRequest(original)
			if baseDN != "" {
				request.BaseDN = baseDN
			}
			var result *ldap.SearchResult
			result, err = c.searchOnce(ctx, conn, request)
			if result != nil {
				combined.Entries = append(combined.Entries, result.Entries...)
				combined.Referrals = append(combined.Referrals, result.Referrals...)
				combined.Controls = append(combined.Controls, result.Controls...)
			}
		}()
		if err != nil {
			return nil, err
		}
		if len(combined.Referrals) > 0 {
			return nil, directory.ErrDirectoryReferral
		}
	}
	return combined, nil
}

func cloneSearchRequest(request *ldap.SearchRequest) *ldap.SearchRequest {
	attrs := append([]string(nil), request.Attributes...)
	controls := append([]ldap.Control(nil), request.Controls...)
	return ldap.NewSearchRequest(
		request.BaseDN,
		request.Scope,
		request.DerefAliases,
		request.SizeLimit,
		request.TimeLimit,
		request.TypesOnly,
		request.Filter,
		attrs,
		controls,
	)
}

func (c Client) allowedReferral(raw string) (endpoint string, baseDN string, ok bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || !c.referralSchemeAllowed(parsed.Scheme) {
		return "", "", false
	}
	refEndpoint := referralEndpoint(parsed)
	for _, allowed := range c.config.Referrals.AllowedURLs {
		allowedParsed, err := url.Parse(allowed)
		if err != nil || allowedParsed.Host == "" || !c.referralSchemeAllowed(allowedParsed.Scheme) {
			continue
		}
		if referralEndpoint(allowedParsed) == refEndpoint {
			base := strings.TrimPrefix(parsed.EscapedPath(), "/")
			if base != "" {
				if unescaped, err := url.PathUnescape(base); err == nil {
					base = unescaped
				}
			}
			return refEndpoint, base, true
		}
	}
	return "", "", false
}

func (c Client) referralSchemeAllowed(scheme string) bool {
	if c.config.TLS.StartTLS {
		return scheme == "ldap"
	}
	return scheme == "ldaps"
}

func referralEndpoint(parsed *url.URL) string {
	host := strings.ToLower(parsed.Host)
	return parsed.Scheme + "://" + host
}

func (c Client) resolveUser(ctx context.Context, conn *ldap.Conn, username string) (string, error) {
	user, err := c.resolveUserWithAttributes(ctx, conn, username, []string{"dn"})
	if err != nil {
		return "", err
	}
	return user.subjectID(), nil
}

type resolvedUser struct {
	dn           string
	subjectValue string
	attributes   map[string][]string
	groupFacts   []directory.GroupFact
}

func (u resolvedUser) subjectID() string {
	if u.subjectValue != "" {
		return u.subjectValue
	}
	return u.dn
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

	result, err := c.search(ctx, conn, searchRequest)
	if err != nil {
		return resolvedUser{}, c.normalizeLDAPError(err)
	}
	entry, err := singleSearchEntry(result.Entries)
	if err != nil {
		return resolvedUser{}, err
	}

	return resolvedUser{
		dn:           entry.DN,
		subjectValue: c.entrySubjectValue(entry),
		attributes:   c.entryAttributes(entry, attributes),
		groupFacts:   c.groupFacts(ctx, conn, entry, attributes),
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

func userResolutionFailureResult(err error) (directory.VerifyPasswordResult, bool) {
	if errors.Is(err, directory.ErrUserNotFound) || errors.Is(err, directory.ErrAmbiguousUser) {
		return directory.FailedVerification(directory.ReasonInvalidCredentials), true
	}
	return directory.VerifyPasswordResult{}, false
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
	if c.config.DirectoryProfile.SubjectAttribute != "" &&
		!stringSliceContains(attrs, c.config.DirectoryProfile.SubjectAttribute) {
		attrs = append(attrs, c.config.DirectoryProfile.SubjectAttribute)
	}
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

func (c Client) groupSearchAttributes() []string {
	names := []string{c.config.Groups.IDAttribute, c.config.Groups.DisplayAttribute}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" {
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

func (c Client) entrySubjectValue(entry *ldap.Entry) string {
	name := c.config.DirectoryProfile.SubjectAttribute
	if name == "" {
		return ""
	}
	for _, attr := range entry.Attributes {
		if !strings.EqualFold(attr.Name, name) {
			continue
		}
		if c.binarySubjectAttribute(name) && len(attr.ByteValues) > 0 {
			return base64.RawURLEncoding.EncodeToString(attr.ByteValues[0])
		}
		if len(attr.Values) > 0 {
			return attr.Values[0]
		}
		if len(attr.ByteValues) > 0 {
			return base64.RawURLEncoding.EncodeToString(attr.ByteValues[0])
		}
	}
	return ""
}

func (c Client) binarySubjectAttribute(name string) bool {
	return c.config.DirectoryProfile.Name == "active_directory" &&
		strings.EqualFold(name, "objectGUID")
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

func (c Client) groupFacts(ctx context.Context, conn *ldap.Conn, entry *ldap.Entry, requested []string) []directory.GroupFact {
	if !c.config.Groups.Enabled || !requestedAttributeIncludes(requested, c.config.Groups.ResponseAttribute) {
		return nil
	}

	switch c.config.DirectoryProfile.GroupStrategy {
	case "ad_matching_rule":
		return c.adMatchingRuleGroupFacts(ctx, conn, entry.DN)
	case "bfs_member_search":
		return c.bfsGroupFacts(ctx, conn, entry.DN)
	default:
		return c.memberAttributeGroupFacts(entry)
	}
}

func (c Client) memberAttributeGroupFacts(entry *ldap.Entry) []directory.GroupFact {
	values := entry.GetAttributeValues(c.config.Groups.MemberAttribute)
	if len(values) == 0 {
		return nil
	}
	facts := make([]directory.GroupFact, 0, len(values))
	for _, dn := range values {
		facts = append(facts, directory.GroupFact{
			ID:      dn,
			DN:      dn,
			Display: dn,
			Source:  c.config.Groups.MemberAttribute,
			Depth:   1,
		})
	}
	return facts
}

func (c Client) adMatchingRuleGroupFacts(ctx context.Context, conn *ldap.Conn, userDN string) []directory.GroupFact {
	filter := fmt.Sprintf("(%s:1.2.840.113556.1.4.1941:=%s)",
		c.config.Groups.SearchMemberAttribute,
		ldap.EscapeFilter(userDN),
	)
	entries, err := c.searchGroupEntries(ctx, conn, filter)
	if err != nil {
		return nil
	}
	return c.groupFactsFromEntries(entries, "ad_matching_rule", 1)
}

func (c Client) bfsGroupFacts(ctx context.Context, conn *ldap.Conn, userDN string) []directory.GroupFact {
	maxDepth := c.config.Groups.MaxDepth
	maxGroups := c.config.Groups.MaxGroups
	seen := map[string]struct{}{}
	frontier := []string{userDN}
	facts := make([]directory.GroupFact, 0)

	for depth := 1; depth <= maxDepth && len(frontier) > 0 && len(facts) < maxGroups; depth++ {
		next := make([]string, 0)
		for _, memberDN := range frontier {
			filter := fmt.Sprintf("(%s=%s)",
				c.config.Groups.SearchMemberAttribute,
				ldap.EscapeFilter(memberDN),
			)
			entries, err := c.searchGroupEntries(ctx, conn, filter)
			if err != nil {
				return facts
			}
			for _, entry := range entries {
				if _, ok := seen[entry.DN]; ok {
					continue
				}
				seen[entry.DN] = struct{}{}
				facts = append(facts, c.groupFactFromEntry(entry, "bfs_member_search", depth))
				if len(facts) >= maxGroups {
					break
				}
				next = append(next, entry.DN)
			}
			if len(facts) >= maxGroups {
				break
			}
		}
		frontier = next
	}

	return facts
}

func (c Client) searchGroupEntries(ctx context.Context, conn *ldap.Conn, filter string) ([]*ldap.Entry, error) {
	timeoutMS := c.config.Groups.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = c.timeouts.LDAPSearchMS
	}
	timeout, err := c.setOperationTimeout(ctx, conn, timeoutMS, time.Second)
	if err != nil {
		return nil, err
	}
	baseDN := c.config.Groups.SearchBaseDN
	if baseDN == "" {
		baseDN = c.config.BaseDN
	}
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		c.config.Groups.MaxGroups,
		ldapTimeLimitSeconds(timeout),
		false,
		filter,
		c.groupSearchAttributes(),
		nil,
	)
	result, err := c.search(ctx, conn, searchRequest)
	if err != nil {
		return nil, err
	}
	if len(result.Entries) > c.config.Groups.MaxGroups {
		return result.Entries[:c.config.Groups.MaxGroups], nil
	}
	return result.Entries, nil
}

func (c Client) groupFactsFromEntries(entries []*ldap.Entry, source string, depth int) []directory.GroupFact {
	limit := c.config.Groups.MaxGroups
	if limit <= 0 || limit > len(entries) {
		limit = len(entries)
	}
	facts := make([]directory.GroupFact, 0, limit)
	for _, entry := range entries[:limit] {
		facts = append(facts, c.groupFactFromEntry(entry, source, depth))
	}
	return facts
}

func (c Client) groupFactFromEntry(entry *ldap.Entry, source string, depth int) directory.GroupFact {
	id := firstAttributeValue(entry, c.config.Groups.IDAttribute)
	if id == "" {
		id = entry.DN
	}
	display := firstAttributeValue(entry, c.config.Groups.DisplayAttribute)
	if display == "" {
		display = id
	}
	return directory.GroupFact{
		ID:      id,
		DN:      entry.DN,
		Display: display,
		Source:  source,
		Depth:   depth,
	}
}

func firstAttributeValue(entry *ldap.Entry, name string) string {
	if name == "" {
		return ""
	}
	values := entry.GetAttributeValues(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
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

func (c Client) normalizeLDAPError(err error) error {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		if c.config.DirectoryProfile.StatusNormalization == "active_directory" {
			if mapped, ok := normalizeADInvalidCredentialsError(err); ok {
				return mapped
			}
		}
		if c.config.DirectoryProfile.StatusNormalization == "" && c.config.DirectoryProfile.Name == "active_directory" {
			if mapped, ok := normalizeADInvalidCredentialsError(err); ok {
				return mapped
			}
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

func normalizeLDAPError(err error) error {
	return Client{config: config.LDAPConfig{
		DirectoryProfile: config.DirectoryProfileConfig{StatusNormalization: "active_directory"},
	}}.normalizeLDAPError(err)
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
