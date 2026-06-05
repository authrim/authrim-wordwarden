package ldapadapter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"github.com/authrim/authrim-wordwarden/internal/ports/config"
	"github.com/go-ldap/ldap/v3"
)

func TestUserDNFromTemplateEscapesUsername(t *testing.T) {
	client := NewClient(config.LDAPConfig{
		DNTemplate: "uid={username},ou=People,dc=example,dc=com",
	}, "", config.TimeoutConfig{})

	got := client.userDNFromTemplate(`alice, admin+test`)
	want := `uid=alice\, admin\+test,ou=People,dc=example,dc=com`
	if got != want {
		t.Fatalf("userDNFromTemplate() = %q, want %q", got, want)
	}
}

func TestRequestedAttributesIntersectsAndDeduplicates(t *testing.T) {
	got := requestedAttributes(
		[]string{"mail", "telephoneNumber", "mail", "displayName"},
		[]string{"uid", "mail", "displayName"},
	)
	want := []string{"mail", "displayName"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requestedAttributes() = %#v, want %#v", got, want)
	}
}

func TestEndpointURLsPreferPrimaryThenFailover(t *testing.T) {
	client := NewClient(config.LDAPConfig{
		URL:  "ldaps://ldap-a.example.com:636",
		URLs: []string{"ldaps://ldap-b.example.com:636"},
	}, "", config.TimeoutConfig{})

	got := client.endpointURLs()
	want := []string{"ldaps://ldap-a.example.com:636", "ldaps://ldap-b.example.com:636"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpointURLs() = %#v, want %#v", got, want)
	}
}

func TestNewClientCreatesPoolWhenConfigured(t *testing.T) {
	client := NewClient(config.LDAPConfig{
		Pool: config.PoolConfig{MaxIdle: 2},
	}, "", config.TimeoutConfig{})

	if client.pool == nil {
		t.Fatal("pool = nil")
	}
	if cap(client.pool.idle) != 2 {
		t.Fatalf("pool capacity = %d", cap(client.pool.idle))
	}
}

func TestTLSConfigDerivesServerNameFromEndpoint(t *testing.T) {
	client := NewClient(config.LDAPConfig{}, "", config.TimeoutConfig{})

	got, err := client.tlsConfig("ldaps://ldap-a.example.com:636", false)
	if err != nil {
		t.Fatalf("tlsConfig() error = %v", err)
	}
	if got.ServerName != "ldap-a.example.com" {
		t.Fatalf("ServerName = %q", got.ServerName)
	}
}

func TestDialPreservesDirectoryTLSError(t *testing.T) {
	client := NewClient(config.LDAPConfig{
		URL: "ldaps://ldap-a.example.com:636",
		TLS: config.LDAPTLSConfig{
			CAFileRef: "file:/path/that/does/not/exist",
		},
	}, "", config.TimeoutConfig{})

	_, err := client.dial(context.Background(), false)
	if !errors.Is(err, directory.ErrDirectoryTLS) {
		t.Fatalf("dial() error = %v, want %v", err, directory.ErrDirectoryTLS)
	}
	if errors.Is(err, directory.ErrDirectoryUnavailable) {
		t.Fatalf("dial() error should preserve TLS classification without wrapping unavailable: %v", err)
	}
}

func TestGroupPrimitiveSearchAndResponseAttributes(t *testing.T) {
	client := NewClient(config.LDAPConfig{
		Attributes: []string{"uid", "mail"},
		Groups: config.GroupConfig{
			Enabled:           true,
			MemberAttribute:   "memberOf",
			ResponseAttribute: "groups",
		},
	}, "", config.TimeoutConfig{})

	searchAttrs := client.searchAttributes([]string{"mail", "groups"})
	if !reflect.DeepEqual(searchAttrs, []string{"mail", "memberOf"}) {
		t.Fatalf("searchAttributes() = %#v", searchAttrs)
	}

	entry := &ldap.Entry{
		DN: "uid=alice,ou=People,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "mail", Values: []string{"alice@example.com"}},
			{Name: "memberOf", Values: []string{"cn=staff,ou=Groups,dc=example,dc=com"}},
		},
	}
	attrs := client.entryAttributes(entry, []string{"mail", "groups"})
	if attrs["mail"][0] != "alice@example.com" {
		t.Fatalf("mail attrs = %#v", attrs)
	}
	if attrs["groups"][0] != "cn=staff,ou=Groups,dc=example,dc=com" {
		t.Fatalf("group attrs = %#v", attrs)
	}
	if _, ok := attrs["memberOf"]; ok {
		t.Fatalf("memberOf should not be returned directly: %#v", attrs)
	}
}

func TestBindUserRejectsEmptyPasswordBeforeLDAPBind(t *testing.T) {
	client := NewClient(config.LDAPConfig{}, "", config.TimeoutConfig{})

	if err := client.bindUser(context.Background(), nil, "uid=alice,ou=People,dc=example,dc=com", ""); !errors.Is(err, directory.ErrInvalidCredentials) {
		t.Fatalf("bindUser() error = %v, want %v", err, directory.ErrInvalidCredentials)
	}
}

func TestNormalizeADInvalidCredentialsError(t *testing.T) {
	tests := []struct {
		name string
		code string
		want error
	}{
		{name: "password expired", code: "532", want: directory.ErrPasswordExpired},
		{name: "account disabled", code: "533", want: directory.ErrAccountDisabled},
		{name: "must change password", code: "773", want: directory.ErrMustChangePassword},
		{name: "account locked", code: "775", want: directory.ErrAccountLocked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ldap.NewError(
				ldap.LDAPResultInvalidCredentials,
				fmt.Errorf("80090308: LdapErr: DSID-0C09044B, comment: AcceptSecurityContext error, data %s, v2580", tt.code),
			)

			got := normalizeLDAPError(err)
			if !errors.Is(got, tt.want) {
				t.Fatalf("normalizeLDAPError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeLDAPReferralError(t *testing.T) {
	err := ldap.NewError(ldap.LDAPResultReferral, fmt.Errorf("referral returned"))

	got := normalizeLDAPError(err)
	if !errors.Is(got, directory.ErrDirectoryReferral) {
		t.Fatalf("normalizeLDAPError() = %v, want %v", got, directory.ErrDirectoryReferral)
	}
}

func TestCredentialVerdictFromADBindError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantResult directory.CredentialResult
		wantReason string
	}{
		{
			name:       "invalid credentials",
			err:        directory.ErrInvalidCredentials,
			wantResult: directory.CredentialResultFailure,
			wantReason: directory.ReasonInvalidCredentials,
		},
		{
			name:       "password expired",
			err:        directory.ErrPasswordExpired,
			wantResult: directory.CredentialResultPolicyRequired,
			wantReason: directory.ReasonPasswordExpired,
		},
		{
			name:       "must change password",
			err:        directory.ErrMustChangePassword,
			wantResult: directory.CredentialResultPolicyRequired,
			wantReason: directory.ReasonMustChangePassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := credentialVerdictFromBindError(tt.err)
			if !ok {
				t.Fatal("credentialVerdictFromBindError() did not map error")
			}
			if got.CredentialResult() != tt.wantResult || got.SafeReason() != tt.wantReason {
				t.Fatalf("credentialVerdictFromBindError() = %#v", got)
			}
			if got.IsSuccess() {
				t.Fatal("mapped bind error must not be success")
			}
		})
	}
}

func TestSingleSearchEntryRejectsAmbiguousResults(t *testing.T) {
	_, err := singleSearchEntry([]*ldap.Entry{
		{DN: "uid=alice,ou=People,dc=example,dc=com"},
		{DN: "uid=alice2,ou=People,dc=example,dc=com"},
	})
	if !errors.Is(err, directory.ErrAmbiguousUser) {
		t.Fatalf("singleSearchEntry() error = %v, want %v", err, directory.ErrAmbiguousUser)
	}
}

func TestTimeoutWithinContextCapsConfiguredTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	got, err := timeoutWithinContext(ctx, 1500, time.Second)
	if err != nil {
		t.Fatalf("timeoutWithinContext() error = %v", err)
	}
	if got <= 0 || got > 25*time.Millisecond {
		t.Fatalf("timeoutWithinContext() = %s, want <= 25ms", got)
	}
}

func TestLDAPTimeLimitSecondsRoundsUp(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    int
	}{
		{name: "sub second", timeout: 25 * time.Millisecond, want: 1},
		{name: "exact second", timeout: time.Second, want: 1},
		{name: "partial second", timeout: 1500 * time.Millisecond, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ldapTimeLimitSeconds(tt.timeout); got != tt.want {
				t.Fatalf("ldapTimeLimitSeconds() = %d, want %d", got, tt.want)
			}
		})
	}
}
