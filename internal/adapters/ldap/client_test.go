package ldapadapter

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"github.com/authrim/authrim-wordwarden/internal/ports/config"
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

func TestBindUserRejectsEmptyPasswordBeforeLDAPBind(t *testing.T) {
	client := NewClient(config.LDAPConfig{}, "", config.TimeoutConfig{})

	if err := client.bindUser(context.Background(), nil, "uid=alice,ou=People,dc=example,dc=com", ""); !errors.Is(err, directory.ErrInvalidCredentials) {
		t.Fatalf("bindUser() error = %v, want %v", err, directory.ErrInvalidCredentials)
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
