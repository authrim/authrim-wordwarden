package ldapadapter

import (
	"reflect"
	"testing"

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
