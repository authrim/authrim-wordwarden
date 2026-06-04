package ldapadapter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"github.com/authrim/authrim-wordwarden/internal/ports/config"
)

func TestOpenLDAPIntegration(t *testing.T) {
	if os.Getenv("WORDWARDEN_LDAP_INTEGRATION") != "1" {
		t.Skip("set WORDWARDEN_LDAP_INTEGRATION=1 to run OpenLDAP integration test")
	}

	caFile := os.Getenv("WORDWARDEN_LDAP_CA_FILE")
	if caFile == "" {
		caFile = "../../../test/integration/openldap/certs/ca.crt"
	}

	client := NewClient(config.LDAPConfig{
		URL: "ldaps://localhost:1636",
		TLS: config.LDAPTLSConfig{
			Verify:     true,
			ServerName: "localhost",
			CAFileRef:  "file:" + caFile,
		},
		LookupMode: "search_then_bind",
		Username: config.UsernameConfig{
			AllowedFormats: []string{"local_part", "email"},
			AllowedDomains: []string{"example.com"},
			Normalization: config.UsernameNormalizationConfig{
				Trim:                 true,
				Unicode:              "NFKC",
				Case:                 "lower",
				RejectDomainMismatch: true,
			},
		},
		BindDN:             "cn=admin,dc=example,dc=com",
		BaseDN:             "dc=example,dc=com",
		UserFilter:         "(uid={username})",
		FilterTemplateMode: "builtin_or_template",
		Attributes:         []string{"uid", "mail", "displayName"},
	}, "admin", config.TimeoutConfig{
		LDAPConnectMS: 1000,
		LDAPBindMS:    1500,
		LDAPSearchMS:  1500,
		RequestMS:     3000,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testResult, err := client.TestConnection(ctx, directory.TestConnectionRequest{
		Username:     " alice ",
		Password:     "password",
		TestPassword: true,
	})
	if err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}
	if !testResult.ServiceBound || !testResult.UserResolved || !testResult.PasswordOK {
		t.Fatalf("TestConnection() result = %#v", testResult)
	}

	verifyResult, err := client.VerifyPassword(ctx, directory.VerifyPasswordRequest{
		Username:       "alice",
		Password:       "password",
		AttributeNames: []string{"uid", "mail", "displayName", "telephoneNumber"},
	})
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !verifyResult.Success {
		t.Fatalf("VerifyPassword() result = %#v", verifyResult)
	}
	if verifyResult.Attributes["mail"][0] != "alice@example.com" {
		t.Fatalf("mail attribute = %#v", verifyResult.Attributes["mail"])
	}
	if _, ok := verifyResult.Attributes["telephoneNumber"]; ok {
		t.Fatalf("unexpected non-allowlisted attribute: %#v", verifyResult.Attributes)
	}
}
