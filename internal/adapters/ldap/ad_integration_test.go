package ldapadapter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"github.com/authrim/authrim-wordwarden/internal/ports/config"
)

func TestSambaADIntegration(t *testing.T) {
	if os.Getenv("WORDWARDEN_SAMBA_AD_INTEGRATION") != "1" {
		t.Skip("set WORDWARDEN_SAMBA_AD_INTEGRATION=1 to run Samba AD integration test")
	}

	cfg := config.LDAPConfig{
		URL: envOr("WORDWARDEN_SAMBA_AD_URL", "ldap://localhost:1390"),
		TLS: config.LDAPTLSConfig{
			Verify: false,
		},
		DirectoryProfile: config.DirectoryProfileConfig{
			Name:                 "active_directory",
			SubjectAttribute:     "objectGUID",
			IdentifierAttributes: []string{"sAMAccountName", "userPrincipalName", "mail"},
			GroupStrategy:        "member_attribute_only",
			StatusNormalization:  "active_directory",
		},
		LookupMode: "search_then_bind",
		Username: config.UsernameConfig{
			AllowedFormats: []string{"local_part", "email"},
			AllowedDomains: []string{"example.test"},
			Normalization: config.UsernameNormalizationConfig{
				Trim:                 true,
				Unicode:              "NFKC",
				Case:                 "lower",
				RejectDomainMismatch: true,
			},
		},
		BindDN:             envOr("WORDWARDEN_SAMBA_AD_BIND_DN", "Administrator@EXAMPLE.TEST"),
		BaseDN:             envOr("WORDWARDEN_SAMBA_AD_BASE_DN", "CN=Users,DC=example,DC=test"),
		UserFilter:         "(|(sAMAccountName={username})(userPrincipalName={username})(mail={username}))",
		FilterTemplateMode: "builtin_or_template",
		Attributes:         []string{"sAMAccountName", "mail", "displayName", "memberOf"},
		Groups: config.GroupConfig{
			Enabled:           true,
			MemberAttribute:   "memberOf",
			ResponseAttribute: "groups",
			IDAttribute:       "cn",
			DisplayAttribute:  "cn",
			MaxDepth:          1,
			MaxGroups:         100,
			TimeoutMS:         1000,
		},
	}

	client := NewClient(cfg, envOr("WORDWARDEN_SAMBA_AD_BIND_PASSWORD", "Passw0rd!"), integrationTimeouts())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.VerifyPassword(ctx, directory.VerifyPasswordRequest{
		Username:       envOr("WORDWARDEN_SAMBA_AD_USERNAME", "alice"),
		Password:       envOr("WORDWARDEN_SAMBA_AD_PASSWORD", "Password123!"),
		AttributeNames: []string{"sAMAccountName", "mail", "displayName", "groups"},
	})
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !result.Success {
		t.Fatalf("VerifyPassword() result = %#v", result)
	}
	if result.Subject.DirectoryID == "" {
		t.Fatalf("DirectoryID is empty: %#v", result.Subject)
	}
	if result.Attributes["mail"][0] != "alice@example.test" {
		t.Fatalf("mail attribute = %#v", result.Attributes["mail"])
	}
	if len(result.GroupFacts) == 0 {
		t.Fatalf("expected group facts, got %#v", result.GroupFacts)
	}
}

func TestRealADIntegration(t *testing.T) {
	if os.Getenv("WORDWARDEN_REAL_AD_INTEGRATION") != "1" {
		t.Skip("set WORDWARDEN_REAL_AD_INTEGRATION=1 to run real AD integration test")
	}

	required := []string{
		"WORDWARDEN_REAL_AD_URL",
		"WORDWARDEN_REAL_AD_BIND_DN",
		"WORDWARDEN_REAL_AD_BIND_PASSWORD",
		"WORDWARDEN_REAL_AD_BASE_DN",
		"WORDWARDEN_REAL_AD_USERNAME",
		"WORDWARDEN_REAL_AD_PASSWORD",
	}
	for _, name := range required {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required when WORDWARDEN_REAL_AD_INTEGRATION=1", name)
		}
	}

	cfg := config.LDAPConfig{
		URL: os.Getenv("WORDWARDEN_REAL_AD_URL"),
		TLS: config.LDAPTLSConfig{
			Verify:     envOr("WORDWARDEN_REAL_AD_TLS_VERIFY", "true") != "false",
			ServerName: os.Getenv("WORDWARDEN_REAL_AD_TLS_SERVER_NAME"),
			CAFileRef:  optionalFileRef(os.Getenv("WORDWARDEN_REAL_AD_CA_FILE")),
			StartTLS:   os.Getenv("WORDWARDEN_REAL_AD_STARTTLS") == "1",
		},
		DirectoryProfile: config.DirectoryProfileConfig{
			Name:                 "active_directory",
			SubjectAttribute:     envOr("WORDWARDEN_REAL_AD_SUBJECT_ATTRIBUTE", "objectGUID"),
			IdentifierAttributes: []string{"sAMAccountName", "userPrincipalName", "mail"},
			GroupStrategy:        envOr("WORDWARDEN_REAL_AD_GROUP_STRATEGY", "member_attribute_only"),
			StatusNormalization:  "active_directory",
		},
		LookupMode: "search_then_bind",
		Username: config.UsernameConfig{
			AllowedFormats: []string{"local_part", "email", "upn"},
			Normalization: config.UsernameNormalizationConfig{
				Trim:    true,
				Unicode: "NFKC",
				Case:    "none",
			},
		},
		BindDN:             os.Getenv("WORDWARDEN_REAL_AD_BIND_DN"),
		BaseDN:             os.Getenv("WORDWARDEN_REAL_AD_BASE_DN"),
		UserFilter:         envOr("WORDWARDEN_REAL_AD_USER_FILTER", "(|(sAMAccountName={username})(userPrincipalName={username})(mail={username}))"),
		FilterTemplateMode: "builtin_or_template",
		Attributes:         []string{"sAMAccountName", "userPrincipalName", "mail", "displayName", "memberOf"},
		Groups: config.GroupConfig{
			Enabled:           os.Getenv("WORDWARDEN_REAL_AD_GROUPS") == "1",
			MemberAttribute:   "memberOf",
			ResponseAttribute: "groups",
			IDAttribute:       "cn",
			DisplayAttribute:  "cn",
			MaxDepth:          1,
			MaxGroups:         100,
			TimeoutMS:         3000,
		},
	}

	client := NewClient(cfg, os.Getenv("WORDWARDEN_REAL_AD_BIND_PASSWORD"), integrationTimeouts())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := client.VerifyPassword(ctx, directory.VerifyPasswordRequest{
		Username:       os.Getenv("WORDWARDEN_REAL_AD_USERNAME"),
		Password:       os.Getenv("WORDWARDEN_REAL_AD_PASSWORD"),
		AttributeNames: []string{"sAMAccountName", "userPrincipalName", "mail", "displayName", "groups"},
	})
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !result.Success {
		t.Fatalf("VerifyPassword() result = %#v", result)
	}
	if result.Subject.DirectoryID == "" {
		t.Fatalf("DirectoryID is empty: %#v", result.Subject)
	}
}

func integrationTimeouts() config.TimeoutConfig {
	return config.TimeoutConfig{
		LDAPConnectMS: 3000,
		LDAPBindMS:    5000,
		LDAPSearchMS:  5000,
		RequestMS:     10000,
	}
}

func envOr(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func optionalFileRef(path string) string {
	if path == "" {
		return ""
	}
	return "file:" + path
}
