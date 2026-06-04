package username

import (
	"errors"
	"testing"

	"github.com/authrim/authrim-wordwarden/internal/ports/config"
)

func TestPreprocessNormalizesUsername(t *testing.T) {
	result, err := Preprocess(" ＡＬＩＣＥ ", config.UsernameConfig{
		AllowedFormats: []string{"local_part"},
		Normalization: config.UsernameNormalizationConfig{
			Trim:    true,
			Unicode: "NFKC",
			Case:    "lower",
		},
	})
	if err != nil {
		t.Fatalf("Preprocess() error = %v", err)
	}
	if result.Value != "alice" {
		t.Fatalf("Value = %q", result.Value)
	}
}

func TestPreprocessRejectsDisallowedFormat(t *testing.T) {
	_, err := Preprocess("alice@example.com", config.UsernameConfig{
		AllowedFormats: []string{"local_part"},
		Normalization:  config.UsernameNormalizationConfig{Trim: true},
	})
	if !errors.Is(err, ErrFormatNotAllowed) {
		t.Fatalf("Preprocess() error = %v, want %v", err, ErrFormatNotAllowed)
	}
}

func TestPreprocessRejectsDomainMismatch(t *testing.T) {
	_, err := Preprocess("alice@evil.example", config.UsernameConfig{
		AllowedFormats: []string{"email"},
		AllowedDomains: []string{"example.com"},
		Normalization: config.UsernameNormalizationConfig{
			Trim:                 true,
			Case:                 "lower",
			RejectDomainMismatch: true,
		},
	})
	if !errors.Is(err, ErrDomainMismatch) {
		t.Fatalf("Preprocess() error = %v, want %v", err, ErrDomainMismatch)
	}
}

func TestPreprocessAllowsConfiguredDomain(t *testing.T) {
	result, err := Preprocess("Alice@Example.COM", config.UsernameConfig{
		AllowedFormats: []string{"email"},
		AllowedDomains: []string{"example.com"},
		Normalization: config.UsernameNormalizationConfig{
			Trim:                 true,
			Case:                 "lower",
			RejectDomainMismatch: true,
		},
	})
	if err != nil {
		t.Fatalf("Preprocess() error = %v", err)
	}
	if result.Value != "alice@example.com" {
		t.Fatalf("Value = %q", result.Value)
	}
}
