package username

import (
	"errors"
	"strings"

	"github.com/authrim/authrim-wordwarden/internal/ports/config"
	"golang.org/x/text/unicode/norm"
)

var (
	ErrEmptyUsername    = errors.New("empty_username")
	ErrFormatNotAllowed = errors.New("username_format_not_allowed")
	ErrDomainMismatch   = errors.New("username_domain_mismatch")
)

type Result struct {
	Value  string
	Format string
}

func Preprocess(raw string, cfg config.UsernameConfig) (Result, error) {
	value := raw
	if cfg.Normalization.Trim {
		value = strings.TrimSpace(value)
	}
	if cfg.Normalization.Unicode == "NFKC" {
		value = norm.NFKC.String(value)
	}
	if cfg.Normalization.Case == "lower" {
		value = strings.ToLower(value)
	}
	if value == "" {
		return Result{}, ErrEmptyUsername
	}

	format := detectFormat(value)
	if !formatAllowed(format, cfg.AllowedFormats) {
		return Result{}, ErrFormatNotAllowed
	}
	if cfg.Normalization.RejectDomainMismatch {
		if err := validateDomain(value, format, cfg); err != nil {
			return Result{}, err
		}
	}

	return Result{Value: value, Format: format}, nil
}

func detectFormat(value string) string {
	if strings.Contains(value, "@") {
		return "email"
	}
	return "local_part"
}

func formatAllowed(format string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == format {
			return true
		}
		if format == "email" && candidate == "upn" {
			return true
		}
	}
	return false
}

func validateDomain(value string, format string, cfg config.UsernameConfig) error {
	if format != "email" {
		return nil
	}
	_, domain, ok := strings.Cut(value, "@")
	if !ok || domain == "" {
		return ErrFormatNotAllowed
	}
	if len(cfg.AllowedDomains) == 0 && len(cfg.AllowedUPNSuffixes) == 0 {
		return nil
	}
	for _, allowed := range cfg.AllowedDomains {
		if strings.EqualFold(domain, allowed) {
			return nil
		}
	}
	for _, allowed := range cfg.AllowedUPNSuffixes {
		if strings.EqualFold(domain, allowed) {
			return nil
		}
	}
	return ErrDomainMismatch
}
