package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type SecretRef struct {
	Scheme string
	Name   string
	Raw    string
}

type SecretValue []byte

type Resolver interface {
	ResolveSecret(ctx context.Context, ref SecretRef) (SecretValue, error)
}

func ParseRef(raw string) (SecretRef, error) {
	if raw == "" {
		return SecretRef{}, errors.New("secret reference is empty")
	}
	scheme, name, ok := strings.Cut(raw, ":")
	if !ok || scheme == "" || name == "" {
		return SecretRef{}, fmt.Errorf("invalid secret reference %q", raw)
	}
	switch scheme {
	case "env", "file":
		return SecretRef{Scheme: scheme, Name: name, Raw: raw}, nil
	default:
		return SecretRef{}, fmt.Errorf("unsupported secret reference scheme %q", scheme)
	}
}
