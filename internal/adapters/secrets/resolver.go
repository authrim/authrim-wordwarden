package secretsadapter

import (
	"context"
	"fmt"
	"os"

	"github.com/authrim/authrim-wordwarden/internal/ports/secrets"
)

type Resolver struct{}

func NewResolver() Resolver {
	return Resolver{}
}

func (Resolver) ResolveSecret(_ context.Context, ref secrets.SecretRef) (secrets.SecretValue, error) {
	switch ref.Scheme {
	case "env":
		value, ok := os.LookupEnv(ref.Name)
		if !ok {
			return nil, fmt.Errorf("environment variable %q is not set", ref.Name)
		}
		return secrets.SecretValue(value), nil
	case "file":
		value, err := os.ReadFile(ref.Name)
		if err != nil {
			return nil, err
		}
		return secrets.SecretValue(value), nil
	default:
		return nil, fmt.Errorf("unsupported secret reference scheme %q", ref.Scheme)
	}
}
