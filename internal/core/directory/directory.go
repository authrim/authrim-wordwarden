package directory

import (
	"context"
	"errors"
)

var (
	ErrInvalidCredentials   = errors.New("invalid_credentials")
	ErrUserNotFound         = errors.New("user_not_found")
	ErrDirectoryTLS         = errors.New("directory_tls_error")
	ErrDirectoryUnavailable = errors.New("directory_unavailable")
)

type Client interface {
	TestConnection(ctx context.Context, request TestConnectionRequest) (TestConnectionResult, error)
}

type TestConnectionRequest struct {
	Username      string
	Password      string
	TestPassword  bool
	AllowInsecure bool
}

type TestConnectionResult struct {
	TLSVerified  bool
	ServiceBound bool
	UserResolved bool
	PasswordOK   bool
	Subject      Subject
}

type Subject struct {
	DirectoryID string
	Username    string
}
