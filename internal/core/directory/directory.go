package directory

import (
	"context"
	"errors"
)

var (
	ErrInvalidCredentials   = errors.New("invalid_credentials")
	ErrUserNotFound         = errors.New("user_not_found")
	ErrAmbiguousUser        = errors.New("ambiguous_user")
	ErrDirectoryTLS         = errors.New("directory_tls_error")
	ErrDirectoryUnavailable = errors.New("directory_unavailable")
	ErrDirectoryReferral    = errors.New("directory_referral")
	ErrAccountDisabled      = errors.New("account_disabled")
	ErrAccountLocked        = errors.New("account_locked")
	ErrPasswordExpired      = errors.New("password_expired")
	ErrMustChangePassword   = errors.New("must_change_password")
)

type Client interface {
	TestConnection(ctx context.Context, request TestConnectionRequest) (TestConnectionResult, error)
	VerifyPassword(ctx context.Context, request VerifyPasswordRequest) (VerifyPasswordResult, error)
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

type VerifyPasswordRequest struct {
	Username       string
	Password       string
	AttributeNames []string
}

type CredentialResult string

const (
	CredentialResultSuccess           CredentialResult = "success"
	CredentialResultFailure           CredentialResult = "failure"
	CredentialResultPolicyRequired    CredentialResult = "policy_required"
	CredentialResultSourceUnavailable CredentialResult = "source_unavailable"
)

const (
	ReasonInvalidCredentials   = "invalid_credentials"
	ReasonAccountDisabled      = "account_disabled"
	ReasonAccountLocked        = "account_locked"
	ReasonPasswordExpired      = "password_expired"
	ReasonMustChangePassword   = "must_change_password"
	ReasonDirectoryUnavailable = "directory_unavailable"
)

type VerifyPasswordResult struct {
	Result     CredentialResult
	Success    bool
	Reason     string
	Subject    Subject
	Attributes map[string][]string
}

func SuccessfulVerification(subject Subject, attributes map[string][]string) VerifyPasswordResult {
	return VerifyPasswordResult{
		Result:     CredentialResultSuccess,
		Success:    true,
		Subject:    subject,
		Attributes: attributes,
	}
}

func FailedVerification(reason string) VerifyPasswordResult {
	if reason == "" {
		reason = ReasonInvalidCredentials
	}
	return VerifyPasswordResult{
		Result:  CredentialResultFailure,
		Success: false,
		Reason:  reason,
	}
}

func PolicyRequiredVerification(reason string) VerifyPasswordResult {
	return VerifyPasswordResult{
		Result:  CredentialResultPolicyRequired,
		Success: false,
		Reason:  reason,
	}
}

func SourceUnavailableVerification(reason string) VerifyPasswordResult {
	if reason == "" {
		reason = ReasonDirectoryUnavailable
	}
	return VerifyPasswordResult{
		Result:  CredentialResultSourceUnavailable,
		Success: false,
		Reason:  reason,
	}
}

func (r VerifyPasswordResult) CredentialResult() CredentialResult {
	if r.Result != "" {
		return r.Result
	}
	if r.Success {
		return CredentialResultSuccess
	}
	return CredentialResultFailure
}

func (r VerifyPasswordResult) IsSuccess() bool {
	return r.CredentialResult() == CredentialResultSuccess
}

func (r VerifyPasswordResult) SafeReason() string {
	if r.Reason != "" {
		return r.Reason
	}
	if r.CredentialResult() == CredentialResultFailure {
		return ReasonInvalidCredentials
	}
	if r.CredentialResult() == CredentialResultSourceUnavailable {
		return ReasonDirectoryUnavailable
	}
	return string(r.CredentialResult())
}
