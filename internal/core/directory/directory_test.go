package directory

import "testing"

func TestCredentialResultCompatibility(t *testing.T) {
	legacySuccess := VerifyPasswordResult{Success: true}
	if !legacySuccess.IsSuccess() {
		t.Fatal("legacy success result should remain successful")
	}
	if legacySuccess.CredentialResult() != CredentialResultSuccess {
		t.Fatalf("CredentialResult = %q", legacySuccess.CredentialResult())
	}

	legacyFailure := VerifyPasswordResult{Success: false}
	if legacyFailure.IsSuccess() {
		t.Fatal("legacy failure result should not be successful")
	}
	if legacyFailure.SafeReason() != ReasonInvalidCredentials {
		t.Fatalf("SafeReason = %q", legacyFailure.SafeReason())
	}
}

func TestPolicyRequiredVerificationIsNotSuccess(t *testing.T) {
	result := PolicyRequiredVerification(ReasonMustChangePassword)

	if result.IsSuccess() {
		t.Fatal("policy_required must not be success")
	}
	if result.CredentialResult() != CredentialResultPolicyRequired {
		t.Fatalf("CredentialResult = %q", result.CredentialResult())
	}
	if result.SafeReason() != ReasonMustChangePassword {
		t.Fatalf("SafeReason = %q", result.SafeReason())
	}
}

func TestSourceUnavailableVerificationIsNotSuccess(t *testing.T) {
	result := SourceUnavailableVerification("")

	if result.IsSuccess() {
		t.Fatal("source_unavailable must not be success")
	}
	if result.CredentialResult() != CredentialResultSourceUnavailable {
		t.Fatalf("CredentialResult = %q", result.CredentialResult())
	}
	if result.SafeReason() != ReasonDirectoryUnavailable {
		t.Fatalf("SafeReason = %q", result.SafeReason())
	}
}
