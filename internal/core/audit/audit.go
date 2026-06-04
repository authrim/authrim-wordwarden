package audit

import (
	"context"
	"time"
)

const (
	EventVerifySuccess  = "directory_password.verify.success"
	EventVerifyFailure  = "directory_password.verify.failure"
	EventVerifyError    = "directory_password.verify.error"
	EventHMACFailure    = "directory_password.hmac.failure"
	EventReplayDetected = "directory_password.replay.detected"
	EventConfigError    = "directory_password.config.error"
)

type Event struct {
	EventID         string    `json:"event_id"`
	EventType       string    `json:"event_type"`
	Timestamp       time.Time `json:"timestamp"`
	TenantID        string    `json:"tenant_id,omitempty"`
	ConnectorID     string    `json:"connector_id,omitempty"`
	RequestID       string    `json:"request_id,omitempty"`
	KeyID           string    `json:"key_id,omitempty"`
	Result          string    `json:"result,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	ErrorCode       string    `json:"error_code,omitempty"`
	Retryable       bool      `json:"retryable"`
	LatencyMS       int64     `json:"latency_ms"`
	DirectoryStatus string    `json:"directory_status,omitempty"`
	UsernameHash    string    `json:"username_hash,omitempty"`
}

type Sink interface {
	WriteEvent(ctx context.Context, event Event) error
}

type DiscardSink struct{}

func (DiscardSink) WriteEvent(context.Context, Event) error {
	return nil
}
