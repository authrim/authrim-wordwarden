package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	hmacadapter "github.com/authrim/authrim-wordwarden/internal/adapters/hmac"
	"github.com/authrim/authrim-wordwarden/internal/core/audit"
	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"github.com/google/uuid"
)

type TenantRuntime struct {
	TenantID         string
	ConnectorID      string
	HMACVerifier     hmacadapter.Verifier
	Directory        directory.Client
	AuditHashSecret  []byte
	ConcurrencyLimit int
}

type HandlerOptions struct {
	Tenants map[string]TenantRuntime
	Audit   audit.Sink
}

type healthResponse struct {
	OK        bool   `json:"ok"`
	Connector string `json:"connector"`
	Version   string `json:"version"`
}

type handler struct {
	version string
	tenants map[string]TenantRuntime
	replay  *replayCache
	audit   audit.Sink
	limits  map[string]chan struct{}
}

func NewHandler(version string, options ...HandlerOptions) http.Handler {
	h := &handler{
		version: version,
		tenants: map[string]TenantRuntime{},
		replay:  newReplayCache(5 * time.Minute),
		audit:   audit.DiscardSink{},
		limits:  map[string]chan struct{}{},
	}
	if len(options) > 0 && options[0].Tenants != nil {
		h.tenants = options[0].Tenants
	}
	if len(options) > 0 && options[0].Audit != nil {
		h.audit = options[0].Audit
	}
	for connectorID, runtime := range h.tenants {
		limit := runtime.ConcurrencyLimit
		if limit <= 0 {
			limit = 8
		}
		h.limits[connectorID] = make(chan struct{}, limit)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			OK:        true,
			Connector: "authrim-wordwarden",
			Version:   version,
		})
	})
	mux.HandleFunc("POST /v1/auth/verify-password", h.verifyPassword)
	return mux
}

type verifyPasswordRequest struct {
	RequestID      string   `json:"request_id"`
	TenantID       string   `json:"tenant_id"`
	ConnectorID    string   `json:"connector_id"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	AttributeNames []string `json:"attribute_names"`
}

type verifyPasswordResponse struct {
	RequestID       string              `json:"request_id"`
	TenantID        string              `json:"tenant_id"`
	ConnectorID     string              `json:"connector_id"`
	Result          string              `json:"result"`
	Reason          string              `json:"reason,omitempty"`
	Subject         *subjectResponse    `json:"subject,omitempty"`
	Attributes      map[string][]string `json:"attributes,omitempty"`
	DirectoryStatus string              `json:"directory_status"`
}

type subjectResponse struct {
	DirectoryID string `json:"directory_id"`
	Username    string `json:"username"`
}

type errorResponse struct {
	RequestID   string       `json:"request_id,omitempty"`
	TenantID    string       `json:"tenant_id,omitempty"`
	ConnectorID string       `json:"connector_id,omitempty"`
	Error       errorPayload `json:"error"`
}

type errorPayload struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

func (h *handler) verifyPassword(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	connectorID := req.Header.Get(hmacadapter.HeaderConnectorID)
	runtime, ok := h.tenants[connectorID]
	if !ok {
		h.emit(req, audit.Event{
			EventType:   audit.EventVerifyError,
			ConnectorID: connectorID,
			Result:      "error",
			ErrorCode:   "unknown_connector",
			Retryable:   false,
			LatencyMS:   latencyMS(start),
		})
		writeError(w, http.StatusForbidden, errorResponse{
			ConnectorID: connectorID,
			Error:       errorPayload{Code: "unknown_connector", Retryable: false},
		})
		return
	}

	verification, body, err := runtime.HMACVerifier.Verify(req)
	if err != nil {
		h.emit(req, audit.Event{
			EventType:   audit.EventHMACFailure,
			TenantID:    runtime.TenantID,
			ConnectorID: runtime.ConnectorID,
			Result:      "error",
			ErrorCode:   hmacErrorCode(err),
			Retryable:   false,
			LatencyMS:   latencyMS(start),
		})
		writeError(w, http.StatusUnauthorized, errorResponse{
			ConnectorID: connectorID,
			Error:       errorPayload{Code: hmacErrorCode(err), Retryable: false},
		})
		return
	}
	if !h.replay.Remember(verification.RequestID + ":" + verification.Nonce) {
		h.emit(req, audit.Event{
			EventType:   audit.EventReplayDetected,
			TenantID:    runtime.TenantID,
			ConnectorID: runtime.ConnectorID,
			RequestID:   verification.RequestID,
			KeyID:       verification.KeyID,
			Result:      "error",
			ErrorCode:   "replay_detected",
			Retryable:   false,
			LatencyMS:   latencyMS(start),
		})
		writeError(w, http.StatusConflict, errorResponse{
			RequestID:   verification.RequestID,
			ConnectorID: connectorID,
			Error:       errorPayload{Code: "replay_detected", Retryable: false},
		})
		return
	}

	release, ok := h.acquire(connectorID)
	if !ok {
		h.emit(req, audit.Event{
			EventType:   audit.EventVerifyError,
			TenantID:    runtime.TenantID,
			ConnectorID: runtime.ConnectorID,
			RequestID:   verification.RequestID,
			KeyID:       verification.KeyID,
			Result:      "error",
			ErrorCode:   "connector_rate_limited",
			Retryable:   true,
			LatencyMS:   latencyMS(start),
		})
		writeError(w, http.StatusTooManyRequests, errorResponse{
			RequestID:   verification.RequestID,
			ConnectorID: connectorID,
			Error:       errorPayload{Code: "connector_rate_limited", Retryable: true},
		})
		return
	}
	defer release()

	var requestBody verifyPasswordRequest
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&requestBody); err != nil {
		h.emit(req, audit.Event{
			EventType:   audit.EventVerifyError,
			TenantID:    runtime.TenantID,
			ConnectorID: runtime.ConnectorID,
			RequestID:   verification.RequestID,
			KeyID:       verification.KeyID,
			Result:      "error",
			ErrorCode:   "malformed_request",
			Retryable:   false,
			LatencyMS:   latencyMS(start),
		})
		writeError(w, http.StatusBadRequest, errorResponse{
			RequestID:   verification.RequestID,
			ConnectorID: connectorID,
			Error:       errorPayload{Code: "malformed_request", Retryable: false},
		})
		return
	}

	if requestBody.TenantID != runtime.TenantID || requestBody.ConnectorID != runtime.ConnectorID ||
		requestBody.RequestID != verification.RequestID || verification.ConnectorID != runtime.ConnectorID {
		h.emit(req, audit.Event{
			EventType:    audit.EventVerifyError,
			TenantID:     requestBody.TenantID,
			ConnectorID:  requestBody.ConnectorID,
			RequestID:    verification.RequestID,
			KeyID:        verification.KeyID,
			Result:       "error",
			ErrorCode:    "tenant_connector_mismatch",
			Retryable:    false,
			LatencyMS:    latencyMS(start),
			UsernameHash: usernameHash(runtime.AuditHashSecret, requestBody.Username),
		})
		writeError(w, http.StatusForbidden, errorResponse{
			RequestID:   verification.RequestID,
			TenantID:    requestBody.TenantID,
			ConnectorID: connectorID,
			Error:       errorPayload{Code: "tenant_connector_mismatch", Retryable: false},
		})
		return
	}

	result, err := runtime.Directory.VerifyPassword(req.Context(), directory.VerifyPasswordRequest{
		Username:       requestBody.Username,
		Password:       requestBody.Password,
		AttributeNames: requestBody.AttributeNames,
	})
	if err != nil {
		code := directoryErrorCode(err)
		h.emit(req, audit.Event{
			EventType:    audit.EventVerifyError,
			TenantID:     requestBody.TenantID,
			ConnectorID:  requestBody.ConnectorID,
			RequestID:    requestBody.RequestID,
			KeyID:        verification.KeyID,
			Result:       "error",
			ErrorCode:    code,
			Retryable:    true,
			LatencyMS:    latencyMS(start),
			UsernameHash: usernameHash(runtime.AuditHashSecret, requestBody.Username),
		})
		writeError(w, http.StatusServiceUnavailable, errorResponse{
			RequestID:   requestBody.RequestID,
			TenantID:    requestBody.TenantID,
			ConnectorID: requestBody.ConnectorID,
			Error:       errorPayload{Code: directoryErrorCode(err), Retryable: true},
		})
		return
	}

	if !result.Success {
		h.emit(req, audit.Event{
			EventType:       audit.EventVerifyFailure,
			TenantID:        requestBody.TenantID,
			ConnectorID:     requestBody.ConnectorID,
			RequestID:       requestBody.RequestID,
			KeyID:           verification.KeyID,
			Result:          "failure",
			Reason:          "invalid_credentials",
			Retryable:       false,
			LatencyMS:       latencyMS(start),
			DirectoryStatus: "ok",
			UsernameHash:    usernameHash(runtime.AuditHashSecret, requestBody.Username),
		})
		writeJSON(w, http.StatusOK, verifyPasswordResponse{
			RequestID:       requestBody.RequestID,
			TenantID:        requestBody.TenantID,
			ConnectorID:     requestBody.ConnectorID,
			Result:          "failure",
			Reason:          "invalid_credentials",
			DirectoryStatus: "ok",
		})
		return
	}

	h.emit(req, audit.Event{
		EventType:       audit.EventVerifySuccess,
		TenantID:        requestBody.TenantID,
		ConnectorID:     requestBody.ConnectorID,
		RequestID:       requestBody.RequestID,
		KeyID:           verification.KeyID,
		Result:          "success",
		Retryable:       false,
		LatencyMS:       latencyMS(start),
		DirectoryStatus: "ok",
		UsernameHash:    usernameHash(runtime.AuditHashSecret, requestBody.Username),
	})
	writeJSON(w, http.StatusOK, verifyPasswordResponse{
		RequestID:   requestBody.RequestID,
		TenantID:    requestBody.TenantID,
		ConnectorID: requestBody.ConnectorID,
		Result:      "success",
		Subject: &subjectResponse{
			DirectoryID: result.Subject.DirectoryID,
			Username:    result.Subject.Username,
		},
		Attributes:      result.Attributes,
		DirectoryStatus: "ok",
	})
}

func (h *handler) emit(req *http.Request, event audit.Event) {
	event.EventID = uuid.NewString()
	event.Timestamp = time.Now().UTC()
	_ = h.audit.WriteEvent(req.Context(), event)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, value errorResponse) {
	writeJSON(w, status, value)
}

func hmacErrorCode(err error) string {
	switch {
	case errors.Is(err, hmacadapter.ErrMissingHeader):
		return "missing_hmac_header"
	case errors.Is(err, hmacadapter.ErrInvalidTimestamp):
		return "invalid_hmac_timestamp"
	case errors.Is(err, hmacadapter.ErrStaleTimestamp):
		return "stale_hmac_timestamp"
	case errors.Is(err, hmacadapter.ErrUnknownKey):
		return "unknown_hmac_key"
	case errors.Is(err, hmacadapter.ErrInvalidSignature):
		return "invalid_hmac_signature"
	default:
		return "hmac_verification_failed"
	}
}

func directoryErrorCode(err error) string {
	switch {
	case errors.Is(err, directory.ErrDirectoryTLS):
		return "directory_tls_error"
	case errors.Is(err, directory.ErrDirectoryUnavailable):
		return "directory_unavailable"
	default:
		return "directory_error"
	}
}

func latencyMS(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func usernameHash(secret []byte, username string) string {
	if username == "" || len(secret) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(username))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func (h *handler) acquire(connectorID string) (func(), bool) {
	limit, ok := h.limits[connectorID]
	if !ok {
		return func() {}, true
	}
	select {
	case limit <- struct{}{}:
		return func() { <-limit }, true
	default:
		return nil, false
	}
}

type replayCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]time.Time
}

func newReplayCache(ttl time.Duration) *replayCache {
	return &replayCache{ttl: ttl, entries: map[string]time.Time{}}
}

func (c *replayCache) Remember(key string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for entry, expiresAt := range c.entries {
		if now.After(expiresAt) {
			delete(c.entries, entry)
		}
	}

	if _, ok := c.entries[key]; ok {
		return false
	}
	c.entries[key] = now.Add(c.ttl)
	return true
}
