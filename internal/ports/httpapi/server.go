package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
	RequestTimeoutMS int
	StormProtection  StormProtectionPolicy
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
	storms  map[string]*connectorStorms
}

func NewHandler(version string, options ...HandlerOptions) http.Handler {
	h := &handler{
		version: version,
		tenants: map[string]TenantRuntime{},
		replay:  newReplayCache(5 * time.Minute),
		audit:   audit.DiscardSink{},
		limits:  map[string]chan struct{}{},
		storms:  map[string]*connectorStorms{},
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
		h.storms[connectorID] = newConnectorStorms(runtime.StormProtection)
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

const maxVerifyPasswordBodyBytes = 64 * 1024

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

	if h.stormBlocked(connectorID, stormKindHMACFailure) {
		h.emit(req, audit.Event{
			EventType:   audit.EventVerifyError,
			TenantID:    runtime.TenantID,
			ConnectorID: runtime.ConnectorID,
			Result:      "error",
			ErrorCode:   "hmac_failure_storm_limited",
			Retryable:   true,
			LatencyMS:   latencyMS(start),
		})
		writeStormError(w, connectorID, "hmac_failure_storm_limited")
		return
	}

	req.Body = http.MaxBytesReader(w, req.Body, maxVerifyPasswordBodyBytes)
	verification, body, err := runtime.HMACVerifier.Verify(req)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			h.emit(req, audit.Event{
				EventType:   audit.EventVerifyError,
				TenantID:    runtime.TenantID,
				ConnectorID: runtime.ConnectorID,
				Result:      "error",
				ErrorCode:   "payload_too_large",
				Retryable:   false,
				LatencyMS:   latencyMS(start),
			})
			writeError(w, http.StatusRequestEntityTooLarge, errorResponse{
				ConnectorID: connectorID,
				Error:       errorPayload{Code: "payload_too_large", Retryable: false},
			})
			return
		}
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
		h.recordStorm(connectorID, stormKindHMACFailure)
		return
	}
	if h.stormBlocked(connectorID, stormKindReplay) {
		h.emit(req, audit.Event{
			EventType:   audit.EventVerifyError,
			TenantID:    runtime.TenantID,
			ConnectorID: runtime.ConnectorID,
			RequestID:   verification.RequestID,
			KeyID:       verification.KeyID,
			Result:      "error",
			ErrorCode:   "replay_storm_limited",
			Retryable:   true,
			LatencyMS:   latencyMS(start),
		})
		writeStormErrorWithRequest(w, verification.RequestID, connectorID, "replay_storm_limited")
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
		h.recordStorm(connectorID, stormKindReplay)
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

	if h.stormBlocked(connectorID, stormKindMalformed) {
		h.emit(req, audit.Event{
			EventType:   audit.EventVerifyError,
			TenantID:    runtime.TenantID,
			ConnectorID: runtime.ConnectorID,
			RequestID:   verification.RequestID,
			KeyID:       verification.KeyID,
			Result:      "error",
			ErrorCode:   "malformed_request_storm_limited",
			Retryable:   true,
			LatencyMS:   latencyMS(start),
		})
		writeStormErrorWithRequest(w, verification.RequestID, connectorID, "malformed_request_storm_limited")
		return
	}

	var requestBody verifyPasswordRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&requestBody); err != nil {
		h.writeMalformedRequest(w, req, runtime, verification, connectorID, start)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		h.writeMalformedRequest(w, req, runtime, verification, connectorID, start)
		return
	}
	if !validVerifyPasswordRequest(requestBody) {
		h.writeMalformedRequest(w, req, runtime, verification, connectorID, start)
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

	if h.stormBlocked(connectorID, stormKindDirectoryError) {
		h.emit(req, audit.Event{
			EventType:    audit.EventVerifyError,
			TenantID:     requestBody.TenantID,
			ConnectorID:  requestBody.ConnectorID,
			RequestID:    requestBody.RequestID,
			KeyID:        verification.KeyID,
			Result:       "error",
			ErrorCode:    "directory_error_storm_limited",
			Retryable:    true,
			LatencyMS:    latencyMS(start),
			UsernameHash: usernameHash(runtime.AuditHashSecret, requestBody.Username),
		})
		writeError(w, http.StatusServiceUnavailable, errorResponse{
			RequestID:   requestBody.RequestID,
			TenantID:    requestBody.TenantID,
			ConnectorID: requestBody.ConnectorID,
			Error:       errorPayload{Code: "directory_error_storm_limited", Retryable: true},
		})
		return
	}

	directoryCtx, cancel := context.WithTimeout(req.Context(), durationFromMS(runtime.RequestTimeoutMS, 2500*time.Millisecond))
	defer cancel()
	result, err := runtime.Directory.VerifyPassword(directoryCtx, directory.VerifyPasswordRequest{
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
		h.recordStorm(connectorID, stormKindDirectoryError)
		return
	}
	h.resetStorm(connectorID, stormKindDirectoryError)

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

func (h *handler) writeMalformedRequest(
	w http.ResponseWriter,
	req *http.Request,
	runtime TenantRuntime,
	verification hmacadapter.VerificationResult,
	connectorID string,
	start time.Time,
) {
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
	h.recordStorm(connectorID, stormKindMalformed)
}

func validVerifyPasswordRequest(request verifyPasswordRequest) bool {
	return request.RequestID != "" &&
		request.TenantID != "" &&
		request.ConnectorID != "" &&
		request.Username != "" &&
		request.Password != ""
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

func writeStormError(w http.ResponseWriter, connectorID string, code string) {
	writeError(w, http.StatusTooManyRequests, errorResponse{
		ConnectorID: connectorID,
		Error:       errorPayload{Code: code, Retryable: true},
	})
}

func writeStormErrorWithRequest(w http.ResponseWriter, requestID string, connectorID string, code string) {
	writeError(w, http.StatusTooManyRequests, errorResponse{
		RequestID:   requestID,
		ConnectorID: connectorID,
		Error:       errorPayload{Code: code, Retryable: true},
	})
}

func hmacErrorCode(err error) string {
	switch {
	case errors.Is(err, hmacadapter.ErrMissingHeader):
		return "missing_hmac_header"
	case errors.Is(err, hmacadapter.ErrUnsignedHeader):
		return "unsigned_required_hmac_header"
	case errors.Is(err, hmacadapter.ErrInvalidTimestamp):
		return "invalid_hmac_timestamp"
	case errors.Is(err, hmacadapter.ErrStaleTimestamp):
		return "stale_hmac_timestamp"
	case errors.Is(err, hmacadapter.ErrUnknownKey):
		return "unknown_hmac_key"
	case errors.Is(err, hmacadapter.ErrInvalidSignature):
		return "invalid_hmac_signature"
	case errors.Is(err, hmacadapter.ErrMalformedSignedField):
		return "malformed_signed_header"
	default:
		return "hmac_verification_failed"
	}
}

func durationFromMS(value int, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
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

func (h *handler) stormBlocked(connectorID string, kind stormKind) bool {
	storms, ok := h.storms[connectorID]
	return ok && storms.blocked(kind)
}

func (h *handler) recordStorm(connectorID string, kind stormKind) {
	if storms, ok := h.storms[connectorID]; ok {
		storms.record(kind)
	}
}

func (h *handler) resetStorm(connectorID string, kind stormKind) {
	if storms, ok := h.storms[connectorID]; ok {
		storms.reset(kind)
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
