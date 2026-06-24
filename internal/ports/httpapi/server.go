package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
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
	Tenants          map[string]TenantRuntime
	Audit            audit.Sink
	ExposeOperations bool
}

type healthResponse struct {
	OK        bool   `json:"ok"`
	Connector string `json:"connector"`
	Version   string `json:"version"`
}

type versionResponse struct {
	Connector string `json:"connector"`
	Version   string `json:"version"`
}

type healthDetailResponse struct {
	OK        bool                 `json:"ok"`
	Connector string               `json:"connector"`
	Version   string               `json:"version"`
	Tenants   []healthDetailTenant `json:"tenants"`
}

type healthDetailTenant struct {
	TenantID         string `json:"tenant_id"`
	ConnectorID      string `json:"connector_id"`
	ConcurrencyLimit int    `json:"concurrency_limit"`
	RequestTimeoutMS int    `json:"request_timeout_ms"`
}

type handler struct {
	version          string
	tenants          map[string]TenantRuntime
	replay           *replayCache
	audit            audit.Sink
	limits           map[string]chan struct{}
	storms           map[string]*connectorStorms
	metrics          *metricsStore
	exposeOperations bool
}

func NewHandler(version string, options ...HandlerOptions) http.Handler {
	h := &handler{
		version: version,
		tenants: map[string]TenantRuntime{},
		replay:  newReplayCache(5 * time.Minute),
		audit:   audit.DiscardSink{},
		limits:  map[string]chan struct{}{},
		storms:  map[string]*connectorStorms{},
		metrics: newMetricsStore(),
	}
	if len(options) > 0 && options[0].Tenants != nil {
		h.tenants = options[0].Tenants
	}
	if len(options) > 0 && options[0].Audit != nil {
		h.audit = options[0].Audit
	}
	if len(options) > 0 {
		h.exposeOperations = options[0].ExposeOperations
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
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, versionResponse{
			Connector: "authrim-wordwarden",
			Version:   version,
		})
	})
	mux.HandleFunc("GET /healthz/details", h.healthDetails)
	mux.HandleFunc("GET /metrics", h.metricsEndpoint)
	mux.HandleFunc("POST /v1/auth/verify-password", h.verifyPassword)
	return mux
}

func (h *handler) healthDetails(w http.ResponseWriter, req *http.Request) {
	if !h.operationsAllowed(req) {
		http.NotFound(w, req)
		return
	}
	connectors := make([]string, 0, len(h.tenants))
	for connectorID := range h.tenants {
		connectors = append(connectors, connectorID)
	}
	sort.Strings(connectors)

	tenants := make([]healthDetailTenant, 0, len(connectors))
	for _, connectorID := range connectors {
		runtime := h.tenants[connectorID]
		concurrencyLimit := runtime.ConcurrencyLimit
		if concurrencyLimit <= 0 {
			concurrencyLimit = 8
		}
		requestTimeoutMS := runtime.RequestTimeoutMS
		if requestTimeoutMS <= 0 {
			requestTimeoutMS = 2500
		}
		tenants = append(tenants, healthDetailTenant{
			TenantID:         runtime.TenantID,
			ConnectorID:      runtime.ConnectorID,
			ConcurrencyLimit: concurrencyLimit,
			RequestTimeoutMS: requestTimeoutMS,
		})
	}

	writeJSON(w, http.StatusOK, healthDetailResponse{
		OK:        true,
		Connector: "authrim-wordwarden",
		Version:   h.version,
		Tenants:   tenants,
	})
}

func (h *handler) metricsEndpoint(w http.ResponseWriter, req *http.Request) {
	if !h.operationsAllowed(req) {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(h.metrics.prometheus()))
}

func (h *handler) operationsAllowed(req *http.Request) bool {
	if h.exposeOperations {
		return true
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	GroupFacts      []groupFactResponse `json:"group_facts,omitempty"`
	DirectoryStatus string              `json:"directory_status"`
}

type subjectResponse struct {
	DirectoryID string `json:"directory_id"`
	Username    string `json:"username"`
}

type groupFactResponse struct {
	ID      string `json:"id"`
	DN      string `json:"dn"`
	Display string `json:"display"`
	Source  string `json:"source"`
	Depth   int    `json:"depth"`
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
	if !h.replay.Remember(replayKey(runtime.ConnectorID, verification.KeyID, verification.RequestID, verification.Nonce)) {
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

	credentialResult := result.CredentialResult()
	if credentialResult == directory.CredentialResultSourceUnavailable {
		code := result.SafeReason()
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
			Error:       errorPayload{Code: code, Retryable: true},
		})
		h.recordStorm(connectorID, stormKindDirectoryError)
		return
	}
	h.resetStorm(connectorID, stormKindDirectoryError)
	if credentialResult != directory.CredentialResultSuccess {
		reason := result.SafeReason()
		h.emit(req, audit.Event{
			EventType:       audit.EventVerifyFailure,
			TenantID:        requestBody.TenantID,
			ConnectorID:     requestBody.ConnectorID,
			RequestID:       requestBody.RequestID,
			KeyID:           verification.KeyID,
			Result:          string(credentialResult),
			Reason:          reason,
			Retryable:       false,
			LatencyMS:       latencyMS(start),
			DirectoryStatus: "ok",
			UsernameHash:    usernameHash(runtime.AuditHashSecret, requestBody.Username),
		})
		writeJSON(w, http.StatusOK, verifyPasswordResponse{
			RequestID:       requestBody.RequestID,
			TenantID:        requestBody.TenantID,
			ConnectorID:     requestBody.ConnectorID,
			Result:          string(credentialResult),
			Reason:          reason,
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
		GroupFacts:      groupFactResponses(result.GroupFacts),
		DirectoryStatus: "ok",
	})
}

func groupFactResponses(facts []directory.GroupFact) []groupFactResponse {
	if len(facts) == 0 {
		return nil
	}
	result := make([]groupFactResponse, 0, len(facts))
	for _, fact := range facts {
		result = append(result, groupFactResponse{
			ID:      fact.ID,
			DN:      fact.DN,
			Display: fact.Display,
			Source:  fact.Source,
			Depth:   fact.Depth,
		})
	}
	return result
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
	h.metrics.record(event)
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
	case errors.Is(err, directory.ErrDirectoryReferral):
		return "directory_referral"
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

func replayKey(connectorID string, keyID string, requestID string, nonce string) string {
	return connectorID + ":" + keyID + ":" + requestID + ":" + nonce
}

type metricsStore struct {
	mu       sync.Mutex
	counters map[metricKey]uint64
}

type metricKey struct {
	EventType   string
	TenantID    string
	ConnectorID string
	Result      string
	ErrorCode   string
}

func newMetricsStore() *metricsStore {
	return &metricsStore{counters: map[metricKey]uint64{}}
}

func (m *metricsStore) record(event audit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[metricKey{
		EventType:   event.EventType,
		TenantID:    event.TenantID,
		ConnectorID: event.ConnectorID,
		Result:      event.Result,
		ErrorCode:   event.ErrorCode,
	}]++
}

func (m *metricsStore) prometheus() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]metricKey, 0, len(m.counters))
	for key := range m.counters {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return metricSortKey(keys[i]) < metricSortKey(keys[j])
	})

	out := "# HELP wordwarden_events_total Wordwarden audit-classified events.\n" +
		"# TYPE wordwarden_events_total counter\n"
	for _, key := range keys {
		out += fmt.Sprintf(
			"wordwarden_events_total{event_type=%q,tenant_id=%q,connector_id=%q,result=%q,error_code=%q} %d\n",
			key.EventType,
			key.TenantID,
			key.ConnectorID,
			key.Result,
			key.ErrorCode,
			m.counters[key],
		)
	}
	return out
}

func metricSortKey(key metricKey) string {
	return key.EventType + "\x00" + key.TenantID + "\x00" + key.ConnectorID + "\x00" + key.Result + "\x00" + key.ErrorCode
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
