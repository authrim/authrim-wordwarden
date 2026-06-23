package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/authrim/authrim-wordwarden/internal/core/directory"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const (
	Protocol             = "authrim.wordwarden.relay.v1"
	ProtocolVersion      = 1
	MinSupportedVersion  = 1
	Algorithm            = "AUTHRIM-WORDWARDEN-RELAY-HMAC-SHA256"
	maxRelayMessageBytes = 64 * 1024
)

type Config struct {
	URL            string
	TenantID       string
	ConnectorID    string
	KeyID          string
	Secret         []byte
	Directory      directory.Client
	RequestTimeout time.Duration
	Concurrency    int
	ReconnectMin   time.Duration
	ReconnectMax   time.Duration
	Logger         *slog.Logger
}

type Client struct {
	config  Config
	limit   chan struct{}
	logger  *slog.Logger
	writeMu sync.Mutex
}

type challengeMessage struct {
	Type                string `json:"type"`
	Protocol            string `json:"protocol"`
	ProtocolVersion     int    `json:"protocol_version"`
	MinSupportedVersion int    `json:"min_supported_version"`
	ChallengeID         string `json:"challenge_id"`
	Nonce               string `json:"nonce"`
	IssuedAt            string `json:"issued_at"`
	ExpiresAt           string `json:"expires_at"`
}

type authResponseMessage struct {
	Type                string `json:"type"`
	Protocol            string `json:"protocol"`
	ProtocolVersion     int    `json:"protocol_version"`
	MinSupportedVersion int    `json:"min_supported_version"`
	TenantID            string `json:"tenant_id"`
	ConnectorID         string `json:"connector_id"`
	KeyID               string `json:"key_id"`
	ChallengeID         string `json:"challenge_id"`
	Nonce               string `json:"nonce"`
	Timestamp           string `json:"timestamp"`
	Signature           string `json:"signature"`
}

type envelope struct {
	Type                string `json:"type"`
	Protocol            string `json:"protocol"`
	ProtocolVersion     int    `json:"protocol_version"`
	MinSupportedVersion int    `json:"min_supported_version"`
}

type verifyRequestMessage struct {
	Type                string   `json:"type"`
	Protocol            string   `json:"protocol"`
	ProtocolVersion     int      `json:"protocol_version"`
	MinSupportedVersion int      `json:"min_supported_version"`
	ID                  string   `json:"id"`
	RequestID           string   `json:"request_id"`
	TenantID            string   `json:"tenant_id"`
	ConnectorID         string   `json:"connector_id"`
	Username            string   `json:"username"`
	Password            string   `json:"password"`
	AttributeNames      []string `json:"attribute_names"`
}

type verifyResponseMessage struct {
	Type                string              `json:"type"`
	Protocol            string              `json:"protocol"`
	ProtocolVersion     int                 `json:"protocol_version"`
	MinSupportedVersion int                 `json:"min_supported_version"`
	ID                  string              `json:"id"`
	RequestID           string              `json:"request_id"`
	TenantID            string              `json:"tenant_id"`
	ConnectorID         string              `json:"connector_id"`
	Result              string              `json:"result"`
	Reason              string              `json:"reason,omitempty"`
	Subject             *subjectMessage     `json:"subject,omitempty"`
	Attributes          map[string][]string `json:"attributes,omitempty"`
	DirectoryStatus     string              `json:"directory_status"`
}

type verifyErrorMessage struct {
	Type                string       `json:"type"`
	Protocol            string       `json:"protocol"`
	ProtocolVersion     int          `json:"protocol_version"`
	MinSupportedVersion int          `json:"min_supported_version"`
	ID                  string       `json:"id"`
	RequestID           string       `json:"request_id,omitempty"`
	TenantID            string       `json:"tenant_id,omitempty"`
	ConnectorID         string       `json:"connector_id,omitempty"`
	Error               errorPayload `json:"error"`
}

type subjectMessage struct {
	DirectoryID string `json:"directory_id"`
	Username    string `json:"username"`
}

type errorPayload struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

func NewClient(config Config) (*Client, error) {
	if config.URL == "" {
		return nil, errors.New("relay URL is required")
	}
	if _, err := parseRelayURL(config.URL); err != nil {
		return nil, err
	}
	if config.TenantID == "" {
		return nil, errors.New("relay tenant id is required")
	}
	if config.ConnectorID == "" {
		return nil, errors.New("relay connector id is required")
	}
	if err := validateRelayURLBinding(config.URL, config.TenantID, config.ConnectorID); err != nil {
		return nil, err
	}
	if config.KeyID == "" {
		return nil, errors.New("relay key id is required")
	}
	if len(config.Secret) == 0 {
		return nil, errors.New("relay secret is required")
	}
	if config.Directory == nil {
		return nil, errors.New("relay directory client is required")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 2500 * time.Millisecond
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 8
	}
	if config.ReconnectMin <= 0 {
		config.ReconnectMin = time.Second
	}
	if config.ReconnectMax <= 0 {
		config.ReconnectMax = 30 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Client{
		config: config,
		limit:  make(chan struct{}, config.Concurrency),
		logger: config.Logger,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	backoff := c.config.ReconnectMin
	for {
		if err := c.runOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.logger.Warn("relay connection ended", "tenant_id", c.config.TenantID, "connector_id", c.config.ConnectorID, "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > c.config.ReconnectMax {
			backoff = c.config.ReconnectMax
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	relayURL, err := parseRelayURL(c.config.URL)
	if err != nil {
		return err
	}
	conn, _, err := websocket.Dial(ctx, relayURL.String(), nil)
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "relay client stopped")
	conn.SetReadLimit(maxRelayMessageBytes)

	if err := c.authenticate(ctx, conn); err != nil {
		return err
	}
	c.logger.Info("relay connected", "tenant_id", c.config.TenantID, "connector_id", c.config.ConnectorID)

	for {
		var raw json.RawMessage
		if err := wsjson.Read(ctx, conn, &raw); err != nil {
			return err
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		if env.Protocol != Protocol || env.Type != "verify.request" || !relayProtocolCompatible(env) {
			continue
		}
		var request verifyRequestMessage
		if err := json.Unmarshal(raw, &request); err != nil {
			continue
		}
		go c.handleVerifyRequest(ctx, conn, request)
	}
}

func (c *Client) authenticate(ctx context.Context, conn *websocket.Conn) error {
	var challenge challengeMessage
	if err := wsjson.Read(ctx, conn, &challenge); err != nil {
		return err
	}
	if challenge.Type != "auth.challenge" || challenge.Protocol != Protocol || !relayProtocolCompatible(envelope{
		ProtocolVersion:     challenge.ProtocolVersion,
		MinSupportedVersion: challenge.MinSupportedVersion,
	}) {
		return errors.New("invalid relay challenge")
	}
	expiresAt, err := time.Parse(time.RFC3339, challenge.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid relay challenge expiry: %w", err)
	}
	if time.Now().After(expiresAt) {
		return errors.New("relay challenge expired")
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	canonical := AuthCanonical(AuthCanonicalInput{
		TenantID:            c.config.TenantID,
		ConnectorID:         c.config.ConnectorID,
		KeyID:               c.config.KeyID,
		ProtocolVersion:     ProtocolVersion,
		MinSupportedVersion: MinSupportedVersion,
		ChallengeID:         challenge.ChallengeID,
		Nonce:               challenge.Nonce,
		Timestamp:           timestamp,
	})
	response := authResponseMessage{
		Type:                "auth.response",
		Protocol:            Protocol,
		ProtocolVersion:     ProtocolVersion,
		MinSupportedVersion: MinSupportedVersion,
		TenantID:            c.config.TenantID,
		ConnectorID:         c.config.ConnectorID,
		KeyID:               c.config.KeyID,
		ChallengeID:         challenge.ChallengeID,
		Nonce:               challenge.Nonce,
		Timestamp:           timestamp,
		Signature:           SignCanonical(canonical, c.config.Secret),
	}
	if err := wsjson.Write(ctx, conn, response); err != nil {
		return err
	}
	var ack envelope
	if err := wsjson.Read(ctx, conn, &ack); err != nil {
		return err
	}
	if ack.Protocol != Protocol || ack.Type != "auth.ok" || !relayProtocolCompatible(ack) {
		return errors.New("relay authentication rejected")
	}
	return nil
}

func (c *Client) handleVerifyRequest(ctx context.Context, conn *websocket.Conn, request verifyRequestMessage) {
	if !c.validVerifyRequest(request) {
		_ = c.writeJSON(ctx, conn, verifyErrorMessage{
			Type:                "verify.error",
			Protocol:            Protocol,
			ProtocolVersion:     ProtocolVersion,
			MinSupportedVersion: MinSupportedVersion,
			ID:                  request.ID,
			RequestID:           request.RequestID,
			TenantID:            request.TenantID,
			ConnectorID:         request.ConnectorID,
			Error:               errorPayload{Code: "invalid_relay_request", Retryable: false},
		})
		return
	}

	select {
	case c.limit <- struct{}{}:
		defer func() { <-c.limit }()
	default:
		_ = c.writeJSON(ctx, conn, verifyErrorMessage{
			Type:                "verify.error",
			Protocol:            Protocol,
			ProtocolVersion:     ProtocolVersion,
			MinSupportedVersion: MinSupportedVersion,
			ID:                  request.ID,
			RequestID:           request.RequestID,
			TenantID:            request.TenantID,
			ConnectorID:         request.ConnectorID,
			Error:               errorPayload{Code: "connector_rate_limited", Retryable: true},
		})
		return
	}

	requestCtx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()
	result, err := c.config.Directory.VerifyPassword(requestCtx, directory.VerifyPasswordRequest{
		Username:       request.Username,
		Password:       request.Password,
		AttributeNames: request.AttributeNames,
	})
	if err != nil {
		_ = c.writeJSON(ctx, conn, verifyErrorMessage{
			Type:                "verify.error",
			Protocol:            Protocol,
			ProtocolVersion:     ProtocolVersion,
			MinSupportedVersion: MinSupportedVersion,
			ID:                  request.ID,
			RequestID:           request.RequestID,
			TenantID:            request.TenantID,
			ConnectorID:         request.ConnectorID,
			Error:               errorPayload{Code: directoryErrorCode(err), Retryable: true},
		})
		return
	}

	credentialResult := result.CredentialResult()
	if credentialResult == directory.CredentialResultSourceUnavailable {
		_ = c.writeJSON(ctx, conn, verifyErrorMessage{
			Type:                "verify.error",
			Protocol:            Protocol,
			ProtocolVersion:     ProtocolVersion,
			MinSupportedVersion: MinSupportedVersion,
			ID:                  request.ID,
			RequestID:           request.RequestID,
			TenantID:            request.TenantID,
			ConnectorID:         request.ConnectorID,
			Error:               errorPayload{Code: result.SafeReason(), Retryable: true},
		})
		return
	}

	response := verifyResponseMessage{
		Type:                "verify.response",
		Protocol:            Protocol,
		ProtocolVersion:     ProtocolVersion,
		MinSupportedVersion: MinSupportedVersion,
		ID:                  request.ID,
		RequestID:           request.RequestID,
		TenantID:            request.TenantID,
		ConnectorID:         request.ConnectorID,
		Result:              string(credentialResult),
		Reason:              result.SafeReason(),
		DirectoryStatus:     "ok",
	}
	if credentialResult == directory.CredentialResultSuccess {
		response.Reason = ""
		response.Subject = &subjectMessage{
			DirectoryID: result.Subject.DirectoryID,
			Username:    result.Subject.Username,
		}
		response.Attributes = result.Attributes
	}
	_ = c.writeJSON(ctx, conn, response)
}

func (c *Client) writeJSON(ctx context.Context, conn *websocket.Conn, value any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return wsjson.Write(ctx, conn, value)
}

func (c *Client) validVerifyRequest(request verifyRequestMessage) bool {
	return request.Type == "verify.request" &&
		request.Protocol == Protocol &&
		relayProtocolCompatible(envelope{
			ProtocolVersion:     request.ProtocolVersion,
			MinSupportedVersion: request.MinSupportedVersion,
		}) &&
		request.ID != "" &&
		request.RequestID != "" &&
		request.TenantID == c.config.TenantID &&
		request.ConnectorID == c.config.ConnectorID &&
		request.Username != "" &&
		request.Password != ""
}

type AuthCanonicalInput struct {
	TenantID            string
	ConnectorID         string
	KeyID               string
	ProtocolVersion     int
	MinSupportedVersion int
	ChallengeID         string
	Nonce               string
	Timestamp           string
}

func AuthCanonical(input AuthCanonicalInput) string {
	return Algorithm + "\n" +
		input.TenantID + "\n" +
		input.ConnectorID + "\n" +
		input.KeyID + "\n" +
		fmt.Sprintf("%d", input.ProtocolVersion) + "\n" +
		fmt.Sprintf("%d", input.MinSupportedVersion) + "\n" +
		input.ChallengeID + "\n" +
		input.Nonce + "\n" +
		input.Timestamp
}

func SignCanonical(canonical string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func parseRelayURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch parsed.Scheme {
	case "wss":
		return parsed, nil
	case "ws":
		if parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1" {
			return parsed, nil
		}
	}
	return nil, errors.New("relay URL must use wss:// except ws://localhost for local development")
}

func relayProtocolCompatible(env envelope) bool {
	return env.ProtocolVersion >= MinSupportedVersion &&
		env.MinSupportedVersion <= ProtocolVersion
}

func validateRelayURLBinding(raw string, tenantID string, connectorID string) error {
	parsed, err := parseRelayURL(raw)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) < 6 {
		return errors.New("relay URL must include /api/auth/directory-relay/connect/{tenant_id}/{connector_id}")
	}
	if strings.Join(parts[len(parts)-6:len(parts)-2], "/") != "api/auth/directory-relay/connect" {
		return errors.New("relay URL must include /api/auth/directory-relay/connect/{tenant_id}/{connector_id}")
	}
	rawTenantID, err := url.PathUnescape(parts[len(parts)-2])
	if err != nil {
		return errors.New("relay URL tenant id is invalid")
	}
	rawConnectorID, err := url.PathUnescape(parts[len(parts)-1])
	if err != nil {
		return errors.New("relay URL connector id is invalid")
	}
	if rawTenantID != tenantID {
		return errors.New("relay URL tenant id does not match configured tenant_id")
	}
	if rawConnectorID != connectorID {
		return errors.New("relay URL connector id does not match configured connector_id")
	}
	return nil
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
