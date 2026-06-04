package hmacadapter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const Algorithm = "AUTHRIM-HMAC-SHA256"

const (
	HeaderConnectorID   = "X-Authrim-Connector-Id"
	HeaderKeyID         = "X-Authrim-Key-Id"
	HeaderRequestID     = "X-Authrim-Request-Id"
	HeaderTimestamp     = "X-Authrim-Timestamp"
	HeaderNonce         = "X-Authrim-Nonce"
	HeaderSignedHeaders = "X-Authrim-Signed-Headers"
	HeaderSignature     = "X-Authrim-Signature"
)

var (
	ErrMissingHeader    = errors.New("missing_hmac_header")
	ErrInvalidTimestamp = errors.New("invalid_hmac_timestamp")
	ErrStaleTimestamp   = errors.New("stale_hmac_timestamp")
	ErrUnknownKey       = errors.New("unknown_hmac_key")
	ErrInvalidSignature = errors.New("invalid_hmac_signature")
)

type Key struct {
	KID    string
	Secret []byte
}

type KeySet struct {
	Active   Key
	Previous *Key
}

type Verifier struct {
	keys      KeySet
	now       func() time.Time
	clockSkew time.Duration
}

type VerificationResult struct {
	ConnectorID string
	KeyID       string
	RequestID   string
	Timestamp   time.Time
	Nonce       string
}

func NewVerifier(keys KeySet) Verifier {
	return Verifier{
		keys:      keys,
		now:       time.Now,
		clockSkew: 2 * time.Minute,
	}
}

func (v Verifier) WithClock(now func() time.Time) Verifier {
	v.now = now
	return v
}

func (v Verifier) Verify(req *http.Request) (VerificationResult, []byte, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return VerificationResult{}, nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	headers, err := requiredHeaders(req)
	if err != nil {
		return VerificationResult{}, body, err
	}

	timestamp, err := time.Parse(time.RFC3339, headers.timestamp)
	if err != nil {
		return VerificationResult{}, body, fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
	}
	if diff := v.now().Sub(timestamp).Abs(); diff > v.clockSkew {
		return VerificationResult{}, body, ErrStaleTimestamp
	}

	key, ok := v.lookupKey(headers.keyID)
	if !ok {
		return VerificationResult{}, body, ErrUnknownKey
	}

	canonical, err := CanonicalRequest(req, body, headers.signedHeaders, headers.timestamp, headers.nonce)
	if err != nil {
		return VerificationResult{}, body, err
	}
	expected := SignCanonical(canonical, key.Secret)
	if !hmac.Equal([]byte(expected), []byte(headers.signature)) {
		return VerificationResult{}, body, ErrInvalidSignature
	}

	return VerificationResult{
		ConnectorID: headers.connectorID,
		KeyID:       headers.keyID,
		RequestID:   headers.requestID,
		Timestamp:   timestamp,
		Nonce:       headers.nonce,
	}, body, nil
}

func (v Verifier) lookupKey(kid string) (Key, bool) {
	if v.keys.Active.KID == kid {
		return v.keys.Active, true
	}
	if v.keys.Previous != nil && v.keys.Previous.KID == kid {
		return *v.keys.Previous, true
	}
	return Key{}, false
}

type hmacHeaders struct {
	connectorID   string
	keyID         string
	requestID     string
	timestamp     string
	nonce         string
	signedHeaders []string
	signature     string
}

func requiredHeaders(req *http.Request) (hmacHeaders, error) {
	values := hmacHeaders{
		connectorID: strings.TrimSpace(req.Header.Get(HeaderConnectorID)),
		keyID:       strings.TrimSpace(req.Header.Get(HeaderKeyID)),
		requestID:   strings.TrimSpace(req.Header.Get(HeaderRequestID)),
		timestamp:   strings.TrimSpace(req.Header.Get(HeaderTimestamp)),
		nonce:       strings.TrimSpace(req.Header.Get(HeaderNonce)),
		signature:   strings.TrimSpace(req.Header.Get(HeaderSignature)),
	}
	rawSignedHeaders := strings.TrimSpace(req.Header.Get(HeaderSignedHeaders))
	if values.connectorID == "" || values.keyID == "" || values.requestID == "" ||
		values.timestamp == "" || values.nonce == "" || rawSignedHeaders == "" || values.signature == "" {
		return hmacHeaders{}, ErrMissingHeader
	}
	values.signedHeaders = parseSignedHeaders(rawSignedHeaders)
	return values, nil
}

func parseSignedHeaders(raw string) []string {
	parts := strings.Split(raw, ";")
	headers := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.ToLower(strings.TrimSpace(part))
		if name != "" {
			headers = append(headers, name)
		}
	}
	sort.Strings(headers)
	return headers
}

func CanonicalRequest(req *http.Request, body []byte, signedHeaders []string, timestamp string, nonce string) (string, error) {
	bodyHash := sha256.Sum256(body)
	lines := []string{
		Algorithm,
		timestamp,
		nonce,
		req.Method,
		req.URL.EscapedPath(),
		canonicalQuery(req.URL.Query()),
		strings.Join(signedHeaders, ";"),
		hex.EncodeToString(bodyHash[:]),
	}
	return strings.Join(lines, "\n"), nil
}

func SignCanonical(canonical string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0)
	for _, key := range keys {
		vals := append([]string(nil), values[key]...)
		sort.Strings(vals)
		for _, value := range vals {
			parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(value))
		}
	}
	return strings.Join(parts, "&")
}
