// Package sigill calls the blind sealing endpoint. Only digests, opaque URIs
// and content types are sent — never content.
package sigill

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sigill-ai/claude-plugins/internal/evidence"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type SealResult struct {
	Signature     json.RawMessage `json:"signature"`
	OperationID   string          `json:"operationId"`
	Format        string          `json:"format"`
	TimestampedBy string          `json:"timestampedBy"`
}

type signObject struct {
	URI         string `json:"uri"`
	HashHex     string `json:"hashHex"`
	ContentType string `json:"contentType,omitempty"`
}

// SignHashes seals an envelope digest plus its object digests (POST /seal/sign-hashes).
// No label is sent: operation labels derived from event types are not allowed (common rules §6.5).
func (c *Client) SignHashes(ctx context.Context, envelopeHashHex, envelopeContentType, certificateID string, objects []evidence.Object, timestamp bool) (*SealResult, error) {
	objs := make([]signObject, 0, len(objects))
	for _, o := range objects {
		objs = append(objs, signObject{URI: o.URI, HashHex: o.SHA256, ContentType: o.ContentType})
	}
	body := map[string]any{
		"envelopeHashHex":     envelopeHashHex,
		"envelopeContentType": envelopeContentType,
		"certificateId":       certificateID,
		"objects":             objs,
		"qualified":           false,
	}
	if !timestamp {
		body["timestamp"] = false
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/seal/sign-hashes", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sigill-claude-code/"+Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("seal request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == 429 { // throttled before processing: the same request may be sent again
		return nil, &RetryableError{Err: fmt.Errorf("seal throttled"), After: retryAfter(resp.Header)}
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, &AuthError{fmt.Errorf("Sigill refused the API key (%d)", resp.StatusCode)}
	}
	if resp.StatusCode == 402 {
		var p struct {
			Code     string `json:"code"`
			ResetsAt string `json:"resetsAt"`
		}
		if json.Unmarshal(data, &p) == nil && p.Code == "agent_evidence_quota_exceeded" {
			return nil, &QuotaError{ResetsAt: p.ResetsAt}
		}
	}
	if resp.StatusCode/100 != 2 {
		// Body may echo request fields; keep it short and never include the key.
		return nil, fmt.Errorf("seal rejected (%d): %.300s", resp.StatusCode, data)
	}
	var r SealResult
	if err := json.Unmarshal(data, &r); err != nil || len(r.Signature) == 0 {
		return nil, fmt.Errorf("seal response carried no signature")
	}
	return &r, nil
}

// Index uploads a sealed artifact's SIGNED envelope, its JWS and object digests to the
// tenant's agent evidence index (POST /api/agent-evidence/artifacts). Never payloads.
// The platform accepts it only if it matches a seal this tenant made.
func (c *Client) Index(ctx context.Context, envelope, signature json.RawMessage, digests map[string]string) error {
	raw, _ := json.Marshal(map[string]any{"envelope": envelope, "signature": signature, "objectDigests": digests})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/agent-evidence/artifacts", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sigill-claude-code/"+Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("index request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return &IndexError{Status: resp.StatusCode, Body: fmt.Sprintf("%.300s", data)}
	}
	return nil
}

// IndexError is a non-2xx answer from the index.
type IndexError struct {
	Status int
	Body   string
}

func (e *IndexError) Error() string { return fmt.Sprintf("index rejected (%d): %s", e.Status, e.Body) }

// Permanent reports whether retrying the same upload cannot succeed (a 4xx other than
// timeout, throttling or a lost concurrent race).
func (e *IndexError) Permanent() bool {
	if e.Status < 400 || e.Status >= 500 || e.Status == 408 || e.Status == 429 || e.Status == 401 || e.Status == 403 {
		return false
	}
	return !(e.Status == 409 && strings.Contains(e.Body, `"code":"conflict"`))
}

// Version is set at build time (-ldflags "-X .../sigill.Version=...").
var Version = "0.1.0-dev"

// PlatformCertificate returns the id of the active Sigill Platform Seal certificate, used when
// no certificate of the organisation's own (BYOC) is configured.
func (c *Client) PlatformCertificate(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/seal/certificates", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "sigill-claude-code/"+Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("certificate lookup failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("certificate lookup rejected (%d)", resp.StatusCode)
	}
	var certs []struct{ ID, Source, Status string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&certs); err != nil {
		return "", fmt.Errorf("certificate lookup: %w", err)
	}
	for _, ct := range certs {
		if ct.Source == "platform" && ct.Status == "active" && ct.ID != "" {
			return ct.ID, nil
		}
	}
	return "", fmt.Errorf("no active Sigill Platform Seal is available")
}
