package sigill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sigill-ai/claude-plugins/internal/evidence"
)

// Backend is how the recorder reaches Sigill: REST with an API key (headless CI) or the
// MCP agent-recording tools with Sigill sign-in (OAuth). Both give the same guarantees;
// the platform's REST ingest stays the only authority either way.
type Backend interface {
	PlatformCertificate(ctx context.Context) (string, error)
	// qualified asks for a qualified (eIDAS) timestamp; it only applies when timestamp is true.
	SignHashes(ctx context.Context, envelopeHashHex, contentType, certificateID string, objects []evidence.Object, timestamp, qualified bool) (*SealResult, error)
	IndexBatch(ctx context.Context, items []IndexItem) ([]IndexOutcome, error)
}

// IndexItem is one sealed artifact to index; Key identifies it in the outcome.
type IndexItem struct {
	Key           string            `json:"key"`
	Envelope      json.RawMessage   `json:"envelope"`
	Signature     json.RawMessage   `json:"signature"`
	ObjectDigests map[string]string `json:"object_digests"`
}

// IndexOutcome: Status is indexed | exists | rejected | retry.
type IndexOutcome struct {
	Key        string `json:"key"`
	Status     string `json:"status"`
	Code       string `json:"code"`
	RetryAfter int    `json:"retryAfterSeconds"`
}

// RetryableError: the request was refused BEFORE it was processed (throttling), so the
// same request may be sent again. Anything else that fails is not retried.
type RetryableError struct {
	Err   error
	After time.Duration
}

func (e *RetryableError) Error() string { return e.Err.Error() }

// AuthError: the credential was refused; the user must reconnect.
// QuotaError: the organisation's monthly agent evidence pool is used up. Nothing was sealed; recording
// resumes when the pool resets. Not a sealing failure, and not retried within the month.
type QuotaError struct{ ResetsAt string }

func (e *QuotaError) Error() string {
	if e.ResetsAt == "" {
		return "the organisation's monthly agent evidence quota is used up; recording resumes when it resets"
	}
	return "the organisation's monthly agent evidence quota is used up; recording resumes when it resets (" + e.ResetsAt + ")"
}

type AuthError struct{ Err error }

func (e *AuthError) Error() string { return e.Err.Error() }

func retryAfter(h http.Header) time.Duration {
	if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return 2 * time.Second
}

// ── REST (API key) ──────────────────────────────────────────────────────────

// IndexBatch over REST: one request per item.
func (c *Client) IndexBatch(ctx context.Context, items []IndexItem) ([]IndexOutcome, error) {
	out := make([]IndexOutcome, 0, len(items))
	for _, it := range items {
		err := c.Index(ctx, it.Envelope, it.Signature, it.ObjectDigests)
		var ie *IndexError
		switch {
		case err == nil:
			out = append(out, IndexOutcome{Key: it.Key, Status: "indexed"})
		case errors.As(err, &ie) && ie.Permanent():
			out = append(out, IndexOutcome{Key: it.Key, Status: "rejected", Code: strconv.Itoa(ie.Status)})
		default:
			out = append(out, IndexOutcome{Key: it.Key, Status: "retry"})
			return out, nil // unreachable or busy: stop here
		}
	}
	return out, nil
}

// ── MCP (Sigill sign-in) ────────────────────────────────────────────────────

// MCPClient calls the agent-recording tools on POST {Base}/mcp with an OAuth access token.
//
// It deliberately sends tools/call without an MCP initialize handshake: every hook is a short-lived process,
// and Sigill's /mcp endpoint is stateless (plain JSON responses, no session id, no SSE), so it answers
// tools/call on its own. An initialize per hook would add a round trip to every recorded step and buy
// nothing. This relies on that documented server behaviour; a test pins that no initialize is sent.
type MCPClient struct {
	Base  string
	Token string
	HTTP  *http.Client
}

func NewMCP(base, token string) *MCPClient {
	return &MCPClient{Base: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type toolResult struct {
	IsError           bool            `json:"isError"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	Content           []struct {
		Text string `json:"text"`
	} `json:"content"`
}

// call invokes one tool. Transport errors, JSON-RPC errors and tool errors (isError) are
// distinct; retryability comes from the structured result, never from prose.
func (m *MCPClient) call(ctx context.Context, tool string, args any, out any) error {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.Base+"/mcp", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("User-Agent", "sigill-claude-code/"+Version)
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", tool, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return &AuthError{fmt.Errorf("Sigill refused the connection (%d) — sign in again", resp.StatusCode)}
	case resp.StatusCode == 429:
		return &RetryableError{Err: fmt.Errorf("%s throttled", tool), After: retryAfter(resp.Header)}
	case resp.StatusCode != 200:
		return fmt.Errorf("%s failed (%d)", tool, resp.StatusCode)
	}
	var rpc struct {
		Result *toolResult `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &rpc); err != nil {
		return fmt.Errorf("%s: unreadable response", tool)
	}
	if rpc.Error != nil {
		return fmt.Errorf("%s: protocol error %d", tool, rpc.Error.Code)
	}
	if rpc.Result == nil {
		return fmt.Errorf("%s: empty result", tool)
	}
	if rpc.Result.IsError {
		var se struct {
			Error             string `json:"error"`
			Retryable         bool   `json:"retryable"`
			RetryAfterSeconds int    `json:"retryAfterSeconds"`
			Status            int    `json:"status"`
			ResetsAt          string `json:"resetsAt"`
		}
		_ = json.Unmarshal(rpc.Result.StructuredContent, &se)
		msg := se.Error
		if msg == "" {
			msg = "tool error"
		}
		if se.Error == "agent_evidence_quota_exceeded" {
			return &QuotaError{ResetsAt: se.ResetsAt}
		}
		// Only throttling is a proven "not processed" outcome.
		if se.Error == "rate_limited" || se.Status == 429 {
			after := time.Duration(max(se.RetryAfterSeconds, 1)) * time.Second
			return &RetryableError{Err: fmt.Errorf("%s: %s", tool, msg), After: after}
		}
		return fmt.Errorf("%s: %s", tool, msg)
	}
	if out != nil {
		return json.Unmarshal(rpc.Result.StructuredContent, out)
	}
	return nil
}

func (m *MCPClient) PlatformCertificate(ctx context.Context) (string, error) {
	var r struct {
		Certificates []struct{ ID, Source string } `json:"certificates"`
	}
	if err := m.call(ctx, "sigill_agent_recording_config", map[string]any{}, &r); err != nil {
		return "", err
	}
	for _, c := range r.Certificates {
		if c.Source == "platform" && c.ID != "" {
			return c.ID, nil
		}
	}
	return "", errors.New("no active Sigill Platform Seal is available")
}

func (m *MCPClient) SignHashes(ctx context.Context, envelopeHashHex, contentType, certificateID string, objects []evidence.Object, timestamp, qualified bool) (*SealResult, error) {
	objs := make([]map[string]string, 0, len(objects))
	for _, o := range objects {
		objs = append(objs, map[string]string{"uri": o.URI, "hash_hex": o.SHA256, "content_type": o.ContentType})
	}
	var r SealResult
	args := map[string]any{
		"envelope_hash_hex": envelopeHashHex, "envelope_content_type": contentType,
		"certificate_id": certificateID, "timestamp": timestamp, "objects": objs,
	}
	if qualified && timestamp {
		args["qualified"] = true
	}
	err := m.call(ctx, "sigill_seal_agent_artifact", args, &r)
	if err != nil {
		return nil, err
	}
	if len(r.Signature) == 0 {
		return nil, errors.New("seal response carried no signature")
	}
	return &r, nil
}

func (m *MCPClient) IndexBatch(ctx context.Context, items []IndexItem) ([]IndexOutcome, error) {
	var r struct {
		Results []IndexOutcome `json:"results"`
	}
	if err := m.call(ctx, "sigill_index_agent_artifacts", map[string]any{"items": items}, &r); err != nil {
		return nil, err
	}
	return r.Results, nil
}
