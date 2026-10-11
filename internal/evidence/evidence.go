// Package evidence builds Agent Evidence Profiles v1 envelopes
// (sigill-dotnet/spec/agent-profiles-common-v1.md) and computes the
// binding digests that chain them together.
//
// Only digests ever leave the machine: an Object carries the SHA-256 of
// its content, never the content itself.
package evidence

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sigill-ai/claude-plugins/internal/jcs"
)

const (
	ControlArtifactSchema   = "AgentControlArtifact"
	ExecutionEvidenceSchema = "AgentExecutionEvidence"

	ControlArtifactContentType   = "application/vnd.sigill.agent-control+json"
	ExecutionEvidenceContentType = "application/vnd.sigill.agent-execution+json"
)

// Object is a detached object: content stays local, only its digest is sealed.
type Object struct {
	URI         string `json:"uri"`
	Role        string `json:"role"`
	ContentType string `json:"contentType"`
	SizeBytes   int    `json:"sizeBytes"`
	SHA256      string `json:"sha256"`
}

// NewObject hashes content locally and returns its detached-object record.
func NewObject(role, contentType string, content []byte) Object {
	sum := sha256.Sum256(content)
	return Object{URI: NewURN(), Role: role, ContentType: contentType, SizeBytes: len(content), SHA256: hex.EncodeToString(sum[:])}
}

// NewURN returns an opaque urn:uuid (v4). URIs never carry personal data (§5).
func NewURN() string { return "urn:uuid:" + NewUUID() }

func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// FormatTime renders the millisecond-precision UTC time the profiles sign (§4).
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func objectsBlock(objs []Object) []map[string]any {
	out := make([]map[string]any, 0, len(objs))
	for _, o := range objs {
		out = append(out, map[string]any{"uri": o.URI, "role": o.Role, "contentType": o.ContentType, "sizeBytes": o.SizeBytes})
	}
	return out
}

// Digests maps object URI → SHA-256 hex, the bundle's objectDigests.
func Digests(objs []Object) map[string]string {
	d := map[string]string{}
	for _, o := range objs {
		d[o.URI] = o.SHA256
	}
	return d
}

type Actor struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

type TimestampPolicy struct {
	Profile       string `json:"profile"`
	EveryEvents   int    `json:"everyEvents"`
	EverySeconds  int    `json:"everySeconds"`
	Consequential bool   `json:"consequential"`
}

// ControlArtifact builds the BEFORE envelope (agent-control-artifact-v1.md).
func ControlArtifact(now time.Time, actor Actor, activity, correlationID, agentID, agentVersion, controlSetID, controlSetVersion string,
	policy TimestampPolicy, objs []Object) map[string]any {
	return map[string]any{
		"schemaName":      ControlArtifactSchema,
		"schemaVersion":   "1",
		"evidenceId":      NewUUID(),
		"createdAt":       FormatTime(now),
		"actor":           actor,
		"activity":        map[string]any{"name": activity, "correlationId": correlationID},
		"agent":           map[string]any{"id": agentID, "version": agentVersion},
		"controlSet":      map[string]any{"id": controlSetID, "version": controlSetVersion},
		"timestampPolicy": policy,
		"objects":         objectsBlock(objs),
	}
}

// Event builds one DURING envelope (agent-execution-evidence-v1.md; schemaVersion "2" adds
// sub-agent delegation, agent-delegation-v1.md). step must already hold the type-specific
// fields; this adds type, eventTime, consequential and timestamp. binds is set on run_start
// only: the Control Artifact, and for a sub-agent run the parent's delegation.
func Event(now time.Time, schemaVersion string, actor Actor, activity, correlationID string, seq int, prevSig string, binds map[string]any,
	stepType string, step map[string]any, consequential, stamp bool, extensions map[string]any, objs []Object) map[string]any {
	if step == nil {
		step = map[string]any{}
	}
	step["type"] = stepType
	step["eventTime"] = FormatTime(now)
	step["consequential"] = consequential
	if stamp {
		step["timestamp"] = "required"
	} else {
		step["timestamp"] = "none"
	}
	chain := map[string]any{"seq": seq}
	if seq > 0 {
		chain["prevSignatureSha256"] = prevSig
	}
	env := map[string]any{
		"schemaName":    ExecutionEvidenceSchema,
		"schemaVersion": schemaVersion,
		"evidenceId":    NewUUID(),
		"createdAt":     FormatTime(now),
		"actor":         actor,
		"activity":      map[string]any{"name": activity, "correlationId": correlationID},
		"chain":         chain,
		"step":          step,
		"objects":       objectsBlock(objs),
	}
	if len(binds) > 0 {
		env["binds"] = binds
	}
	if len(extensions) > 0 {
		env["extensions"] = extensions
	}
	return env
}

// EnvelopeHash returns the canonical bytes and their SHA-256 hex — what /seal/sign-hashes signs.
func EnvelopeHash(envelope any) ([]byte, string, error) {
	c, err := jcs.Marshal(envelope)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(c)
	return c, hex.EncodeToString(sum[:]), nil
}

// SignatureSha256 is the binding digest (§2): SHA-256 hex over the
// base64url-decoded signature value of the single classical JWS entry
// (first signatures[] entry whose protected alg is not ML-DSA, or a
// flattened JWS). Empty when there is none or it is not strict base64url.
func SignatureSha256(signature json.RawMessage) string {
	var jws struct {
		Signature  *string `json:"signature"`
		Signatures []struct {
			Protected string `json:"protected"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(signature, &jws); err != nil {
		return ""
	}
	pick := ""
	found := false
	if jws.Signatures != nil {
		for _, e := range jws.Signatures {
			if isPQ(e.Protected) {
				continue
			}
			pick, found = e.Signature, true
			break
		}
	} else if jws.Signature != nil {
		pick, found = *jws.Signature, true
	}
	if !found || !strictB64URL(pick) {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(pick)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// An entry whose protected header cannot be read counts as classical (§2).
func isPQ(protected string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return false
	}
	return strings.HasPrefix(h.Alg, "ML-DSA")
}

func strictB64URL(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// CheckSignatureTimestamp verifies that a sealed JWS carries the signature timestamp
// a required timestamp demands (common rules §6.2): a JAdES sigTst in the classical
// entry's etsiU whose RFC 3161 token is bound to THIS signature — its message imprint
// (SHA-256, -384 or -512 over the base64url signature value, JAdES §5.3.4) occurs in
// the token. It does not verify the TSA's signature; verifiers do that.
func CheckSignatureTimestamp(signature json.RawMessage) error {
	var jws struct {
		Signature  *string          `json:"signature"`
		Header     *json.RawMessage `json:"header"`
		Signatures []struct {
			Protected string          `json:"protected"`
			Signature string          `json:"signature"`
			Header    json.RawMessage `json:"header"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(signature, &jws); err != nil {
		return fmt.Errorf("the seal is not a JSON JWS")
	}
	var sig string
	var header json.RawMessage
	for _, e := range jws.Signatures {
		if !isPQ(e.Protected) {
			sig, header = e.Signature, e.Header
			break
		}
	}
	if jws.Signatures == nil && jws.Signature != nil && jws.Header != nil {
		sig, header = *jws.Signature, *jws.Header
	}
	if sig == "" || len(header) == 0 {
		return fmt.Errorf("the seal carries no signature timestamp")
	}
	var h struct {
		EtsiU []string `json:"etsiU"`
	}
	if json.Unmarshal(header, &h) != nil {
		return fmt.Errorf("the seal's unprotected header is malformed")
	}
	target := []byte(sig)
	imprints := [][]byte{}
	s256 := sha256.Sum256(target)
	s384 := sha512.Sum384(target)
	s512 := sha512.Sum512(target)
	imprints = append(imprints, s256[:], s384[:], s512[:])
	for _, comp := range h.EtsiU {
		raw, err := base64.RawURLEncoding.DecodeString(comp)
		if err != nil {
			continue
		}
		var c struct {
			SigTst *struct {
				TstTokens []struct {
					Val string `json:"val"`
				} `json:"tstTokens"`
			} `json:"sigTst"`
		}
		if json.Unmarshal(raw, &c) != nil || c.SigTst == nil {
			continue
		}
		for _, t := range c.SigTst.TstTokens {
			der, err := base64.StdEncoding.DecodeString(t.Val)
			if err != nil {
				continue
			}
			for _, im := range imprints {
				if bytes.Contains(der, im) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("the seal carries no signature timestamp bound to its signature")
}
