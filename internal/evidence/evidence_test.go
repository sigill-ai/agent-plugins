package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Cross-language vector: sigill-dotnet spec/test-vectors/agent-run/signature-sha256.json.
func TestSignatureSha256Vectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "agent-run", "signature-sha256.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name      string          `json:"name"`
		Signature json.RawMessage `json:"signature"`
		Expected  *string         `json:"expected"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		want := ""
		if c.Expected != nil {
			want = *c.Expected
		}
		if got := SignatureSha256(c.Signature); got != want {
			t.Errorf("%s: got %q want %q", c.Name, got, want)
		}
	}
}

// The chain of vector 10: every event's prevSignatureSha256 is the binding
// digest of the previous artifact's signature.
func TestVector10Chain(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "10-agent-controlled-run", "artifacts")
	files, _ := filepath.Glob(filepath.Join(dir, "1*.agent-execution.json"))
	var prev string
	for i, f := range files {
		raw, _ := os.ReadFile(f)
		var a struct {
			Envelope struct {
				Chain struct {
					Seq  int    `json:"seq"`
					Prev string `json:"prevSignatureSha256"`
				} `json:"chain"`
			} `json:"envelope"`
			Signature json.RawMessage `json:"signature"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		if a.Envelope.Chain.Seq != i {
			t.Fatalf("%s: seq %d, want %d", f, a.Envelope.Chain.Seq, i)
		}
		if i > 0 && a.Envelope.Chain.Prev != prev {
			t.Fatalf("%s: chain link does not match previous signature", f)
		}
		prev = SignatureSha256(a.Signature)
		if prev == "" {
			t.Fatalf("%s: no binding digest", f)
		}
	}
	if len(files) != 7 {
		t.Fatalf("expected 7 events, got %d", len(files))
	}
}

func TestFormatTime(t *testing.T) {
	ts := time.Date(2026, 10, 10, 9, 0, 2, 123456789, time.FixedZone("CEST", 7200))
	if got := FormatTime(ts); got != "2026-10-10T07:00:02.123Z" {
		t.Fatalf("got %s", got)
	}
}
