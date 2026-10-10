package jcs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNumbers(t *testing.T) {
	// RFC 8785 Appendix B and ECMAScript edge cases.
	cases := map[string]string{
		"0": "0", "-0": "0", "1": "1", "-1": "-1", "1.0": "1", "100": "100",
		"1e21": "1e+21", "1e20": "100000000000000000000", "0.000001": "0.000001",
		"1e-7": "1e-7", "123.456": "123.456", "9007199254740991": "9007199254740991",
		"1.5e300": "1.5e+300", "5e-324": "5e-324", "0.1": "0.1", "333333333.3333333": "333333333.3333333",
	}
	for in, want := range cases {
		got, err := formatNumber(in)
		if err != nil || got != want {
			t.Errorf("formatNumber(%s) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestStringsAndOrdering(t *testing.T) {
	in := []byte(`{"b":"\u00e9\n","a":[true,null,1.50],"\u20ac":1,"\r":2,"1":3}`)
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\r\":2,\"1\":3,\"a\":[true,null,1.5],\"b\":\"é\\n\",\"€\":1}"
	if string(got) != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

func TestRejectsDuplicates(t *testing.T) {
	if _, err := Canonicalize([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate member names must be rejected")
	}
}

// Every envelope of the real sealed run in sigill-dotnet vector 10 must
// canonicalize to the pinned bytes and hash.
func TestVector10Canonical(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "10-agent-controlled-run")
	files, _ := filepath.Glob(filepath.Join(dir, "artifacts", "*.json"))
	if len(files) == 0 {
		t.Fatal("no vector artifacts found")
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var art struct {
			Envelope json.RawMessage `json:"envelope"`
		}
		if err := json.Unmarshal(raw, &art); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		got, err := Canonicalize(art.Envelope)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		stem := strings.SplitN(filepath.Base(f), ".", 2)[0]
		want, _ := os.ReadFile(filepath.Join(dir, "canonical", stem+".canonical.json"))
		if !bytes.Equal(got, bytes.TrimRight(want, "\n")) {
			t.Errorf("%s: canonical bytes differ", stem)
		}
		wantHash, _ := os.ReadFile(filepath.Join(dir, "canonical", stem+".envelope-hash.txt"))
		sum := sha256.Sum256(got)
		if hex.EncodeToString(sum[:]) != strings.TrimSpace(string(wantHash)) {
			t.Errorf("%s: envelope hash differs", stem)
		}
	}
}
