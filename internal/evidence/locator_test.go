package evidence

import (
	"regexp"
	"testing"
)

func TestIsProductionReference(t *testing.T) {
	for uri, want := range map[string]bool{
		"": false, ".": false, "..": false, "a/": false, "/a": false, "a//b": false, `a\b`: false, "a b": false,
		"a%20b": false, "a?b": false, "a#b": false, "urn:x": false, "https://x": false, "objects/../x": false,
		"a\tb": false, "ø": false, "sigill-envelope.json": true,
		"a": true, "objects/6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90": true, "x/y.z/A_b~c-d": true, "...": true,
	} {
		if got := IsProductionReference(uri); got != want {
			t.Errorf("IsProductionReference(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestNewObjectUsesObjectsUUID(t *testing.T) {
	o := NewObject("tool-arguments", "application/json", []byte(`{}`))
	if !regexp.MustCompile(`^objects/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(o.URI) {
		t.Fatalf("NewObject URI %q", o.URI)
	}
}

func TestRemintUnsignedOnlyTouchesLegacyURIsAndKeepsDigests(t *testing.T) {
	keep := NewObject("model-input", "text/plain", []byte("a"))
	old := NewObject("model-input", "text/plain", []byte("b"))
	old.URI = "urn:uuid:6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90"
	out := RemintUnsigned([]Object{keep, old})
	if out[0] != keep {
		t.Fatal("a production-profile URI must not change")
	}
	if out[1].URI == old.URI || !IsProductionReference(out[1].URI) || out[1].SHA256 != old.SHA256 || out[1].SizeBytes != old.SizeBytes {
		t.Fatalf("re-mint: %+v from %+v", out[1], old)
	}
	if old.URI != "urn:uuid:6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90" {
		t.Fatal("the input slice must not be mutated")
	}
}
