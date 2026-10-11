package evidence

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/sigill-ai/claude-plugins/internal/evidence/evidencetest"
)

// sealWith wraps a token in a JWS the way the platform returns a timestamped seal.
func sealWith(sig string, token []byte) json.RawMessage {
	comp, _ := json.Marshal(map[string]any{"sigTst": map[string]any{"tstTokens": []any{map[string]any{"val": base64.StdEncoding.EncodeToString(token)}}}})
	raw, _ := json.Marshal(map[string]any{"signatures": []any{map[string]any{
		"protected": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"PS256"}`)), "signature": sig,
		"header": map[string]any{"etsiU": []string{base64.RawURLEncoding.EncodeToString(comp)}},
	}}})
	return raw
}

const sig = "c2lnbmF0dXJlLXZhbHVl"

func TestTimestamp_RealPlatformTokenPasses(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/real-run-end-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSignatureTimestamp(raw); err != nil {
		t.Fatalf("a real Sigill seal timestamp must pass: %v", err)
	}
}

func TestTimestamp_WellFormedBoundTokenPasses(t *testing.T) {
	if err := CheckSignatureTimestamp(sealWith(sig, evidencetest.ForSignature(sig))); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256([]byte(sig))
	if err := CheckSignatureTimestamp(sealWith(sig, evidencetest.Token(evidencetest.OIDSHA256, s[:]))); err != nil {
		t.Fatal(err)
	}
}

func TestTimestamp_DigestOnlyValFails(t *testing.T) {
	s := sha512.Sum512([]byte(sig))
	if CheckSignatureTimestamp(sealWith(sig, s[:])) == nil {
		t.Fatal("a bare digest is not a timestamp token")
	}
}

func TestTimestamp_ImprintBytesOutsideMessageImprintFail(t *testing.T) {
	s := sha512.Sum512([]byte(sig))
	other := sha512.Sum512([]byte("another signature"))
	tok := append(evidencetest.Token(evidencetest.OIDSHA512, other[:]), s[:]...) // right bytes, wrong place
	if CheckSignatureTimestamp(sealWith(sig, tok)) == nil {
		t.Fatal("the expected bytes appended after the token must not pass")
	}
	if CheckSignatureTimestamp(sealWith(sig, evidencetest.Token(evidencetest.OIDSHA512, other[:]))) == nil {
		t.Fatal("a token over another signature must not pass")
	}
}

func TestTimestamp_WrongAlgorithmFails(t *testing.T) {
	s := sha512.Sum512([]byte(sig))
	// SHA-512 bytes declared as SHA-256: wrong length for the algorithm.
	if CheckSignatureTimestamp(sealWith(sig, evidencetest.Token(evidencetest.OIDSHA256, s[:]))) == nil {
		t.Fatal("an imprint must match its declared algorithm")
	}
	s256 := sha256.Sum256([]byte(sig))
	if CheckSignatureTimestamp(sealWith(sig, evidencetest.Token(evidencetest.OIDSHA512, append(s256[:], s256[:]...)))) == nil {
		t.Fatal("a 64-byte imprint that is not the SHA-512 must fail")
	}
}

func TestTimestamp_IndefiniteLengthBERPasses(t *testing.T) {
	der := evidencetest.ForSignature(sig)
	// Re-encode the outer ContentInfo SEQUENCE with an indefinite length.
	tl, _, err := readTLV(der, 0)
	if err != nil {
		t.Fatal(err)
	}
	ber := append(append([]byte{0x30, 0x80}, tl.content...), 0, 0)
	if err := CheckSignatureTimestamp(sealWith(sig, ber)); err != nil {
		t.Fatalf("BER indefinite length must be accepted: %v", err)
	}
}

// R3-5: a token is a CMS SignedData with a SignerInfo and a DER TSTInfo carrying every mandatory field.
func TestTimestamp_TruncatedStructuresFail(t *testing.T) {
	s := sha512.Sum512([]byte(sig))
	for name, opts := range map[string]evidencetest.Options{
		"no signerInfos":   {NoSignerInfos: true},
		"no serialNumber":  {OmitSerial: true},
		"no genTime":       {OmitGenTime: true},
		"BER inside TSTInfo": {BERTSTInfo: true},
	} {
		if err := CheckSignatureTimestamp(sealWith(sig, evidencetest.TokenWith(evidencetest.OIDSHA512, s[:], opts))); err == nil {
			t.Errorf("%s: must fail", name)
		}
	}
	if err := CheckSignatureTimestamp(sealWith(sig, evidencetest.TokenWith(evidencetest.OIDSHA512, s[:], evidencetest.Options{}))); err != nil {
		t.Fatalf("the complete token must pass: %v", err)
	}
}
