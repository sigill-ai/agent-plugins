// Package jcs implements the JSON Canonicalization Scheme (RFC 8785).
//
// Sigill seals the SHA-256 of an envelope's canonical bytes, so this package
// must produce byte-identical output to the reference SDK (sigill-dotnet,
// Internal/JsonCanonicalizer.cs). The cross-language vectors in
// sigill-dotnet/spec/test-vectors pin that.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize parses JSON text and returns its RFC 8785 canonical form.
// Duplicate member names, invalid UTF-8, NaN and Infinity are rejected.
func Canonicalize(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("jcs: input is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("jcs: trailing data after JSON value")
	}
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Marshal canonicalizes a Go value (maps, slices, strings, numbers, bools, nil).
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

type member struct {
	key string
	val any
}

type object []member

// parseValue walks tokens so duplicate keys are detected (encoding/json silently keeps the last).
func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := object{}
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("jcs: %w", err)
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("jcs: object key is not a string")
				}
				if seen[key] {
					return nil, fmt.Errorf("jcs: duplicate member name %q", key)
				}
				seen[key] = true
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj = append(obj, member{key, val})
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, fmt.Errorf("jcs: %w", err)
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, fmt.Errorf("jcs: %w", err)
			}
			return arr, nil
		}
		return nil, fmt.Errorf("jcs: unexpected delimiter %v", t)
	default:
		return t, nil // string, json.Number, bool, nil
	}
}

func write(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		s, err := formatNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case object:
		// RFC 8785 §3.2.3: sort by the UTF-16 code units of the member names.
		sorted := make(object, len(t))
		copy(sorted, t)
		sort.Slice(sorted, func(i, j int) bool { return lessUTF16(sorted[i].key, sorted[j].key) })
		buf.WriteByte('{')
		for i, m := range sorted {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, m.key)
			buf.WriteByte(':')
			if err := write(buf, m.val); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString escapes per RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify).
func writeString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[r>>4])
				buf.WriteByte(hex[r&0xF])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// formatNumber serializes like ECMAScript Number.prototype.toString (RFC 8785 §3.2.2.3).
func formatNumber(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("jcs: number %q: %w", lit, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("jcs: NaN and Infinity are not allowed")
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest round-trip digits: "d.ddddde±XX".
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k := len(digits)
	n := exp + 1 // position of the decimal point
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		es := strconv.Itoa(n - 1)
		if n-1 >= 0 {
			es = "+" + es
		}
		if k == 1 {
			out = digits + "e" + es
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es
		}
	}
	return sign + out, nil
}
