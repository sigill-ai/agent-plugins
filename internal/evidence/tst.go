package evidence

// A structural and value check of RFC 3161 timestamp tokens — NOT TSA verification. It establishes that the
// token is a well-formed CMS SignedData (RFC 5652) with at least one SignerInfo carrying its mandatory fields,
// that it encapsulates a DER-framed TSTInfo (RFC 3161 §2.4.2: definite minimal lengths, primitive strings)
// whose mandatory fields decode (encoding/asn1) to valid values — version 1, a policy OID, a messageImprint of
// a supported hash with a matching length, a minimally encoded serialNumber, a UTC genTime of the RFC 3161
// form — and that the TSTInfo's own messageImprint is bound to the signature being checked. The outer CMS may
// be BER (indefinite lengths, constructed OCTET STRINGs). Whether the TSA's signature is valid and its
// certificate trusted is decided by verifiers (Sigill's verify-objects, the SDKs), never here.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

type tlv struct {
	class, number int
	constructed   bool
	content       []byte // the content octets (for an indefinite length: the nested encodings, without EOC)
}

var errASN1 = errors.New("malformed ASN.1")

// readTLV reads one BER element from b and returns it and the rest.
func readTLV(b []byte, depth int) (tlv, []byte, error) {
	if depth > 32 || len(b) < 2 {
		return tlv{}, nil, errASN1
	}
	t := tlv{class: int(b[0] >> 6), constructed: b[0]&0x20 != 0, number: int(b[0] & 0x1f)}
	if t.number == 0x1f {
		return tlv{}, nil, errASN1 // high tag numbers do not occur in the structures read here
	}
	l, i := int(b[1]), 2
	switch {
	case l == 0x80: // indefinite: constructed only, ends with 00 00
		if !t.constructed {
			return tlv{}, nil, errASN1
		}
		rest := b[2:]
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				t.content = b[2 : len(b)-len(rest)]
				return t, rest[2:], nil
			}
			var err error
			if _, rest, err = readTLV(rest, depth+1); err != nil {
				return tlv{}, nil, err
			}
		}
	case l > 0x80:
		n := l & 0x7f
		if n > 4 || len(b) < 2+n {
			return tlv{}, nil, errASN1
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		i = 2 + n
	}
	if l < 0 || len(b)-i < l {
		return tlv{}, nil, errASN1
	}
	t.content = b[i : i+l]
	return t, b[i+l:], nil
}

// children reads every element of a constructed value.
func children(t tlv, depth int) ([]tlv, error) {
	if !t.constructed {
		return nil, errASN1
	}
	var out []tlv
	rest := t.content
	for len(rest) > 0 {
		c, r, err := readTLV(rest, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		rest = r
	}
	return out, nil
}

func universal(t tlv, number int) bool { return t.class == 0 && t.number == number }

// octets returns an OCTET STRING's value, joining the segments of a constructed (BER) one.
func octets(t tlv, depth int) ([]byte, error) {
	if !universal(t, 4) {
		return nil, errASN1
	}
	if !t.constructed {
		return t.content, nil
	}
	parts, err := children(t, depth)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, p := range parts {
		v, err := octets(p, depth+1)
		if err != nil {
			return nil, err
		}
		buf.Write(v)
	}
	return buf.Bytes(), nil
}

func oidIs(t tlv, der []byte) bool {
	return universal(t, 6) && !t.constructed && bytes.Equal(t.content, der)
}

var (
	oidSignedData = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}             // 1.2.840.113549.1.7.2
	oidTSTInfo    = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04} // 1.2.840.113549.1.9.16.1.4
)

// tokenImprint parses a timestamp token (CMS ContentInfo with SignedData over a TSTInfo) and returns the hash
// function its messageImprint declares and the hashed message it states.
func tokenImprint(token []byte) (func() hash.Hash, []byte, error) {
	ci, rest, err := readTLV(token, 0)
	if err != nil || len(rest) != 0 || !universal(ci, 16) {
		return nil, nil, errors.New("the timestamp token is not a ContentInfo")
	}
	ciParts, err := children(ci, 0)
	if err != nil || len(ciParts) != 2 || !oidIs(ciParts[0], oidSignedData) || ciParts[1].class != 2 || ciParts[1].number != 0 {
		return nil, nil, errors.New("the timestamp token is not CMS SignedData")
	}
	inner, err := children(ciParts[1], 1)
	if err != nil || len(inner) != 1 || !universal(inner[0], 16) {
		return nil, nil, errors.New("the timestamp token's SignedData is malformed")
	}
	// SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo, [0] certificates OPTIONAL,
	//                           [1] crls OPTIONAL, signerInfos SET }
	sd, err := children(inner[0], 2)
	if err != nil || len(sd) < 4 || !universal(sd[0], 2) || !universal(sd[1], 17) || !universal(sd[2], 16) {
		return nil, nil, errors.New("the timestamp token's SignedData is malformed")
	}
	for _, opt := range sd[3 : len(sd)-1] {
		if opt.class != 2 || (opt.number != 0 && opt.number != 1) {
			return nil, nil, errors.New("the timestamp token's SignedData is malformed")
		}
	}
	if err := checkSignerInfos(sd[len(sd)-1]); err != nil {
		return nil, nil, err
	}
	encap, err := children(sd[2], 3) // version, digestAlgorithms, encapContentInfo
	if err != nil || len(encap) != 2 || !oidIs(encap[0], oidTSTInfo) || encap[1].class != 2 || encap[1].number != 0 {
		return nil, nil, errors.New("the timestamp token does not encapsulate a TSTInfo")
	}
	ec, err := children(encap[1], 4)
	if err != nil || len(ec) != 1 {
		return nil, nil, errors.New("the timestamp token's eContent is malformed")
	}
	info, err := octets(ec[0], 5)
	if err != nil {
		return nil, nil, errors.New("the timestamp token's eContent is not an OCTET STRING")
	}
	if !isDER(info, 0) {
		return nil, nil, errors.New("the TSTInfo is not DER-encoded (RFC 3161 §2.4.2)")
	}
	var tst tstInfo
	if rest, err := asn1.Unmarshal(info, &tst); err != nil || len(rest) != 0 {
		return nil, nil, fmt.Errorf("the TSTInfo is malformed or lacks a mandatory field (version, policy, messageImprint, serialNumber, genTime): %v", err)
	}
	if tst.Version != 1 {
		return nil, nil, fmt.Errorf("the TSTInfo version is %d, not 1", tst.Version)
	}
	if len(tst.Policy) < 2 {
		return nil, nil, errors.New("the TSTInfo's policy is not a valid OID")
	}
	if tst.SerialNumber == nil {
		return nil, nil, errors.New("the TSTInfo's serialNumber is malformed")
	}
	if tst.GenTime.Class != asn1.ClassUniversal || tst.GenTime.Tag != asn1.TagGeneralizedTime || tst.GenTime.IsCompound ||
		!validGenTime(tst.GenTime.Bytes) {
		return nil, nil, errors.New("the TSTInfo's genTime is not a valid UTC GeneralizedTime (RFC 3161 §2.4.2)")
	}
	hashed := tst.MessageImprint.HashedMessage
	alg := tst.MessageImprint.HashAlgorithm.Algorithm
	var h func() hash.Hash
	switch {
	case alg.Equal(asn1OIDSHA256):
		h = sha256.New
	case alg.Equal(asn1OIDSHA384):
		h = sha512.New384
	case alg.Equal(asn1OIDSHA512):
		h = sha512.New
	default:
		return nil, nil, errors.New("the messageImprint uses an unsupported hash algorithm")
	}
	if len(hashed) != h().Size() {
		return nil, nil, errors.New("the messageImprint's length does not match its hash algorithm")
	}
	return h, hashed, nil
}

// TSTInfo ::= SEQUENCE { version INTEGER { v1(1) }, policy TSAPolicyId, messageImprint MessageImprint,
// serialNumber INTEGER, genTime GeneralizedTime, accuracy, ordering, nonce, tsa, extensions (all optional) }.
// encoding/asn1 rejects empty or non-minimal INTEGERs, malformed OIDs and constructed OCTET STRINGs; the
// optional trailing fields are not interpreted here.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      asn1.RawValue // validated by validGenTime: encoding/asn1 would also accept offsets
}

var (
	asn1OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	asn1OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	asn1OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// validGenTime: RFC 3161 §2.4.2 genTime — YYYYMMDDhhmmss[.s+]Z in UTC, a valid calendar time, fractional
// seconds without trailing zeros (and no lone "."), no other characters.
func validGenTime(b []byte) bool {
	s := string(b)
	if len(s) < 15 || s[len(s)-1] != 'Z' {
		return false
	}
	body, frac, hasFrac := strings.Cut(s[:len(s)-1], ".")
	if hasFrac && (frac == "" || strings.HasSuffix(frac, "0")) {
		return false
	}
	if len(body) != 14 || !digits(body) || !digits(frac) {
		return false
	}
	_, err := time.Parse("20060102150405", body)
	return err == nil
}

func digits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// checkSignerInfos requires signerInfos ::= SET OF SignerInfo with at least one SignerInfo carrying its
// mandatory fields: version INTEGER, sid (IssuerAndSerialNumber or [0] SubjectKeyIdentifier), digestAlgorithm,
// [0] signedAttrs OPTIONAL, signatureAlgorithm, signature OCTET STRING. Structure only; the signature itself
// is not checked here.
func checkSignerInfos(set tlv) error {
	bad := errors.New("the timestamp token has no well-formed SignerInfo")
	if !universal(set, 17) {
		return bad
	}
	infos, err := children(set, 3)
	if err != nil || len(infos) == 0 {
		return bad
	}
	for _, si := range infos {
		f, err := children(si, 4)
		if err != nil || !universal(si, 16) || len(f) < 5 || !universal(f[0], 2) {
			return bad
		}
		if !(universal(f[1], 16) || (f[1].class == 2 && f[1].number == 0)) || !universal(f[2], 16) {
			return bad
		}
		i := 3
		if f[i].class == 2 && f[i].number == 0 { // signedAttrs
			i++
		}
		if len(f) < i+2 || !universal(f[i], 16) || !universal(f[i+1], 4) {
			return bad
		}
	}
	return nil
}

// isDER reports whether b is one DER element: definite, minimal lengths throughout and primitive encodings for
// the string types (X.690 §10). The TSTInfo must be DER (RFC 3161 §2.4.2); its timestamp is what is signed.
func isDER(b []byte, depth int) bool {
	rest, ok := derElement(b, depth)
	return ok && len(rest) == 0
}

func derElement(b []byte, depth int) ([]byte, bool) {
	if depth > 32 || len(b) < 2 || b[0]&0x1f == 0x1f {
		return nil, false
	}
	constructed := b[0]&0x20 != 0
	class, number := b[0]>>6, b[0]&0x1f
	l, i := int(b[1]), 2
	switch {
	case l == 0x80:
		return nil, false // indefinite
	case l > 0x80:
		n := l & 0x7f
		if n > 4 || len(b) < 2+n || b[2] == 0 {
			return nil, false // too long, or a leading zero octet
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		if l < 0x80 {
			return nil, false // long form where the short form fits
		}
		i = 2 + n
	}
	if len(b)-i < l {
		return nil, false
	}
	content := b[i : i+l]
	if class == 0 && constructed && (number == 3 || number == 4 || number == 12 || (number >= 18 && number <= 30)) {
		return nil, false // a constructed string (BER only)
	}
	if constructed {
		for len(content) > 0 {
			var ok bool
			if content, ok = derElement(content, depth+1); !ok {
				return nil, false
			}
		}
	}
	return b[i+l:], true
}
