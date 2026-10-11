package evidence

// A structural check of RFC 3161 timestamp tokens: enough of CMS and TSTInfo to read the message imprint a
// token states, with BER tolerance (indefinite lengths, constructed OCTET STRINGs). It does NOT verify the
// TSA's signature or certificate; verifiers do that. It only establishes that a well-formed token's own
// messageImprint is bound to the signature being checked.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
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
	oidSHA256     = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}             // 2.16.840.1.101.3.4.2.1
	oidSHA384     = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}
	oidSHA512     = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}
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
	sd, err := children(inner[0], 2)
	if err != nil || len(sd) < 3 {
		return nil, nil, errors.New("the timestamp token's SignedData is malformed")
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
	tst, rest, err := readTLV(info, 5)
	if err != nil || len(rest) != 0 || !universal(tst, 16) {
		return nil, nil, errors.New("the TSTInfo is malformed")
	}
	fields, err := children(tst, 6) // version, policy, messageImprint, …
	if err != nil || len(fields) < 3 || !universal(fields[0], 2) || !universal(fields[1], 6) || !universal(fields[2], 16) {
		return nil, nil, errors.New("the TSTInfo is malformed")
	}
	mi, err := children(fields[2], 7)
	if err != nil || len(mi) != 2 || !universal(mi[0], 16) {
		return nil, nil, errors.New("the TSTInfo's messageImprint is malformed")
	}
	alg, err := children(mi[0], 8)
	if err != nil || len(alg) == 0 {
		return nil, nil, errors.New("the messageImprint's hashAlgorithm is malformed")
	}
	hashed, err := octets(mi[1], 8)
	if err != nil {
		return nil, nil, errors.New("the messageImprint's hashedMessage is malformed")
	}
	var h func() hash.Hash
	switch {
	case oidIs(alg[0], oidSHA256):
		h = sha256.New
	case oidIs(alg[0], oidSHA384):
		h = sha512.New384
	case oidIs(alg[0], oidSHA512):
		h = sha512.New
	default:
		return nil, nil, errors.New("the messageImprint uses an unsupported hash algorithm")
	}
	if len(hashed) != h().Size() {
		return nil, nil, errors.New("the messageImprint's length does not match its hash algorithm")
	}
	return h, hashed, nil
}
