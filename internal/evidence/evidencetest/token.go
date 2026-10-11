// Package evidencetest builds minimal RFC 3161 timestamp tokens for tests: a CMS ContentInfo with SignedData
// encapsulating a TSTInfo whose messageImprint is given. There is no TSA signature — tests of the plugin's
// structural imprint check only. Never imported by production code.
package evidencetest

import (
	"crypto/sha512"
	"encoding/asn1"
	"math/big"
	"time"
)

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

type algID struct {
	Algorithm asn1.ObjectIdentifier
}

type messageImprint struct {
	HashAlgorithm algID
	HashedMessage []byte
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
}

// tstInfoRaw carries serialNumber and genTime as given octets (invalid-value tests).
type tstInfoRaw struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   asn1.RawValue
	GenTime        asn1.RawValue
}

// tstInfoNoSerial and tstInfoNoGenTime are TSTInfos missing a mandatory field (negative tests).
type tstInfoNoSerial struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	GenTime        time.Time `asn1:"generalized"`
}

type tstInfoNoGenTime struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	Sid                issuerAndSerial
	DigestAlgorithm    algID
	SignatureAlgorithm algID
	Signature          []byte
}

// Options shape a token for negative tests.
type Options struct {
	NoSignerInfos bool // signerInfos is an empty SET
	OmitSerial    bool // TSTInfo without serialNumber
	OmitGenTime   bool // TSTInfo without genTime
	BERTSTInfo    bool // the TSTInfo SEQUENCE encoded with an indefinite length

	Version       int    // TSTInfo version when non-zero (default 1)
	SerialContent []byte // when non-nil: the serialNumber INTEGER's content octets as given (may be empty)
	GenTime       string // when non-empty: the genTime GeneralizedTime's characters as given
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []algID `asn1:"set"`
	EncapContentInfo encapContentInfo
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     signedData `asn1:"explicit,tag:0"`
}

// Token returns a DER token whose TSTInfo states imprint under alg, with one structurally complete
// SignerInfo (its signature is a placeholder: there is no TSA).
func Token(alg asn1.ObjectIdentifier, imprint []byte) []byte {
	return TokenWith(alg, imprint, Options{})
}

// TokenWith is Token shaped by opts.
func TokenWith(alg asn1.ObjectIdentifier, imprint []byte, opts Options) []byte {
	mi := messageImprint{algID{alg}, imprint}
	policy, serial, gen := asn1.ObjectIdentifier{1, 2, 3}, big.NewInt(1), time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	version := 1
	if opts.Version != 0 {
		version = opts.Version
	}
	var v any = tstInfo{Version: version, Policy: policy, SerialNumber: serial, GenTime: gen, MessageImprint: mi}
	if opts.SerialContent != nil || opts.GenTime != "" {
		serialRaw := asn1.RawValue{Tag: asn1.TagInteger, Bytes: serial.Bytes()}
		if opts.SerialContent != nil {
			serialRaw.Bytes = opts.SerialContent
		}
		genRaw := asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(gen.Format("20060102150405Z"))}
		if opts.GenTime != "" {
			genRaw.Bytes = []byte(opts.GenTime)
		}
		v = tstInfoRaw{Version: version, Policy: policy, MessageImprint: mi, SerialNumber: serialRaw, GenTime: genRaw}
	}
	switch {
	case opts.OmitSerial:
		v = tstInfoNoSerial{Version: 1, Policy: policy, GenTime: gen, MessageImprint: mi}
	case opts.OmitGenTime:
		v = tstInfoNoGenTime{Version: 1, Policy: policy, SerialNumber: serial, MessageImprint: mi}
	}
	info, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	if opts.BERTSTInfo { // same content, indefinite length: valid BER, not DER
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(info, &raw); err != nil {
			panic(err)
		}
		info = append(append([]byte{0x30, 0x80}, raw.Bytes...), 0, 0)
	}
	signers := []asn1.RawValue{}
	if !opts.NoSignerInfos {
		emptyName, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true})
		si, err := asn1.Marshal(signerInfo{Version: 1, Sid: issuerAndSerial{Issuer: asn1.RawValue{FullBytes: emptyName}, Serial: big.NewInt(7)},
			DigestAlgorithm: algID{alg}, SignatureAlgorithm: algID{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}},
			Signature: []byte("placeholder")})
		if err != nil {
			panic(err)
		}
		signers = append(signers, asn1.RawValue{FullBytes: si})
	}
	der, err := asn1.Marshal(contentInfo{ContentType: oidSignedData, Content: signedData{Version: 3,
		DigestAlgorithms: []algID{{alg}}, EncapContentInfo: encapContentInfo{EContentType: oidTSTInfo, EContent: info},
		SignerInfos: signers}})
	if err != nil {
		panic(err)
	}
	return der
}

// ForSignature is a token bound to a JWS signature value the way JAdES binds it: SHA-512 over its base64url text.
func ForSignature(sigB64URL string) []byte {
	sum := sha512.Sum512([]byte(sigB64URL))
	return Token(OIDSHA512, sum[:])
}
