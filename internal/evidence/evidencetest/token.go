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

// Token returns a DER token whose TSTInfo states imprint under alg.
func Token(alg asn1.ObjectIdentifier, imprint []byte) []byte {
	info, err := asn1.Marshal(tstInfo{Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3}, SerialNumber: big.NewInt(1),
		GenTime: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC), MessageImprint: messageImprint{algID{alg}, imprint}})
	if err != nil {
		panic(err)
	}
	der, err := asn1.Marshal(contentInfo{ContentType: oidSignedData, Content: signedData{Version: 3,
		DigestAlgorithms: []algID{{alg}}, EncapContentInfo: encapContentInfo{EContentType: oidTSTInfo, EContent: info},
		SignerInfos: []asn1.RawValue{}}})
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
