package cms

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// Attribute is a CMS attribute.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// Parsed is a decoded SignedData with a single signer.
type Parsed struct {
	Raw          []byte
	EContentType asn1.ObjectIdentifier
	EContent     []byte // encapsulated content (e.g. TSTInfo), nil if detached
	Certificates []*x509.Certificate
	Signer       *x509.Certificate
	Digest       crypto.Hash
	SignatureAlg pkix.AlgorithmIdentifier
	// SignedAttrsDER is the signed attributes re-tagged as SET (0x31).
	SignedAttrsDER []byte
	SignedAttrs    []Attribute
	UnsignedAttrs  []Attribute
	Signature      []byte
}

// Parse decodes a DER ContentInfo containing SignedData. Trailing zero
// padding (as found in PDF /Contents) is ignored.
func Parse(der []byte) (*Parsed, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("cms: %w", err)
	}
	if len(bytes.Trim(rest, "\x00")) != 0 {
		return nil, errors.New("cms: trailing data")
	}
	if !ci.ContentType.Equal(OIDSignedData) {
		return nil, fmt.Errorf("cms: content type %v is not signedData", ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("cms: signedData: %w", err)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("cms: %d signer infos, want 1", len(sd.SignerInfos))
	}
	p := &Parsed{Raw: der[:len(der)-len(rest)], EContentType: sd.EncapContentInfo.EContentType}
	if len(sd.EncapContentInfo.EContent.Bytes) > 0 {
		var oct []byte
		if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &oct); err == nil {
			p.EContent = oct
		}
	}
	if len(sd.Certificates.Bytes) > 0 {
		certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cms: certificates: %w", err)
		}
		p.Certificates = certs
	}
	si := sd.SignerInfos[0]
	if p.Digest, err = HashFromOID(si.DigestAlgorithm.Algorithm); err != nil {
		return nil, err
	}
	p.SignatureAlg = si.SignatureAlgorithm
	p.Signature = si.Signature
	if len(si.SignedAttrs.FullBytes) > 0 {
		p.SignedAttrsDER = append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
		if p.SignedAttrs, err = parseAttrs(p.SignedAttrsDER); err != nil {
			return nil, err
		}
	}
	if len(si.UnsignedAttrs.FullBytes) > 0 {
		if p.UnsignedAttrs, err = parseAttrs(append([]byte{0x31}, si.UnsignedAttrs.FullBytes[1:]...)); err != nil {
			return nil, err
		}
	}
	// Locate the signer certificate by IssuerAndSerialNumber.
	var ias issuerAndSerial
	if si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0 {
		for _, c := range p.Certificates {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, si.SID.Bytes) {
				p.Signer = c
				break
			}
		}
	} else if _, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err == nil {
		for _, c := range p.Certificates {
			if c.SerialNumber.Cmp(ias.Serial) == 0 && bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) {
				p.Signer = c
				break
			}
		}
	}
	if p.Signer == nil {
		return nil, errors.New("cms: signer certificate not found")
	}
	return p, nil
}

func parseAttrs(set []byte) ([]Attribute, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(set, &raw); err != nil {
		return nil, fmt.Errorf("cms: attributes: %w", err)
	}
	var attrs []Attribute
	rest := raw.Bytes
	for len(rest) > 0 {
		var a Attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, fmt.Errorf("cms: attribute: %w", err)
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

// Attr returns the first value of attribute oid.
func Attr(attrs []Attribute, oid asn1.ObjectIdentifier) (asn1.RawValue, bool) {
	for _, a := range attrs {
		if a.Type.Equal(oid) && len(a.Values) > 0 {
			return a.Values[0], true
		}
	}
	return asn1.RawValue{}, false
}

// Verify checks the signature over the signed attributes and that the
// messageDigest attribute equals digest(content) where content is the
// detached data digest supplied by the caller.
func (p *Parsed) Verify(contentDigest []byte) error {
	if p.SignedAttrsDER == nil {
		return errors.New("cms: no signed attributes")
	}
	md, ok := Attr(p.SignedAttrs, OIDMessageDigest)
	if !ok {
		return errors.New("cms: messageDigest attribute missing")
	}
	var got []byte
	if _, err := asn1.Unmarshal(md.FullBytes, &got); err != nil {
		return fmt.Errorf("cms: messageDigest: %w", err)
	}
	if !bytes.Equal(got, contentDigest) {
		return errors.New("cms: messageDigest mismatch")
	}
	pss := p.SignatureAlg.Algorithm.Equal(OIDRSASSAPSS)
	return verifyRaw(p.Signer.PublicKey, p.Digest, pss, p.SignedAttrsDER, p.Signature)
}

// TimestampToken returns the signature timestamp token, if present.
func (p *Parsed) TimestampToken() []byte {
	v, ok := Attr(p.UnsignedAttrs, OIDSignatureTimeStamp)
	if !ok {
		return nil
	}
	return v.FullBytes
}
