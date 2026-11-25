// Package cms builds and parses the CMS SignedData structures (RFC 5652)
// used by PAdES signatures: detached CAdES signatures with ESS
// signing-certificate-v2 (RFC 5035) and optional RFC 3161 timestamps.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Object identifiers.
var (
	OIDData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDContentType            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDSigningCertificateV2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	OIDSignatureTimeStamp     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	OIDCMSAlgorithmProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}
	OIDTSTInfo                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	OIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDRSASSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	OIDSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSHA1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDECDSASHA1     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// DigestOID returns the OID of h.
func DigestOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return OIDSHA256, nil
	case crypto.SHA384:
		return OIDSHA384, nil
	case crypto.SHA512:
		return OIDSHA512, nil
	case crypto.SHA1:
		return OIDSHA1, nil
	}
	return nil, fmt.Errorf("cms: unsupported digest %v", h)
}

// HashFromOID maps a digest OID to a crypto.Hash.
func HashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDSHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDSHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDSHA512):
		return crypto.SHA512, nil
	case oid.Equal(OIDSHA1):
		return crypto.SHA1, nil
	}
	return 0, fmt.Errorf("cms: unsupported digest OID %v", oid)
}

// SignerConfig describes how the SignerInfo is built.
type SignerConfig struct {
	// Chain[0] is the signing certificate; all are embedded.
	Chain  []*x509.Certificate
	Digest crypto.Hash
	// PSS selects RSASSA-PSS for RSA keys.
	PSS bool
	// SigningTime adds the signingTime attribute when non-nil
	// (adbe.pkcs7.detached only; forbidden for PAdES).
	SigningTime *time.Time
	// AlgorithmProtection adds the RFC 6211 attribute.
	AlgorithmProtection bool
	// ExtraCerts are added to the certificate set (e.g. a root).
	ExtraCerts []*x509.Certificate
}

func (c *SignerConfig) cert() (*x509.Certificate, error) {
	if len(c.Chain) == 0 || c.Chain[0] == nil {
		return nil, errors.New("cms: no signing certificate")
	}
	return c.Chain[0], nil
}

func addAlgID(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, params []byte) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if params != nil {
			b.AddBytes(params)
		}
	})
}

var asn1Null = []byte{0x05, 0x00}

// DigestAlgorithmID returns the DER AlgorithmIdentifier of the digest
// (parameters absent, RFC 5754).
func (c *SignerConfig) DigestAlgorithmID() ([]byte, error) {
	oid, err := DigestOID(c.Digest)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	addAlgID(&b, oid, nil)
	return b.Bytes()
}

// SignatureAlgorithmID returns the DER AlgorithmIdentifier used in
// SignerInfo.signatureAlgorithm.
func (c *SignerConfig) SignatureAlgorithmID() ([]byte, error) {
	cert, err := c.cert()
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if c.PSS {
			params, err := pssParams(c.Digest)
			if err != nil {
				return nil, err
			}
			addAlgID(&b, OIDRSASSAPSS, params)
		} else {
			addAlgID(&b, OIDRSAEncryption, asn1Null)
		}
	case *ecdsa.PublicKey:
		var oid asn1.ObjectIdentifier
		switch c.Digest {
		case crypto.SHA256:
			oid = OIDECDSASHA256
		case crypto.SHA384:
			oid = OIDECDSASHA384
		case crypto.SHA512:
			oid = OIDECDSASHA512
		default:
			return nil, fmt.Errorf("cms: unsupported ECDSA digest %v", c.Digest)
		}
		addAlgID(&b, oid, nil)
	default:
		return nil, fmt.Errorf("cms: unsupported public key type %T", cert.PublicKey)
	}
	return b.Bytes()
}

// pssParams encodes RSASSA-PSS-params (RFC 4055) like crypto/x509 does:
// explicit hash (with NULL params), MGF1 with the same hash, salt length =
// hash length, default trailer field.
func pssParams(h crypto.Hash) ([]byte, error) {
	oid, err := DigestOID(h)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			addAlgID(b, oid, asn1Null)
		})
		b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(OIDMGF1)
				addAlgID(b, oid, asn1Null)
			})
		})
		b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1Int64(int64(h.Size()))
		})
	})
	return b.Bytes()
}

func attribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddBytes(value)
		})
	})
	return b.BytesOrPanic()
}

// derSet encodes a DER SET OF with elements sorted by their encodings.
func derSet(elems [][]byte) []byte {
	sorted := append([][]byte(nil), elems...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
		for _, e := range sorted {
			b.AddBytes(e)
		}
	})
	return b.BytesOrPanic()
}

// SigningCertificateV2 returns the DER of the ESS SigningCertificateV2 value.
func SigningCertificateV2(cert *x509.Certificate, h crypto.Hash) ([]byte, error) {
	oid, err := DigestOID(h)
	if err != nil {
		return nil, err
	}
	hh := h.New()
	hh.Write(cert.Raw)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SigningCertificateV2
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // certs
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ESSCertIDv2
				if h != crypto.SHA256 { // DEFAULT id-sha256
					addAlgID(b, oid, nil)
				}
				b.AddASN1OctetString(hh.Sum(nil))
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // IssuerSerial
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // GeneralNames
						b.AddASN1(cbasn1.Tag(4).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
							b.AddBytes(cert.RawIssuer)
						})
					})
					b.AddASN1BigInt(cert.SerialNumber)
				})
			})
		})
	})
	return b.Bytes()
}

// SignedAttributes returns the DER encoding (SET OF, tag 0x31) of the signed
// attributes; this is the exact byte string that gets signed.
func (c *SignerConfig) SignedAttributes(messageDigest []byte) ([]byte, error) {
	cert, err := c.cert()
	if err != nil {
		return nil, err
	}
	var attrs [][]byte
	var ct cryptobyte.Builder
	ct.AddASN1ObjectIdentifier(OIDData)
	attrs = append(attrs, attribute(OIDContentType, ct.BytesOrPanic()))
	var md cryptobyte.Builder
	md.AddASN1OctetString(messageDigest)
	attrs = append(attrs, attribute(OIDMessageDigest, md.BytesOrPanic()))
	scv2, err := SigningCertificateV2(cert, c.Digest)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, attribute(OIDSigningCertificateV2, scv2))
	if c.SigningTime != nil {
		t, err := asn1.Marshal(c.SigningTime.UTC())
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attribute(OIDSigningTime, t))
	}
	if c.AlgorithmProtection {
		dig, err := c.DigestAlgorithmID()
		if err != nil {
			return nil, err
		}
		sig, err := c.SignatureAlgorithmID()
		if err != nil {
			return nil, err
		}
		// signatureAlgorithm [1] IMPLICIT: replace the SEQUENCE tag.
		sigImplicit := append([]byte{0xA1}, sig[1:]...)
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(dig)
			b.AddBytes(sigImplicit)
		})
		attrs = append(attrs, attribute(OIDCMSAlgorithmProtection, b.BytesOrPanic()))
	}
	return derSet(attrs), nil
}

// UnsignedAttribute builds one attribute for the unsignedAttrs set.
func UnsignedAttribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	return attribute(oid, value)
}

// TimestampAttribute wraps a TimeStampToken (a ContentInfo) as the
// id-aa-signatureTimeStampToken unsigned attribute.
func TimestampAttribute(token []byte) []byte {
	return attribute(OIDSignatureTimeStamp, token)
}

// Assemble builds the ContentInfo(SignedData) DER.
func (c *SignerConfig) Assemble(signedAttrs, signature []byte, unsignedAttrs [][]byte) ([]byte, error) {
	cert, err := c.cert()
	if err != nil {
		return nil, err
	}
	dig, err := c.DigestAlgorithmID()
	if err != nil {
		return nil, err
	}
	sigAlg, err := c.SignatureAlgorithmID()
	if err != nil {
		return nil, err
	}
	if len(signedAttrs) == 0 || signedAttrs[0] != 0x31 {
		return nil, errors.New("cms: signed attributes must be a DER SET")
	}
	var certs [][]byte
	seen := map[string]bool{}
	for _, cc := range append(append([]*x509.Certificate{}, c.Chain...), c.ExtraCerts...) {
		if cc == nil || seen[string(cc.Raw)] {
			continue
		}
		seen[string(cc.Raw)] = true
		certs = append(certs, cc.Raw)
	}
	sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i], certs[j]) < 0 })

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ContentInfo
		b.AddASN1ObjectIdentifier(OIDSignedData)
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignedData
				b.AddASN1Int64(1)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(dig) })
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(OIDData)
				})
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					for _, raw := range certs {
						b.AddBytes(raw)
					}
				})
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignerInfo
						b.AddASN1Int64(1)
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddBytes(cert.RawIssuer)
							b.AddASN1BigInt(cert.SerialNumber)
						})
						b.AddBytes(dig)
						b.AddBytes(append([]byte{0xA0}, signedAttrs[1:]...))
						b.AddBytes(sigAlg)
						b.AddASN1OctetString(signature)
						if len(unsignedAttrs) > 0 {
							set := derSet(unsignedAttrs)
							b.AddBytes(append([]byte{0xA1}, set[1:]...))
						}
					})
				})
			})
		})
	})
	return b.Bytes()
}

// SignerOpts returns the crypto.SignerOpts to use with crypto.Signer.Sign.
func (c *SignerConfig) SignerOpts() crypto.SignerOpts {
	if c.PSS {
		return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: c.Digest}
	}
	return c.Digest
}

// VerifySignature checks sig over signedAttrs with the certificate's key.
func (c *SignerConfig) VerifySignature(signedAttrs, sig []byte) error {
	cert, err := c.cert()
	if err != nil {
		return err
	}
	return verifyRaw(cert.PublicKey, c.Digest, c.PSS, signedAttrs, sig)
}

func verifyRaw(pub any, h crypto.Hash, pss bool, data, sig []byte) error {
	hh := h.New()
	hh.Write(data)
	d := hh.Sum(nil)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if pss {
			return rsa.VerifyPSS(k, h, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h})
		}
		return rsa.VerifyPKCS1v15(k, h, d, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, d, sig) {
			return errors.New("cms: ECDSA signature verification failed")
		}
		return nil
	}
	return fmt.Errorf("cms: unsupported public key type %T", pub)
}

// NormalizeECDSA converts a raw r||s ECDSA signature (as returned by many
// HSMs and cloud KMS) into ASN.1 DER. DER input is returned unchanged.
func NormalizeECDSA(pub *ecdsa.PublicKey, sig []byte) []byte {
	n := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return sig
	}
	// A DER signature can coincidentally have length 2n; if it parses as a
	// SEQUENCE of two INTEGERs consuming all input, keep it.
	s := cryptobyte.String(sig)
	var inner cryptobyte.String
	if s.ReadASN1(&inner, cbasn1.SEQUENCE) && s.Empty() {
		var r1, s1 []byte
		if inner.ReadASN1Integer(&r1) && inner.ReadASN1Integer(&s1) && inner.Empty() {
			return sig
		}
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addUnsigned(b, sig[:n])
		addUnsigned(b, sig[n:])
	})
	return b.BytesOrPanic()
}

func addUnsigned(b *cryptobyte.Builder, v []byte) {
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
		if len(v) > 0 && v[0]&0x80 != 0 {
			b.AddUint8(0)
		}
		b.AddBytes(v)
	})
}
