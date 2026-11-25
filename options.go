package pdfsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"net/http"
	"time"
)

// Level is the PAdES baseline conformance level.
type Level int

const (
	// LevelBB is PAdES-BASELINE-B: a CAdES signature with signed attributes.
	LevelBB Level = iota
	// LevelBT adds an RFC 3161 signature timestamp.
	LevelBT
	// LevelBLT adds validation data (certificates, OCSP, CRLs) in a DSS.
	LevelBLT
	// LevelBLTA adds a document timestamp over everything.
	LevelBLTA
)

func (l Level) String() string {
	switch l {
	case LevelBB:
		return "B-B"
	case LevelBT:
		return "B-T"
	case LevelBLT:
		return "B-LT"
	case LevelBLTA:
		return "B-LTA"
	}
	return "unknown"
}

// CertLevel is the DocMDP certification level.
type CertLevel int

const (
	// NotCertified creates an approval signature.
	NotCertified CertLevel = 0
	// CertNoChanges allows no changes (DocMDP P=1).
	CertNoChanges CertLevel = 1
	// CertFormFilling allows form filling and signing (P=2).
	CertFormFilling CertLevel = 2
	// CertFormFillingAnnotations also allows annotations (P=3).
	CertFormFillingAnnotations CertLevel = 3
)

// SubFilter values.
const (
	SubFilterCAdES      = "ETSI.CAdES.detached"
	SubFilterPKCS7      = "adbe.pkcs7.detached"
	subFilterRFC3161    = "ETSI.RFC3161"
	defaultFilter       = "Adobe.PPKLite"
	defaultAppName      = "pdfsigner"
	minimumContentsSize = 4096
)

// Timestamper obtains RFC 3161 timestamp tokens.
type Timestamper interface {
	// Timestamp returns a DER TimeStampToken (ContentInfo) over digest,
	// which was computed with h.
	Timestamp(ctx context.Context, h crypto.Hash, digest []byte) ([]byte, error)
}

// RevocationSource fetches validation material for B-LT/B-LTA.
type RevocationSource interface {
	// OCSP returns a DER OCSPResponse for cert.
	OCSP(ctx context.Context, cert, issuer *x509.Certificate) ([]byte, error)
	// CRL returns a DER CRL covering cert.
	CRL(ctx context.Context, cert, issuer *x509.Certificate) ([]byte, error)
	// Issuer fetches the issuer of cert (AIA caIssuers).
	Issuer(ctx context.Context, cert *x509.Certificate) (*x509.Certificate, error)
}

// TSAConfig configures the built-in RFC 3161 HTTP client.
type TSAConfig struct {
	// URLs are tried in order; the first success wins.
	URLs               []string
	Username, Password string
	PolicyOID          asn1.ObjectIdentifier
	// Digest for the message imprint; default SHA-256.
	Digest  crypto.Hash
	Timeout time.Duration
}

// Policy relaxes or tightens validation rules.
type Policy struct {
	// AllowExpiredCert permits signing with a certificate that is not valid
	// at the signing time.
	AllowExpiredCert bool
	// AllowMissingRevocation lets B-LT/B-LTA proceed when no OCSP or CRL
	// can be obtained for some certificate.
	AllowMissingRevocation bool
	// ForbidLTVAfterNoChanges rejects adding DSS/document timestamp
	// revisions to a DocMDP P=1 document (allowed by default).
	ForbidLTVAfterNoChanges bool
	// StrictTSAEKU requires the TSA certificate's timeStamping extended key
	// usage to be the only one and marked critical (RFC 3161 2.3).
	StrictTSAEKU bool
	// OmitVRI skips writing the (deprecated) /VRI dictionary.
	OmitVRI bool
	// AddDTSRevocationRevision appends validation data for the document
	// timestamp in a final revision (B-LTA).
	AddDTSRevocationRevision bool
	// IgnorePermissions signs encrypted documents opened with the user
	// password even if the permission flags do not allow it.
	IgnorePermissions bool
}

// SignOptions configures a signature.
type SignOptions struct {
	// Signer is the private key. Required for Sign; may be nil for Prepare.
	// Supported: RSA (PKCS#1 v1.5 or PSS) and ECDSA P-256/P-384/P-521.
	Signer crypto.Signer
	// Chain is the signing certificate followed by intermediates.
	Chain []*x509.Certificate
	// Digest is the message digest algorithm; default SHA-256.
	Digest crypto.Hash
	// RSAPSS selects RSASSA-PSS for RSA keys.
	RSAPSS bool
	// Level is the PAdES level; default LevelBB.
	Level Level
	// SubFilter is SubFilterCAdES (default) or SubFilterPKCS7.
	SubFilter string
	// Certify makes this a certification signature with DocMDP.
	Certify CertLevel
	// FieldName names the signature field. If an unsigned signature field
	// with this name exists it is used; default "Signature<n>".
	FieldName string

	Reason, Location, ContactInfo, Name string

	// SigningTime is the claimed signing time (/M); default Now().
	SigningTime time.Time
	// Appearance makes the signature visible; nil = invisible.
	Appearance *Appearance

	// TSA configures the built-in timestamp client (B-T and above).
	TSA *TSAConfig
	// Timestamper overrides TSA.
	Timestamper Timestamper
	// RevocationSource overrides the built-in online OCSP/CRL/AIA fetcher.
	RevocationSource RevocationSource
	// OCSPResponses and CRLs are pre-fetched DER validation data that are
	// embedded for B-LT/B-LTA in addition to fetched data.
	OCSPResponses [][]byte
	CRLs          [][]byte
	// ExtraCertificates are added to the DSS (e.g. the root CA).
	ExtraCertificates []*x509.Certificate

	// Password opens encrypted documents (owner or user password).
	Password []byte
	// ContentsSize overrides the reserved signature size in bytes.
	ContentsSize int
	// HTTPClient is used for TSA, OCSP, CRL and AIA requests.
	HTTPClient *http.Client

	Policy Policy

	// Rand is the source of randomness (IDs, AES IVs, nonces); default
	// crypto/rand.
	Rand io.Reader
	// Now returns the current time; default time.Now.
	Now func() time.Time
}

// Result carries non-fatal information about a signing operation.
type Result struct {
	Warnings []string
}

func (o *SignOptions) withDefaults() SignOptions {
	c := *o
	if c.Digest == 0 {
		c.Digest = crypto.SHA256
	}
	if c.SubFilter == "" {
		c.SubFilter = SubFilterCAdES
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.SigningTime.IsZero() {
		c.SigningTime = c.Now()
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	return c
}

func (o *SignOptions) timestamper() Timestamper {
	if o.Timestamper != nil {
		return o.Timestamper
	}
	if o.TSA != nil && len(o.TSA.URLs) > 0 {
		return &httpTimestamper{cfg: *o.TSA, client: o.HTTPClient, rand: o.Rand, strictEKU: o.Policy.StrictTSAEKU}
	}
	return nil
}
