// Package testpki generates throwaway certificate hierarchies for tests.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"time"
)

// KeyType selects the key algorithm.
type KeyType int

const (
	RSA2048 KeyType = iota
	P256
	P384
)

// Entity is a certificate with its private key.
type Entity struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// URLs configures the AIA/CRL extensions of issued certificates.
type URLs struct {
	OCSP      string
	CRL       string
	CAIssuers string
}

var serial atomic.Int64

func newKey(kt KeyType) crypto.Signer {
	switch kt {
	case P256:
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k
	case P384:
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return k
	}
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	return k
}

// Template returns a base certificate template.
func Template(cn string, notBefore time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1000 + serial.Add(1)),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"pdfsigner test"}, Country: []string{"AT"}},
		NotBefore:    notBefore.Add(-time.Hour),
		NotAfter:     notBefore.Add(5 * 365 * 24 * time.Hour),
	}
}

// Issue signs tmpl with issuer (nil = self-signed) using a new key of kt.
func Issue(tmpl *x509.Certificate, kt KeyType, issuer *Entity) *Entity {
	key := newKey(kt)
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.Cert, issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &Entity{Cert: cert, Key: key}
}

// Hierarchy is root -> intermediate -> leaf (signer) plus a TSA.
type Hierarchy struct {
	Root, Intermediate, Leaf, TSA, OCSPResponder *Entity
}

// Chain returns [leaf, intermediate].
func (h *Hierarchy) Chain() []*x509.Certificate {
	return []*x509.Certificate{h.Leaf.Cert, h.Intermediate.Cert}
}

// New creates a hierarchy whose leaf has key type kt. urls (may be zero)
// are embedded in the intermediate, leaf and TSA certificates.
func New(kt KeyType, now time.Time, urls URLs) *Hierarchy {
	h := &Hierarchy{}
	rt := Template("pdfsigner Test Root", now)
	rt.IsCA, rt.BasicConstraintsValid = true, true
	rt.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	h.Root = Issue(rt, P256, nil)

	ext := func(t *x509.Certificate) {
		if urls.OCSP != "" {
			t.OCSPServer = []string{urls.OCSP}
		}
		if urls.CRL != "" {
			t.CRLDistributionPoints = []string{urls.CRL}
		}
		if urls.CAIssuers != "" {
			t.IssuingCertificateURL = []string{urls.CAIssuers}
		}
	}
	it := Template("pdfsigner Test Intermediate", now)
	it.IsCA, it.BasicConstraintsValid = true, true
	it.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	ext(it)
	h.Intermediate = Issue(it, P256, h.Root)

	lt := Template("pdfsigner Test Signer", now)
	lt.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	ext(lt)
	h.Leaf = Issue(lt, kt, h.Intermediate)

	tt := Template("pdfsigner Test TSA", now)
	tt.KeyUsage = x509.KeyUsageDigitalSignature
	tt.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	ext(tt)
	h.TSA = Issue(tt, P256, h.Intermediate)

	ot := Template("pdfsigner Test OCSP", now)
	ot.KeyUsage = x509.KeyUsageDigitalSignature
	ot.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	// id-pkix-ocsp-nocheck
	ot.ExtraExtensions = []pkix.Extension{{Id: []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{0x05, 0x00}}}
	h.OCSPResponder = Issue(ot, P256, h.Intermediate)
	return h
}
