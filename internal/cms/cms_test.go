package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mailvibi/pdfsigner/internal/testpki"
)

func TestSignedDataRoundTrip(t *testing.T) {
	content := []byte("detached content to sign")
	for _, tc := range []struct {
		name string
		kt   testpki.KeyType
		h    crypto.Hash
		pss  bool
	}{
		{"rsa-sha256", testpki.RSA2048, crypto.SHA256, false},
		{"rsa-pss-sha384", testpki.RSA2048, crypto.SHA384, true},
		{"p256-sha256", testpki.P256, crypto.SHA256, false},
		{"p384-sha512", testpki.P384, crypto.SHA512, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testpki.New(tc.kt, time.Now(), testpki.URLs{})
			now := time.Now()
			cfg := &SignerConfig{Chain: h.Chain(), Digest: tc.h, PSS: tc.pss, AlgorithmProtection: true, SigningTime: &now}
			hh := tc.h.New()
			hh.Write(content)
			md := hh.Sum(nil)
			sa, err := cfg.SignedAttributes(md)
			if err != nil {
				t.Fatal(err)
			}
			ah := tc.h.New()
			ah.Write(sa)
			sig, err := h.Leaf.Key.Sign(rand.Reader, ah.Sum(nil), cfg.SignerOpts())
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.VerifySignature(sa, sig); err != nil {
				t.Fatal(err)
			}
			der, err := cfg.Assemble(sa, sig, nil)
			if err != nil {
				t.Fatal(err)
			}
			p, err := Parse(append(der, 0, 0, 0))
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Verify(md); err != nil {
				t.Fatal(err)
			}
			if p.Signer.Equal(h.Leaf.Cert) == false {
				t.Fatal("wrong signer")
			}
			opensslVerify(t, der, content, h.Root.Cert.Raw)
		})
	}
}

func opensslVerify(t *testing.T, der, content, rootDER []byte) {
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	sigF, contF, caF := filepath.Join(dir, "sig.der"), filepath.Join(dir, "content"), filepath.Join(dir, "ca.pem")
	os.WriteFile(sigF, der, 0o644)
	os.WriteFile(contF, content, 0o644)
	os.WriteFile(caF, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o644)
	out, err := exec.Command(path, "cms", "-verify", "-inform", "DER", "-in", sigF, "-binary",
		"-content", contF, "-CAfile", caF, "-purpose", "any", "-out", os.DevNull).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -verify: %v\n%s", err, out)
	}
}

func TestNormalizeECDSA(t *testing.T) {
	h := testpki.New(testpki.P256, time.Now(), testpki.URLs{})
	key := h.Leaf.Key.(*ecdsa.PrivateKey)
	d := sha256.Sum256([]byte("x"))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	der := NormalizeECDSA(&key.PublicKey, raw)
	if !ecdsa.VerifyASN1(&key.PublicKey, d[:], der) {
		t.Fatal("normalized signature does not verify")
	}
	if got := NormalizeECDSA(&key.PublicKey, der); string(got) != string(der) {
		t.Fatal("DER input modified")
	}
}
