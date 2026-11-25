package pdf

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIncrementalRoundTrip(t *testing.T) {
	cases := []struct{ file, pw string }{
		{"demo.pdf", ""},
		{"demo_protected.pdf", "testtest"},
		{"EmptyPage.pdf", ""},
		{"objectXref.pdf", ""},
		{"open_protected.pdf", " "},
		{"sample_signed-sha512.pdf", ""},
		{"pdf_digital_signature_timestamp.pdf", ""},
	}
	for _, c := range cases {
		for _, classic := range []bool{false, true} {
			name := c.file
			if classic {
				name += "/classic"
			}
			t.Run(name, func(t *testing.T) {
				orig := load(t, c.file)
				r, err := Open(orig, []byte(c.pw))
				if err != nil {
					t.Fatal(err)
				}
				w := NewWriter(r, rand.Reader)
				w.ForceClassicXref = classic
				ref, sref := w.NewRef(), w.NewRef()
				w.Set(sref, &Stream{Dict: Dict{}, Data: []byte("payload")})
				w.Set(ref, Dict{"Hello": NewString("wörld (x)\\"), "Raw": sref})
				// Rewrite the catalog with a reference to the new object.
				cat, catRef, err := r.Catalog()
				if err != nil {
					t.Fatal(err)
				}
				nc := DeepCopy(cat).(Dict)
				nc["PdfsignerTest"] = ref
				w.Set(catRef, nc)
				out, err := w.Write()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasPrefix(out, orig) {
					t.Fatal("original bytes are not a prefix")
				}
				r2, err := Open(out, []byte(c.pw))
				if err != nil {
					t.Fatalf("reopen: %v", err)
				}
				cat2, _, err := r2.Catalog()
				if err != nil {
					t.Fatal(err)
				}
				d := r2.ResolveDict(cat2["PdfsignerTest"])
				s, _ := d["Hello"].(*String)
				if s == nil || string(s.Bytes) != "wörld (x)\\" {
					_, err := r2.Resolve(cat2["PdfsignerTest"])
					t.Fatalf("round-trip string = %v (%v)", d, err)
				}
				if st, err := r2.Resolve(d["Raw"]); err != nil || string(st.(*Stream).Data) != "payload" {
					t.Fatalf("round-trip stream = %v %v", st, err)
				}
				if p, err := r2.Pages(); err != nil || len(p) != 1 {
					t.Fatalf("pages: %v %v", p, err)
				}
				if path, err := exec.LookPath("pdfinfo"); err == nil {
					f := filepath.Join(t.TempDir(), "out.pdf")
					os.WriteFile(f, out, 0o644)
					args := []string{f}
					if c.pw != "" {
						args = []string{"-opw", c.pw, f}
					}
					if b, err := exec.Command(path, args...).CombinedOutput(); err != nil || bytes.Contains(b, []byte("Error")) {
						t.Fatalf("pdfinfo: %v\n%s", err, b)
					}
				}
			})
		}
	}
}

func TestFormatReal(t *testing.T) {
	for in, want := range map[float64]string{1: "1", 0.5: "0.5", -0.0000001: "0", 595.32: "595.32", 1e10: "10000000000"} {
		if got := FormatReal(in); got != want {
			t.Errorf("FormatReal(%v) = %q, want %q", in, got, want)
		}
	}
}
