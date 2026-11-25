package pdf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenFixtures(t *testing.T) {
	cases := []struct {
		file     string
		password string
		pages    int
		width    float64
		stream   bool
		enc      bool
	}{
		{"demo.pdf", "", 1, 595.32, false, false},
		{"demo_protected.pdf", "testtest", 1, 595.32, true, true},
		{"EmptyPage.pdf", "", 1, 612, true, false},
		{"objectXref.pdf", "", 1, 594.992, false, false},
		{"open_protected.pdf", " ", 1, 0, false, true},
		{"sample_signed-sha1.pdf", "", 1, 595, false, false},
		{"sample_signed-sha512.pdf", "", 1, 595, false, false},
		{"pdf_digital_signature_timestamp.pdf", "", 1, 612, false, false},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			r, err := Open(load(t, c.file), []byte(c.password))
			if err != nil {
				t.Fatal(err)
			}
			if (r.Crypt() != nil) != c.enc {
				t.Errorf("encrypted = %v, want %v", r.Crypt() != nil, c.enc)
			}
			pages, err := r.Pages()
			if err != nil {
				t.Fatal(err)
			}
			if len(pages) != c.pages {
				t.Fatalf("pages = %d, want %d", len(pages), c.pages)
			}
			w := pages[0].MediaBox[2] - pages[0].MediaBox[0]
			if c.width != 0 && (w < c.width-0.01 || w > c.width+0.01) {
				t.Errorf("width = %v, want %v", w, c.width)
			}
			// Load every object to exercise the parser and decryption.
			for num := range r.xref {
				if _, err := r.GetObject(Ref{Num: num, Gen: r.Generation(num)}); err != nil {
					t.Errorf("object %d: %v", num, err)
				}
			}
			if r.Crypt() != nil {
				info := r.ResolveDict(r.Trailer()["Info"])
				t.Logf("info: %v owner=%v P=%d R=%d", info, r.Crypt().Owner(), r.Crypt().P(), r.Crypt().R())
			}
			t.Logf("version=%s lastXrefStream=%v size=%d", r.Version, r.LastXrefIsStream, r.Size())
		})
	}
}

func TestWrongPassword(t *testing.T) {
	if _, err := Open(load(t, "demo_protected.pdf"), []byte("nope")); err != ErrNeedPassword {
		t.Fatalf("err = %v, want ErrNeedPassword", err)
	}
}

func TestBrokenXrefFixtures(t *testing.T) {
	for _, f := range []string{"pades_infinite_loop.pdf", "pades_opposite_infinite_loop.pdf"} {
		if _, err := Open(load(t, f), nil); !errors.Is(err, ErrBrokenXref) {
			t.Errorf("%s: err = %v, want ErrBrokenXref", f, err)
		}
	}
}

// TestPrevLoop builds a file whose /Prev points to itself.
func TestPrevLoop(t *testing.T) {
	body := "%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 200]>>\nendobj\n"
	off := len(body)
	x := fmt.Sprintf("xref\n0 4\n0000000000 65535 f\r\n%010d 00000 n\r\n%010d 00000 n\r\n%010d 00000 n\r\ntrailer\n<</Size 4/Root 1 0 R/Prev %d>>\nstartxref\n%d\n%%%%EOF\n",
		9, strings.Index(body, "2 0 obj"), strings.Index(body, "3 0 obj"), off, off)
	r, err := Open([]byte(body+x), nil)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := r.Pages()
	if err != nil || len(pages) != 1 || pages[0].MediaBox[3] != 200 {
		t.Fatalf("pages=%v err=%v", pages, err)
	}
}
