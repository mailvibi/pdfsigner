package pdf

import (
	"errors"
	"fmt"
)

// Page describes one page of the document.
type Page struct {
	Ref      Ref
	Dict     Dict
	MediaBox [4]float64
	CropBox  [4]float64
	Rotate   int
}

// Pages returns all pages in document order, applying inherited attributes.
func (r *Reader) Pages() ([]Page, error) {
	cat, _, err := r.Catalog()
	if err != nil {
		return nil, err
	}
	root, ok := cat["Pages"].(Ref)
	if !ok {
		return nil, errors.New("pdf: catalog /Pages is not a reference")
	}
	var pages []Page
	visited := map[uint32]bool{}
	type inh struct {
		media, crop Object
		rotate      Object
	}
	var walk func(ref Ref, in inh, depth int) error
	walk = func(ref Ref, in inh, depth int) error {
		if depth > 64 || visited[ref.Num] {
			return errors.New("pdf: page tree cycle or too deep")
		}
		visited[ref.Num] = true
		d := r.ResolveDict(ref)
		if d == nil {
			return fmt.Errorf("pdf: page tree node %v is not a dictionary", ref)
		}
		if v, ok := d["MediaBox"]; ok {
			in.media = v
		}
		if v, ok := d["CropBox"]; ok {
			in.crop = v
		}
		if v, ok := d["Rotate"]; ok {
			in.rotate = v
		}
		kids, hasKids := d["Kids"]
		if d.Name("Type") == "Page" || (!hasKids && d.Name("Type") != "Pages") {
			p := Page{Ref: ref, Dict: d}
			mb, ok := r.rect(in.media)
			if !ok {
				mb = [4]float64{0, 0, 612, 792}
			}
			p.MediaBox = mb
			if cb, ok := r.rect(in.crop); ok {
				p.CropBox = intersect(cb, mb)
			} else {
				p.CropBox = mb
			}
			if rot, ok := r.ResolveInt(in.rotate); ok {
				p.Rotate = int(((rot % 360) + 360) % 360)
			}
			pages = append(pages, p)
			return nil
		}
		for _, k := range r.ResolveArray(kids) {
			kr, ok := k.(Ref)
			if !ok {
				continue
			}
			if err := walk(kr, in, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, inh{}, 0); err != nil {
		return nil, err
	}
	return pages, nil
}

func (r *Reader) rect(o Object) ([4]float64, bool) {
	a := r.ResolveArray(o)
	if len(a) != 4 {
		return [4]float64{}, false
	}
	var out [4]float64
	for i, v := range a {
		rv, err := r.Resolve(v)
		if err != nil {
			return out, false
		}
		f, ok := Number(rv)
		if !ok {
			return out, false
		}
		out[i] = f
	}
	if out[0] > out[2] {
		out[0], out[2] = out[2], out[0]
	}
	if out[1] > out[3] {
		out[1], out[3] = out[3], out[1]
	}
	return out, true
}

func intersect(a, b [4]float64) [4]float64 {
	return [4]float64{max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])}
}
