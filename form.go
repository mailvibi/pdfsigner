package pdfsigner

import (
	"fmt"
	"strings"

	"github.com/mailvibi/pdfsigner/internal/pdf"
)

// formField is a terminal field of the AcroForm tree.
type formField struct {
	ref      pdf.Ref
	dict     pdf.Dict
	fullName string
	ft       pdf.Name // inherited /FT
	signed   bool     // has /V
	widgets  []pdf.Ref
}

// docInfo summarizes the signature-relevant state of a document.
type docInfo struct {
	fields     []formField
	signatures int
	docMDP     int // 0 if not certified
	xfaDynamic bool
	hasXFA     bool
	tagged     bool
	pdfA       bool
}

func analyze(r *pdf.Reader) (*docInfo, error) {
	cat, _, err := r.Catalog()
	if err != nil {
		return nil, err
	}
	info := &docInfo{}
	if b, ok := cat["NeedsRendering"].(pdf.Boolean); ok && bool(b) {
		info.xfaDynamic = true
	}
	if mi := r.ResolveDict(cat["MarkInfo"]); mi != nil {
		if b, ok := mi["Marked"].(pdf.Boolean); ok && bool(b) {
			info.tagged = true
		}
	}
	if md, err := r.Resolve(cat["Metadata"]); err == nil {
		if s, ok := md.(*pdf.Stream); ok {
			data, err := r.DecodeStream(s)
			if err != nil {
				data = s.Data
			}
			info.pdfA = strings.Contains(string(data), "pdfaid:part")
		}
	}
	if acro := r.ResolveDict(cat["AcroForm"]); acro != nil {
		if _, ok := acro["XFA"]; ok {
			info.hasXFA = true
		}
		visited := map[uint32]bool{}
		var walk func(o pdf.Object, parentName string, ft pdf.Name, depth int)
		walk = func(o pdf.Object, parentName string, ft pdf.Name, depth int) {
			ref, ok := o.(pdf.Ref)
			if !ok || depth > 32 || visited[ref.Num] {
				return
			}
			visited[ref.Num] = true
			d := r.ResolveDict(ref)
			if d == nil {
				return
			}
			name := parentName
			if t, ok := d["T"].(*pdf.String); ok {
				part := pdf.DecodeTextString(t.Bytes)
				if name != "" {
					name += "." + part
				} else {
					name = part
				}
			}
			if f := d.Name("FT"); f != "" {
				ft = f
			}
			// Kids that have /T are fields; kids without are widgets.
			var fieldKids, widgetKids []pdf.Ref
			for _, k := range r.ResolveArray(d["Kids"]) {
				kr, ok := k.(pdf.Ref)
				if !ok {
					continue
				}
				kd := r.ResolveDict(kr)
				if kd == nil {
					continue
				}
				if _, hasT := kd["T"]; hasT {
					fieldKids = append(fieldKids, kr)
				} else {
					widgetKids = append(widgetKids, kr)
				}
			}
			for _, k := range fieldKids {
				walk(k, name, ft, depth+1)
			}
			if len(fieldKids) > 0 && len(widgetKids) == 0 {
				return
			}
			f := formField{ref: ref, dict: d, fullName: name, ft: ft}
			if v, ok := d["V"]; ok {
				if _, isNull := v.(pdf.Null); !isNull {
					f.signed = ft == "Sig"
				}
			}
			if d.Name("Subtype") == "Widget" {
				f.widgets = append(f.widgets, ref)
			}
			f.widgets = append(f.widgets, widgetKids...)
			info.fields = append(info.fields, f)
			if f.signed {
				info.signatures++
			}
		}
		for _, f := range r.ResolveArray(acro["Fields"]) {
			walk(f, "", "", 0)
		}
	}
	if perms := r.ResolveDict(cat["Perms"]); perms != nil {
		if sig := r.ResolveDict(perms["DocMDP"]); sig != nil {
			info.docMDP = 2 // default P when absent
			for _, ref := range r.ResolveArray(sig["Reference"]) {
				rd := r.ResolveDict(ref)
				if rd == nil || rd.Name("TransformMethod") != "DocMDP" {
					continue
				}
				if tp := r.ResolveDict(rd["TransformParams"]); tp != nil {
					if p, ok := r.ResolveInt(tp["P"]); ok && p >= 1 && p <= 3 {
						info.docMDP = int(p)
					}
				}
			}
		}
	}
	return info, nil
}

func (d *docInfo) field(name string) *formField {
	for i := range d.fields {
		if d.fields[i].fullName == name {
			return &d.fields[i]
		}
	}
	return nil
}

// fieldNameTaken reports whether any field (terminal or not) uses name as
// its full name or as a prefix component.
func (d *docInfo) fieldNameTaken(name string) bool {
	for _, f := range d.fields {
		if f.fullName == name || strings.HasPrefix(f.fullName, name+".") {
			return true
		}
	}
	return false
}

func (d *docInfo) newFieldName() string {
	for i := 1; ; i++ {
		n := fmt.Sprintf("Signature%d", i)
		if !d.fieldNameTaken(n) {
			return n
		}
	}
}

// fieldLock returns the /Lock dictionary of a field, if any.
func fieldLock(r *pdf.Reader, f *formField) pdf.Dict {
	return r.ResolveDict(f.dict["Lock"])
}
