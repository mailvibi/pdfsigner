package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/mailvibi/pdfsigner/internal/pdfcrypt"
)

var (
	// ErrBrokenXref means the cross-reference data could not be read. The
	// signer refuses to repair files because an incremental update must chain
	// to a valid previous xref section.
	ErrBrokenXref = errors.New("pdf: broken cross-reference table")
	// ErrHeaderOffset means bytes precede the %PDF header.
	ErrHeaderOffset = errors.New("pdf: data before %PDF header is not supported")
	// ErrNeedPassword means the document is encrypted and the password
	// (including the empty password) did not open it.
	ErrNeedPassword = errors.New("pdf: document is encrypted; password required")
	// ErrUnsupportedEncryption is returned for non-Standard security handlers.
	ErrUnsupportedEncryption = errors.New("pdf: unsupported encryption handler")
)

type xrefEntry struct {
	typ byte   // 0 free, 1 in use, 2 compressed
	off int64  // type 1: byte offset; type 2: object stream number
	gen uint16 // type 1: generation; type 2: index in object stream
}

// Reader gives random access to the objects of a PDF file.
type Reader struct {
	data    []byte
	xref    map[uint32]xrefEntry
	trailer Dict

	// LastXref is the startxref value of the last section (the one an
	// incremental update must chain to with /Prev).
	LastXref int64
	// LastXrefIsStream is true if the last xref section is an xref stream.
	LastXrefIsStream bool
	// Version is the header version, e.g. "1.7".
	Version string
	// MaxObjNum is the largest object number seen in any xref section.
	MaxObjNum uint32

	cache   map[uint32]Object
	objStms map[uint32]map[uint32]Object // decoded object streams
	loading map[uint32]bool

	crypt      *pdfcrypt.Handler
	encryptRef *Ref
}

// Open parses data. If the document is encrypted, password (or, failing
// that, the empty password) is used to open it.
func Open(data []byte, password []byte) (*Reader, error) {
	r := &Reader{
		data:    data,
		xref:    map[uint32]xrefEntry{},
		cache:   map[uint32]Object{},
		objStms: map[uint32]map[uint32]Object{},
		loading: map[uint32]bool{},
	}
	if err := r.readHeader(); err != nil {
		return nil, err
	}
	if err := r.readXrefChain(); err != nil {
		return nil, err
	}
	if err := r.setupEncryption(password); err != nil {
		return nil, err
	}
	if _, ok := r.trailer["Root"].(Ref); !ok {
		return nil, fmt.Errorf("%w: trailer has no /Root reference", ErrBrokenXref)
	}
	return r, nil
}

// Data returns the underlying file bytes.
func (r *Reader) Data() []byte { return r.data }

// Trailer returns the merged trailer dictionary of the newest section.
func (r *Reader) Trailer() Dict { return r.trailer }

// Crypt returns the security handler, or nil if the file is not encrypted.
func (r *Reader) Crypt() *pdfcrypt.Handler { return r.crypt }

// EncryptRef returns the reference of the /Encrypt dictionary, if indirect.
func (r *Reader) EncryptRef() *Ref { return r.encryptRef }

// Size returns the number to use as the first new object number.
func (r *Reader) Size() uint32 {
	n, _ := r.trailer.Int("Size")
	if n < 0 {
		n = 0
	}
	s := uint32(n)
	if r.MaxObjNum+1 > s {
		s = r.MaxObjNum + 1
	}
	return s
}

func (r *Reader) readHeader() error {
	i := bytes.Index(r.data[:min(len(r.data), 1024)], []byte("%PDF-"))
	if i < 0 {
		return fmt.Errorf("%w: missing %%PDF header", ErrSyntax)
	}
	if i != 0 {
		return ErrHeaderOffset
	}
	v := r.data[5:]
	end := 0
	for end < len(v) && end < 4 && (v[end] == '.' || (v[end] >= '0' && v[end] <= '9')) {
		end++
	}
	r.Version = string(v[:end])
	return nil
}

func (r *Reader) findStartxref() (int64, error) {
	for window := 1024; ; window *= 4 {
		start := len(r.data) - window
		if start < 0 {
			start = 0
		}
		i := bytes.LastIndex(r.data[start:], []byte("startxref"))
		if i >= 0 {
			l := lexer{data: r.data, pos: start + i + len("startxref")}
			tok, err := l.token()
			if err != nil {
				return 0, fmt.Errorf("%w: %v", ErrBrokenXref, err)
			}
			n, ok := tok.(Integer)
			if !ok || n < 0 || int64(n) >= int64(len(r.data)) {
				return 0, fmt.Errorf("%w: bad startxref value", ErrBrokenXref)
			}
			return int64(n), nil
		}
		if start == 0 {
			return 0, fmt.Errorf("%w: startxref not found", ErrBrokenXref)
		}
	}
}

func (r *Reader) readXrefChain() error {
	off, err := r.findStartxref()
	if err != nil {
		return err
	}
	r.LastXref = off
	visited := map[int64]bool{}
	first := true
	for {
		if visited[off] {
			break // /Prev loop
		}
		visited[off] = true
		trailer, isStream, err := r.readXrefSection(off, visited)
		if err != nil {
			return err
		}
		if first {
			r.trailer = trailer
			r.LastXrefIsStream = isStream
			first = false
		}
		prev, ok := trailer["Prev"]
		if !ok {
			break
		}
		p, ok := Number(prev)
		if !ok || p < 0 || int64(p) >= int64(len(r.data)) {
			return fmt.Errorf("%w: bad /Prev", ErrBrokenXref)
		}
		off = int64(p)
	}
	return nil
}

// readXrefSection reads a classic table (plus its /XRefStm) or an xref stream
// at off, adding entries not already present (newer sections win).
func (r *Reader) readXrefSection(off int64, visited map[int64]bool) (Dict, bool, error) {
	l := lexer{data: r.data, pos: int(off)}
	l.skipWS()
	if bytes.HasPrefix(r.data[l.pos:], []byte("xref")) {
		l.pos += 4
		// Parse the table into a scratch map first so that, for hybrid
		// files, entries of the /XRefStm stream (which describe the
		// compressed objects the table marks free) take precedence.
		saved := r.xref
		r.xref = map[uint32]xrefEntry{}
		trailer, err := r.readClassicXref(&l)
		table := r.xref
		r.xref = saved
		if err != nil {
			return nil, false, err
		}
		if xs, ok := Number(trailer["XRefStm"]); ok && xs > 0 && int64(xs) < int64(len(r.data)) && !visited[int64(xs)] {
			visited[int64(xs)] = true
			// Stream entries for objects the table lists as in use are
			// overridden by the table below only if not already set.
			for num, e := range table {
				if e.typ == 1 {
					r.addEntry(num, e)
				}
			}
			if _, err := r.readXrefStream(int64(xs)); err != nil {
				return nil, false, err
			}
		}
		for num, e := range table {
			r.addEntry(num, e)
		}
		return trailer, false, nil
	}
	trailer, err := r.readXrefStream(off)
	if err != nil {
		return nil, false, err
	}
	return trailer, true, nil
}

func (r *Reader) addEntry(num uint32, e xrefEntry) {
	if num > r.MaxObjNum && e.typ != 0 {
		r.MaxObjNum = num
	}
	if _, ok := r.xref[num]; !ok {
		r.xref[num] = e
	}
}

func (r *Reader) readClassicXref(l *lexer) (Dict, error) {
	for {
		tok, err := l.token()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBrokenXref, err)
		}
		if tok == keyword("trailer") {
			p := &parser{lex: *l}
			t, err := p.object()
			if err != nil {
				return nil, fmt.Errorf("%w: trailer: %v", ErrBrokenXref, err)
			}
			d, ok := t.(Dict)
			if !ok {
				return nil, fmt.Errorf("%w: trailer is not a dictionary", ErrBrokenXref)
			}
			return d, nil
		}
		start, ok1 := tok.(Integer)
		ctok, err := l.token()
		count, ok2 := ctok.(Integer)
		if err != nil || !ok1 || !ok2 || start < 0 || count < 0 || count > 1<<24 {
			return nil, fmt.Errorf("%w: bad subsection header", ErrBrokenXref)
		}
		l.skipWS()
		type rawEnt struct {
			off int64
			gen int64
			typ byte
		}
		ents := make([]rawEnt, 0, count)
		for i := int64(0); i < int64(count); i++ {
			// Entries are "oooooooooo ggggg n" but tolerate odd whitespace.
			t1, e1 := l.token()
			t2, e2 := l.token()
			t3, e3 := l.token()
			o, okA := t1.(Integer)
			g, okB := t2.(Integer)
			k, okC := t3.(keyword)
			if e1 != nil || e2 != nil || e3 != nil || !okA || !okB || !okC || (k != "n" && k != "f") {
				return nil, fmt.Errorf("%w: bad entry in subsection starting %d", ErrBrokenXref, start)
			}
			typ := byte(1)
			if k == "f" {
				typ = 0
			}
			ents = append(ents, rawEnt{int64(o), int64(g), typ})
		}
		base := uint32(start)
		// Fix the common "subsection starts at 1 but should start at 0" bug:
		// first entry is a free 65535 entry.
		if base == 1 && len(ents) > 0 && ents[0].typ == 0 && ents[0].gen == 65535 {
			base = 0
		}
		for i, e := range ents {
			num := base + uint32(i)
			if e.typ == 1 {
				r.addEntry(num, xrefEntry{typ: 1, off: e.off, gen: uint16(e.gen)})
			} else {
				r.addEntry(num, xrefEntry{typ: 0})
			}
		}
	}
}

func (r *Reader) readXrefStream(off int64) (Dict, error) {
	ref, obj, err := r.parseIndirectAt(off)
	if err != nil {
		return nil, fmt.Errorf("%w: xref stream: %v", ErrBrokenXref, err)
	}
	s, ok := obj.(*Stream)
	if !ok || s.Dict.Name("Type") != "XRef" {
		return nil, fmt.Errorf("%w: not an xref stream at %d", ErrBrokenXref, off)
	}
	_ = ref
	data, err := r.DecodeStream(s)
	if err != nil {
		return nil, fmt.Errorf("%w: xref stream: %v", ErrBrokenXref, err)
	}
	wArr, ok := s.Dict["W"].(Array)
	if !ok || len(wArr) != 3 {
		return nil, fmt.Errorf("%w: bad /W", ErrBrokenXref)
	}
	var w [3]int
	for i := range w {
		v, ok := wArr[i].(Integer)
		if !ok || v < 0 || v > 8 {
			return nil, fmt.Errorf("%w: bad /W", ErrBrokenXref)
		}
		w[i] = int(v)
	}
	size, _ := s.Dict.Int("Size")
	var index []int64
	if idx, ok := s.Dict["Index"].(Array); ok {
		for _, v := range idx {
			n, ok := v.(Integer)
			if !ok {
				return nil, fmt.Errorf("%w: bad /Index", ErrBrokenXref)
			}
			index = append(index, int64(n))
		}
	} else {
		index = []int64{0, size}
	}
	rowLen := w[0] + w[1] + w[2]
	if rowLen == 0 {
		return nil, fmt.Errorf("%w: bad /W", ErrBrokenXref)
	}
	field := func(b []byte) int64 {
		var v int64
		for _, c := range b {
			v = v<<8 | int64(c)
		}
		return v
	}
	pos := 0
	for i := 0; i+1 < len(index); i += 2 {
		start, count := index[i], index[i+1]
		if start < 0 || count < 0 {
			return nil, fmt.Errorf("%w: bad /Index", ErrBrokenXref)
		}
		for j := int64(0); j < count; j++ {
			if pos+rowLen > len(data) {
				return nil, fmt.Errorf("%w: xref stream truncated", ErrBrokenXref)
			}
			row := data[pos : pos+rowLen]
			pos += rowLen
			typ := int64(1)
			if w[0] > 0 {
				typ = field(row[:w[0]])
			}
			f2 := field(row[w[0] : w[0]+w[1]])
			f3 := field(row[w[0]+w[1]:])
			num := uint32(start + j)
			switch typ {
			case 0:
				r.addEntry(num, xrefEntry{typ: 0})
			case 1:
				r.addEntry(num, xrefEntry{typ: 1, off: f2, gen: uint16(f3)})
			case 2:
				r.addEntry(num, xrefEntry{typ: 2, off: f2, gen: uint16(f3)})
			}
		}
	}
	trailer := s.Dict.Clone()
	return trailer, nil
}

// parseIndirectAt parses "N G obj <object> [stream...] endobj" at off without
// decryption.
func (r *Reader) parseIndirectAt(off int64) (Ref, Object, error) {
	if off < 0 || off >= int64(len(r.data)) {
		return Ref{}, nil, fmt.Errorf("offset %d out of range", off)
	}
	p := newParser(r.data, int(off))
	ref, err := p.indirectHeader()
	if err != nil {
		return Ref{}, nil, err
	}
	obj, err := p.object()
	if err != nil {
		return Ref{}, nil, err
	}
	d, ok := obj.(Dict)
	if !ok {
		return ref, obj, nil
	}
	start := p.streamStart()
	if start < 0 {
		return ref, obj, nil
	}
	length := -1
	switch lv := d["Length"].(type) {
	case Integer:
		length = int(lv)
	case Ref:
		if lv != ref {
			if o, err := r.GetObject(lv); err == nil {
				if n, ok := o.(Integer); ok {
					length = int(n)
				}
			}
		}
	}
	end := -1
	if length >= 0 && start+length <= len(r.data) {
		// Verify endstream follows.
		l := lexer{data: r.data, pos: start + length}
		l.skipWS()
		if bytes.HasPrefix(r.data[l.pos:], []byte("endstream")) {
			end = start + length
		}
	}
	if end < 0 {
		i := bytes.Index(r.data[start:], []byte("endstream"))
		if i < 0 {
			return Ref{}, nil, syntaxErr(start, "endstream not found")
		}
		end = start + i
		// Strip the EOL preceding endstream.
		if end > start && r.data[end-1] == '\n' {
			end--
		}
		if end > start && r.data[end-1] == '\r' {
			end--
		}
	}
	return ref, &Stream{Dict: d, Data: r.data[start:end]}, nil
}

// GetObject returns the (decrypted) object with the given reference. Missing
// objects resolve to Null as the spec requires.
func (r *Reader) GetObject(ref Ref) (Object, error) {
	if o, ok := r.cache[ref.Num]; ok {
		return o, nil
	}
	e, ok := r.xref[ref.Num]
	if !ok || e.typ == 0 {
		return Null{}, nil
	}
	if r.loading[ref.Num] {
		return nil, fmt.Errorf("pdf: reference cycle while loading %v", ref)
	}
	r.loading[ref.Num] = true
	defer delete(r.loading, ref.Num)
	var obj Object
	switch e.typ {
	case 1:
		if e.gen != ref.Gen {
			return Null{}, nil
		}
		got, o, err := r.parseIndirectAt(e.off)
		if err != nil {
			return nil, fmt.Errorf("pdf: object %v: %w", ref, err)
		}
		if got.Num != ref.Num {
			return nil, fmt.Errorf("pdf: object %v: xref points to object %d", ref, got.Num)
		}
		obj = o
		if r.crypt != nil && !r.isEncryptDict(ref) {
			if err := r.decryptObject(obj, ref, true); err != nil {
				return nil, fmt.Errorf("pdf: object %v: %w", ref, err)
			}
		}
	case 2:
		objs, err := r.loadObjStm(uint32(e.off))
		if err != nil {
			return nil, err
		}
		obj, ok = objs[ref.Num]
		if !ok {
			obj = Null{}
		}
	}
	r.cache[ref.Num] = obj
	return obj, nil
}

// InObjStm reports whether object num is stored in an object stream.
func (r *Reader) InObjStm(num uint32) bool {
	e, ok := r.xref[num]
	return ok && e.typ == 2
}

// Generation returns the generation number of object num.
func (r *Reader) Generation(num uint32) uint16 {
	e := r.xref[num]
	if e.typ == 1 {
		return e.gen
	}
	return 0
}

func (r *Reader) isEncryptDict(ref Ref) bool {
	return r.encryptRef != nil && *r.encryptRef == ref
}

func (r *Reader) loadObjStm(num uint32) (map[uint32]Object, error) {
	if m, ok := r.objStms[num]; ok {
		return m, nil
	}
	o, err := r.GetObject(Ref{Num: num})
	if err != nil {
		return nil, err
	}
	s, ok := o.(*Stream)
	if !ok {
		return nil, fmt.Errorf("pdf: object stream %d is not a stream", num)
	}
	data, err := r.DecodeStream(s)
	if err != nil {
		return nil, fmt.Errorf("pdf: object stream %d: %w", num, err)
	}
	n, _ := s.Dict.Int("N")
	first, _ := s.Dict.Int("First")
	if n < 0 || n > 1<<20 || first < 0 || first > int64(len(data)) {
		return nil, fmt.Errorf("pdf: object stream %d: bad /N or /First", num)
	}
	l := lexer{data: data[:first]}
	type pair struct {
		num uint32
		off int64
	}
	pairs := make([]pair, 0, n)
	for i := int64(0); i < n; i++ {
		t1, err1 := l.token()
		t2, err2 := l.token()
		a, ok1 := t1.(Integer)
		b, ok2 := t2.(Integer)
		if err1 != nil || err2 != nil || !ok1 || !ok2 || a < 0 || b < 0 {
			return nil, fmt.Errorf("pdf: object stream %d: bad header", num)
		}
		pairs = append(pairs, pair{uint32(a), int64(b)})
	}
	m := map[uint32]Object{}
	for _, pr := range pairs {
		pos := first + pr.off
		if pos >= int64(len(data)) {
			continue
		}
		p := newParser(data, int(pos))
		obj, err := p.object()
		if err != nil {
			return nil, fmt.Errorf("pdf: object stream %d, object %d: %w", num, pr.num, err)
		}
		// Only accept if the xref says this object lives here.
		if e, ok := r.xref[pr.num]; ok && e.typ == 2 && uint32(e.off) == num {
			m[pr.num] = obj
		}
	}
	r.objStms[num] = m
	return m, nil
}

// Resolve follows references until a direct object is reached.
func (r *Reader) Resolve(o Object) (Object, error) {
	for i := 0; i < 32; i++ {
		ref, ok := o.(Ref)
		if !ok {
			return o, nil
		}
		var err error
		o, err = r.GetObject(ref)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("pdf: reference chain too long")
}

// ResolveDict resolves o and returns it as a Dict (nil if not a dict).
func (r *Reader) ResolveDict(o Object) Dict {
	v, err := r.Resolve(o)
	if err != nil {
		return nil
	}
	switch t := v.(type) {
	case Dict:
		return t
	case *Stream:
		return t.Dict
	}
	return nil
}

// ResolveArray resolves o and returns it as an Array (nil if not an array).
func (r *Reader) ResolveArray(o Object) Array {
	v, err := r.Resolve(o)
	if err != nil {
		return nil
	}
	a, _ := v.(Array)
	return a
}

// ResolveInt resolves o and returns it as an integer.
func (r *Reader) ResolveInt(o Object) (int64, bool) {
	v, err := r.Resolve(o)
	if err != nil {
		return 0, false
	}
	f, ok := Number(v)
	return int64(f), ok
}

// Catalog returns the document catalog.
func (r *Reader) Catalog() (Dict, Ref, error) {
	ref := r.trailer["Root"].(Ref)
	d := r.ResolveDict(ref)
	if d == nil {
		return nil, ref, errors.New("pdf: catalog is not a dictionary")
	}
	return d, ref, nil
}

func (r *Reader) setupEncryption(password []byte) error {
	enc, ok := r.trailer["Encrypt"]
	if !ok {
		return nil
	}
	if ref, ok := enc.(Ref); ok {
		r.encryptRef = &ref
	}
	// The encryption dictionary itself is never encrypted.
	d := r.ResolveDict(enc)
	if d == nil {
		return fmt.Errorf("%w: /Encrypt is not a dictionary", ErrUnsupportedEncryption)
	}
	if d.Name("Filter") != "Standard" {
		return fmt.Errorf("%w: /Filter /%s", ErrUnsupportedEncryption, d.Name("Filter"))
	}
	str := func(k Name) []byte {
		if s, ok := d[k].(*String); ok {
			return s.Bytes
		}
		return nil
	}
	v, _ := d.Int("V")
	rv, _ := d.Int("R")
	length, _ := d.Int("Length")
	p, _ := d.Int("P")
	params := pdfcrypt.Params{
		V: int(v), R: int(rv), Length: int(length),
		O: str("O"), U: str("U"), OE: str("OE"), UE: str("UE"), Perms: str("Perms"),
		P:               int32(p),
		EncryptMetadata: true,
	}
	if b, ok := d["EncryptMetadata"].(Boolean); ok {
		params.EncryptMetadata = bool(b)
	}
	if id, ok := r.trailer["ID"].(Array); ok && len(id) > 0 {
		if s, ok := id[0].(*String); ok {
			params.ID0 = s.Bytes
		}
	}
	switch v {
	case 1, 2:
		params.StrMethod, params.StmMethod = pdfcrypt.MethodRC4, pdfcrypt.MethodRC4
	case 4, 5:
		cf := r.ResolveDict(d["CF"])
		method := func(name Name) (string, error) {
			if name == "" || name == "Identity" {
				return pdfcrypt.MethodIdentity, nil
			}
			fd := r.ResolveDict(cf[name])
			if fd == nil {
				return "", fmt.Errorf("%w: crypt filter %s not found", ErrUnsupportedEncryption, name)
			}
			switch m := fd.Name("CFM"); m {
			case "None":
				return pdfcrypt.MethodIdentity, nil
			case "V2", "AESV2", "AESV3":
				if m == "V2" && v == 4 {
					if l, ok := fd.Int("Length"); ok && l > 0 {
						if l <= 16 {
							params.Length = int(l) * 8
						} else {
							params.Length = int(l)
						}
					}
				}
				return string(m), nil
			default:
				return "", fmt.Errorf("%w: crypt filter method %s", ErrUnsupportedEncryption, m)
			}
		}
		var err error
		if params.StrMethod, err = method(d.Name("StrF")); err != nil {
			return err
		}
		if params.StmMethod, err = method(d.Name("StmF")); err != nil {
			return err
		}
		if v == 4 && params.Length == 0 {
			params.Length = 128
		}
	default:
		return fmt.Errorf("%w: /V %d", ErrUnsupportedEncryption, v)
	}
	h, err := pdfcrypt.Authenticate(params, password)
	if errors.Is(err, pdfcrypt.ErrBadPassword) && len(password) > 0 {
		h, err = pdfcrypt.Authenticate(params, nil)
	}
	if errors.Is(err, pdfcrypt.ErrBadPassword) {
		return ErrNeedPassword
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedEncryption, err)
	}
	r.crypt = h
	// Drop anything cached before encryption was configured (the /Encrypt
	// dictionary itself is fine; xref streams are never encrypted).
	for k := range r.cache {
		if r.encryptRef == nil || k != r.encryptRef.Num {
			delete(r.cache, k)
		}
	}
	r.objStms = map[uint32]map[uint32]Object{}
	return nil
}

// decryptObject decrypts strings and stream data in place.
func (r *Reader) decryptObject(o Object, ref Ref, top bool) error {
	switch v := o.(type) {
	case *String:
		b, err := r.crypt.Decrypt(ref.Num, ref.Gen, v.Bytes, false)
		if err != nil {
			return err
		}
		v.Bytes = b
	case Array:
		for _, e := range v {
			if err := r.decryptObject(e, ref, false); err != nil {
				return err
			}
		}
	case Dict:
		for _, e := range v {
			if err := r.decryptObject(e, ref, false); err != nil {
				return err
			}
		}
	case *Stream:
		t := v.Dict.Name("Type")
		if t == "XRef" {
			return nil // xref streams are not encrypted
		}
		for _, e := range v.Dict {
			if err := r.decryptObject(e, ref, false); err != nil {
				return err
			}
		}
		if t == "Metadata" && !r.crypt.EncryptMetadata() {
			return nil
		}
		if hasIdentityCrypt(v.Dict) {
			return nil
		}
		b, err := r.crypt.Decrypt(ref.Num, ref.Gen, v.Data, true)
		if err != nil {
			return err
		}
		v.Data = b
	}
	return nil
}

func hasIdentityCrypt(d Dict) bool {
	f := d["Filter"]
	switch t := f.(type) {
	case Name:
		return t == "Crypt"
	case Array:
		for _, e := range t {
			if e == Name("Crypt") {
				return true
			}
		}
	}
	return false
}

// itoa is a small helper used by the serializer.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }
