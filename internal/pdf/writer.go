package pdf

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
)

// ContentsPlaceholder serializes as a hex string of Size zero bytes and
// records its position so the signature can be patched in later.
type ContentsPlaceholder struct {
	ID   string
	Size int // bytes (the hex string has 2*Size digits)
}

// ByteRangePlaceholder serializes as an array of spaces wide enough for four
// int64 values and records its position.
type ByteRangePlaceholder struct {
	ID string
}

// byteRangeWidth is the number of characters between '[' and ']' reserved
// for a /ByteRange array: 4 values of up to 19 digits plus separators.
const byteRangeWidth = 4*19 + 3

// Span is a half-open byte interval [Start, End) in the output.
type Span struct{ Start, End int64 }

// Writer appends an incremental update to an existing document.
type Writer struct {
	r       *Reader
	rand    io.Reader
	objs    map[uint32]Object
	gens    map[uint32]uint16
	nextNum uint32

	// ID1 overrides the generated second /ID element.
	ID1 []byte
	// ForceClassicXref writes a classic xref table even if the source used
	// an xref stream.
	ForceClassicXref bool

	spans map[string]Span
}

// NewWriter creates an incremental writer on top of r. rnd supplies AES
// initialization vectors and must not be nil for encrypted documents.
func NewWriter(r *Reader, rnd io.Reader) *Writer {
	return &Writer{
		r:       r,
		rand:    rnd,
		objs:    map[uint32]Object{},
		gens:    map[uint32]uint16{},
		nextNum: r.Size(),
	}
}

// Reader returns the underlying reader.
func (w *Writer) Reader() *Reader { return w.r }

// NewRef allocates a new object number.
func (w *Writer) NewRef() Ref {
	ref := Ref{Num: w.nextNum}
	w.nextNum++
	return ref
}

// Set adds a new object or replaces an existing one.
func (w *Writer) Set(ref Ref, obj Object) {
	w.objs[ref.Num] = obj
	w.gens[ref.Num] = ref.Gen
}

// Get returns an object from the pending update, or from the reader.
func (w *Writer) Get(ref Ref) (Object, error) {
	if o, ok := w.objs[ref.Num]; ok {
		return o, nil
	}
	return w.r.GetObject(ref)
}

// Resolve resolves references against pending objects first.
func (w *Writer) Resolve(o Object) (Object, error) {
	for i := 0; i < 32; i++ {
		ref, ok := o.(Ref)
		if !ok {
			return o, nil
		}
		var err error
		if o, err = w.Get(ref); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("pdf: reference chain too long")
}

// Spans returns the recorded placeholder positions after Write.
func (w *Writer) Spans() map[string]Span { return w.spans }

// Write produces the original document followed by the incremental update.
func (w *Writer) Write() ([]byte, error) {
	orig := w.r.Data()
	var out bytes.Buffer
	out.Grow(len(orig) + 64<<10)
	out.Write(orig)
	if n := len(orig); n > 0 && orig[n-1] != '\n' && orig[n-1] != '\r' {
		out.WriteByte('\n')
	}
	w.spans = map[string]Span{}

	nums := make([]uint32, 0, len(w.objs))
	for n := range w.objs {
		nums = append(nums, n)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })

	offsets := map[uint32]int64{}
	for _, n := range nums {
		ref := Ref{Num: n, Gen: w.gens[n]}
		offsets[n] = int64(out.Len())
		fmt.Fprintf(&out, "%d %d obj\n", ref.Num, ref.Gen)
		if err := w.writeObject(&out, w.objs[n], ref, true); err != nil {
			return nil, fmt.Errorf("pdf: writing object %v: %w", ref, err)
		}
		out.WriteString("\nendobj\n")
	}

	trailer := Dict{}
	trailer["Root"] = w.r.Trailer()["Root"]
	if info, ok := w.r.Trailer()["Info"]; ok {
		trailer["Info"] = info
	}
	if enc, ok := w.r.Trailer()["Encrypt"]; ok {
		trailer["Encrypt"] = enc
	}
	if id := w.id(); id != nil {
		trailer["ID"] = id
	}
	trailer["Prev"] = Integer(w.r.LastXref)

	useStream := w.r.LastXrefIsStream && !w.ForceClassicXref
	xrefOff := int64(out.Len())
	if useStream {
		xref := w.NewRef()
		offsets[xref.Num] = xrefOff
		nums = append(nums, xref.Num)
		size := w.nextNum
		trailer["Size"] = Integer(size)
		maxOff := xrefOff
		width := 4
		if maxOff > math.MaxUint32 {
			width = 8
		}
		var data bytes.Buffer
		idx := Array{}
		for _, run := range runs(nums) {
			idx = append(idx, Integer(run[0]), Integer(run[1]))
			for n := run[0]; n < run[0]+run[1]; n++ {
				data.WriteByte(1)
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], uint64(offsets[n]))
				data.Write(b[8-width:])
				g := w.gens[n]
				data.Write([]byte{byte(g >> 8), byte(g)})
			}
		}
		d := trailer
		d["Type"] = Name("XRef")
		d["W"] = Array{Integer(1), Integer(width), Integer(2)}
		d["Index"] = idx
		d["Filter"] = Name("FlateDecode")
		s := &Stream{Dict: d, Data: FlateEncode(data.Bytes())}
		fmt.Fprintf(&out, "%d 0 obj\n", xref.Num)
		if err := w.writeObject(&out, s, xref, false); err != nil {
			return nil, err
		}
		out.WriteString("\nendobj\n")
	} else {
		trailer["Size"] = Integer(w.nextNum)
		out.WriteString("xref\n")
		for _, run := range runs(nums) {
			fmt.Fprintf(&out, "%d %d\n", run[0], run[1])
			for n := run[0]; n < run[0]+run[1]; n++ {
				fmt.Fprintf(&out, "%010d %05d n\r\n", offsets[n], w.gens[n])
			}
		}
		out.WriteString("trailer\n")
		if err := w.writeObject(&out, trailer, Ref{}, false); err != nil {
			return nil, err
		}
		out.WriteString("\n")
	}
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", xrefOff)
	return out.Bytes(), nil
}

// runs groups sorted object numbers into [start, count] subsections.
func runs(nums []uint32) [][2]uint32 {
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	var out [][2]uint32
	for _, n := range nums {
		if k := len(out); k > 0 && out[k-1][0]+out[k-1][1] == n {
			out[k-1][1]++
			continue
		}
		out = append(out, [2]uint32{n, 1})
	}
	return out
}

// id returns the /ID array for the update: keep ID[0], regenerate ID[1].
// Encrypted files without /ID never get one (it would change the key).
func (w *Writer) id() Array {
	var id0 []byte
	if a, ok := w.r.Trailer()["ID"].(Array); ok && len(a) > 0 {
		if s, ok := a[0].(*String); ok {
			id0 = s.Bytes
		}
	}
	if id0 == nil && w.r.Crypt() != nil {
		return nil
	}
	id1 := w.ID1
	if id1 == nil {
		h := md5.New()
		var b [16]byte
		if w.rand != nil {
			io.ReadFull(w.rand, b[:])
		}
		h.Write(b[:])
		fmt.Fprintf(h, "%d", len(w.r.Data()))
		id1 = h.Sum(nil)
	}
	if id0 == nil {
		id0 = id1
	}
	return Array{
		&String{Bytes: id0, Hex: true, NoEncrypt: true},
		&String{Bytes: id1, Hex: true, NoEncrypt: true},
	}
}

func (w *Writer) encrypting(ref Ref) bool {
	c := w.r.Crypt()
	if c == nil || ref.Num == 0 {
		return false
	}
	if er := w.r.EncryptRef(); er != nil && er.Num == ref.Num {
		return false
	}
	return true
}

// writeObject serializes o. top indicates o is the value of indirect object
// ref and may be encrypted.
func (w *Writer) writeObject(out *bytes.Buffer, o Object, ref Ref, top bool) error {
	enc := top && w.encrypting(ref)
	return w.serialize(out, o, ref, enc, 0)
}

func (w *Writer) serialize(out *bytes.Buffer, o Object, ref Ref, enc bool, depth int) error {
	if depth > maxDepth {
		return errors.New("pdf: object nesting too deep")
	}
	switch v := o.(type) {
	case nil, Null:
		out.WriteString("null")
	case Boolean:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case Integer:
		out.WriteString(strconv.FormatInt(int64(v), 10))
	case Real:
		out.WriteString(FormatReal(float64(v)))
	case Name:
		writeName(out, v)
	case *String:
		b := v.Bytes
		hex := v.Hex
		if enc && !v.NoEncrypt {
			var err error
			b, err = w.r.Crypt().Encrypt(ref.Num, ref.Gen, b, false, w.rand)
			if err != nil {
				return err
			}
			hex = true
		}
		if hex {
			writeHex(out, b)
		} else {
			writeLiteral(out, b)
		}
	case Ref:
		fmt.Fprintf(out, "%d %d R", v.Num, v.Gen)
	case Array:
		out.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				out.WriteByte(' ')
			}
			if err := w.serialize(out, e, ref, enc, depth+1); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case Dict:
		out.WriteString("<<")
		for _, k := range v.SortedKeys() {
			writeName(out, k)
			out.WriteByte(' ')
			if err := w.serialize(out, v[k], ref, enc, depth+1); err != nil {
				return err
			}
		}
		out.WriteString(">>")
	case *Stream:
		if depth > 0 {
			return errors.New("pdf: stream must be an indirect object")
		}
		data := v.Data
		d := v.Dict.Clone()
		if enc && d.Name("Type") != "XRef" && !hasIdentityCrypt(d) &&
			!(d.Name("Type") == "Metadata" && !w.r.Crypt().EncryptMetadata()) {
			var err error
			data, err = w.r.Crypt().Encrypt(ref.Num, ref.Gen, data, true, w.rand)
			if err != nil {
				return err
			}
		}
		d["Length"] = Integer(len(data))
		if err := w.serialize(out, d, ref, enc, depth+1); err != nil {
			return err
		}
		out.WriteString("\nstream\n")
		out.Write(data)
		out.WriteString("\nendstream")
	case ContentsPlaceholder:
		start := int64(out.Len())
		out.WriteByte('<')
		out.Write(bytes.Repeat([]byte("0"), 2*v.Size))
		out.WriteByte('>')
		w.spans[v.ID] = Span{start, int64(out.Len())}
	case ByteRangePlaceholder:
		start := int64(out.Len())
		out.WriteByte('[')
		out.Write(bytes.Repeat([]byte(" "), byteRangeWidth))
		out.WriteByte(']')
		w.spans[v.ID] = Span{start, int64(out.Len())}
	case RawBytes:
		out.Write(v)
	default:
		return fmt.Errorf("pdf: cannot serialize %T", o)
	}
	return nil
}

// RawBytes is written verbatim (used for pre-serialized content).
type RawBytes []byte

// FormatReal formats a real number with at most 6 decimals, no exponent.
func FormatReal(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "0"
	}
	s := strconv.FormatFloat(f, 'f', 6, 64)
	s = trimZeros(s)
	if s == "-0" {
		return "0"
	}
	return s
}

func trimZeros(s string) string {
	if !bytes.ContainsRune([]byte(s), '.') {
		return s
	}
	for len(s) > 0 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

func writeName(out *bytes.Buffer, n Name) {
	out.WriteByte('/')
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c < 0x21 || c > 0x7e || c == '#' || isDelim(c) {
			fmt.Fprintf(out, "#%02X", c)
		} else {
			out.WriteByte(c)
		}
	}
}

func writeHex(out *bytes.Buffer, b []byte) {
	const digits = "0123456789ABCDEF"
	out.WriteByte('<')
	for _, c := range b {
		out.WriteByte(digits[c>>4])
		out.WriteByte(digits[c&15])
	}
	out.WriteByte('>')
}

func writeLiteral(out *bytes.Buffer, b []byte) {
	out.WriteByte('(')
	for _, c := range b {
		switch c {
		case '(', ')', '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case '\r':
			out.WriteString(`\r`)
		case '\n':
			out.WriteString(`\n`)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte(')')
}

// SerializeDirect serializes o without encryption (for content streams).
func SerializeDirect(o Object) ([]byte, error) {
	w := &Writer{r: &Reader{}, spans: map[string]Span{}}
	var b bytes.Buffer
	if err := w.serialize(&b, o, Ref{}, false, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// PatchByteRange writes "0 a b c" into the reserved /ByteRange span.
func PatchByteRange(doc []byte, span Span, br [4]int64) error {
	s := fmt.Sprintf("%d %d %d %d", br[0], br[1], br[2], br[3])
	if len(s) > byteRangeWidth {
		return errors.New("pdf: byte range does not fit placeholder")
	}
	inner := doc[span.Start+1 : span.End-1]
	copy(inner, s)
	for i := len(s); i < len(inner); i++ {
		inner[i] = ' '
	}
	return nil
}
