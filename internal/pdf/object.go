// Package pdf implements the minimal PDF object model, parser, cross-reference
// reader and incremental writer needed to sign PDF documents.
package pdf

import (
	"fmt"
	"sort"
)

// Object is any PDF object: Name, *String, Integer, Real, Boolean, Null,
// Array, Dict, Ref, *Stream, or one of the writer placeholders.
type Object any

// Name is a PDF name object without the leading slash.
type Name string

// String is a PDF string. Bytes holds the decoded (and decrypted) value.
type String struct {
	Bytes []byte
	// Hex selects hexadecimal serialization.
	Hex bool
	// NoEncrypt excludes this string from encryption on write
	// (signature /Contents).
	NoEncrypt bool
}

// NewString returns a literal string object.
func NewString(s string) *String { return &String{Bytes: []byte(s)} }

// NewHexString returns a hex string object.
func NewHexString(b []byte) *String { return &String{Bytes: b, Hex: true} }

// Integer is a PDF integer.
type Integer int64

// Real is a PDF real number.
type Real float64

// Boolean is a PDF boolean.
type Boolean bool

// Null is the PDF null object.
type Null struct{}

// Array is a PDF array.
type Array []Object

// Dict is a PDF dictionary.
type Dict map[Name]Object

// Ref is an indirect reference.
type Ref struct {
	Num uint32
	Gen uint16
}

func (r Ref) String() string { return fmt.Sprintf("%d %d R", r.Num, r.Gen) }

// Stream is a PDF stream. Data holds the raw stream bytes as stored in the
// file (still filter-encoded) but already decrypted.
type Stream struct {
	Dict Dict
	Data []byte
}

// SortedKeys returns the dictionary keys in sorted order.
func (d Dict) SortedKeys() []Name {
	keys := make([]Name, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// Clone returns a shallow copy of d.
func (d Dict) Clone() Dict {
	c := make(Dict, len(d))
	for k, v := range d {
		c[k] = v
	}
	return c
}

// Name returns d[k] as a Name, or "".
func (d Dict) Name(k Name) Name {
	n, _ := d[k].(Name)
	return n
}

// Int returns d[k] as an int64 if it is a direct integer.
func (d Dict) Int(k Name) (int64, bool) {
	switch v := d[k].(type) {
	case Integer:
		return int64(v), true
	case Real:
		return int64(v), true
	}
	return 0, false
}

// DeepCopy copies arrays and dictionaries recursively (strings and streams
// are copied shallowly except for *String which is duplicated).
func DeepCopy(o Object) Object {
	switch v := o.(type) {
	case Dict:
		c := make(Dict, len(v))
		for k, e := range v {
			c[k] = DeepCopy(e)
		}
		return c
	case Array:
		c := make(Array, len(v))
		for i, e := range v {
			c[i] = DeepCopy(e)
		}
		return c
	case *String:
		s := *v
		s.Bytes = append([]byte(nil), v.Bytes...)
		return &s
	case *Stream:
		return &Stream{Dict: DeepCopy(v.Dict).(Dict), Data: v.Data}
	}
	return o
}

// Number returns o as float64 if it is numeric.
func Number(o Object) (float64, bool) {
	switch v := o.(type) {
	case Integer:
		return float64(v), true
	case Real:
		return float64(v), true
	}
	return 0, false
}
