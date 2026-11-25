package pdf

import (
	"bytes"
	"fmt"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// pdfDocHigh maps PDFDocEncoding bytes 0x80..0x9F (others are Latin-1).
var pdfDocHigh = [32]rune{
	0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044,
	0x2039, 0x203A, 0x2212, 0x2030, 0x201E, 0x201C, 0x201D, 0x2018,
	0x2019, 0x201A, 0x2122, 0xFB01, 0xFB02, 0x0141, 0x0152, 0x0160,
	0x0178, 0x017D, 0x0131, 0x0142, 0x0153, 0x0161, 0x017E, 0xFFFD,
}

// DecodeTextString decodes a PDF text string (UTF-16BE with BOM, UTF-8 with
// BOM, or PDFDocEncoding).
func DecodeTextString(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
		return string(utf16.Decode(u))
	}
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{0xEF, 0xBB, 0xBF}) {
		return string(b[3:])
	}
	var s []rune
	for _, c := range b {
		switch {
		case c >= 0x80 && c <= 0x9F:
			s = append(s, pdfDocHigh[c-0x80])
		default:
			s = append(s, rune(c))
		}
	}
	return string(s)
}

// TextString encodes s as a PDF text string: plain bytes if it is
// printable ASCII, otherwise UTF-16BE with a byte order mark.
func TextString(s string) *String {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			ascii = false
			break
		}
	}
	if ascii && utf8.ValidString(s) {
		return &String{Bytes: []byte(s)}
	}
	b := []byte{0xFE, 0xFF}
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u>>8), byte(u))
	}
	return &String{Bytes: b}
}

// Date formats t as a PDF date string D:YYYYMMDDHHmmSS+HH'mm'.
func Date(t time.Time) *String {
	s := t.Format("D:20060102150405")
	_, off := t.Zone()
	if off == 0 {
		s += "Z"
	} else {
		sign := '+'
		if off < 0 {
			sign = '-'
			off = -off
		}
		s += fmt.Sprintf("%c%02d'%02d'", sign, off/3600, (off%3600)/60)
	}
	return &String{Bytes: []byte(s)}
}
