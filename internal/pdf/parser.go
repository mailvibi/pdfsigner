package pdf

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// ErrSyntax is returned for malformed PDF syntax.
var ErrSyntax = errors.New("pdf: syntax error")

func syntaxErr(pos int, format string, args ...any) error {
	return fmt.Errorf("%w at offset %d: %s", ErrSyntax, pos, fmt.Sprintf(format, args...))
}

func isWhite(c byte) bool {
	switch c {
	case 0, '\t', '\n', '\f', '\r', ' ':
		return true
	}
	return false
}

func isDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func isRegular(c byte) bool { return !isWhite(c) && !isDelim(c) }

// keyword is a bare token such as obj, endobj, stream, R.
type keyword string

// lexer reads PDF tokens from a byte slice.
type lexer struct {
	data []byte
	pos  int
}

func (l *lexer) skipWS() {
	for l.pos < len(l.data) {
		c := l.data[l.pos]
		if isWhite(c) {
			l.pos++
			continue
		}
		if c == '%' {
			for l.pos < len(l.data) && l.data[l.pos] != '\r' && l.data[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		return
	}
}

// token returns the next token: Name, *String, Integer, Real, keyword, or a
// delimiter keyword "[", "]", "<<", ">>".
func (l *lexer) token() (any, error) {
	l.skipWS()
	if l.pos >= len(l.data) {
		return nil, syntaxErr(l.pos, "unexpected EOF")
	}
	start := l.pos
	c := l.data[l.pos]
	switch c {
	case '/':
		l.pos++
		var b []byte
		for l.pos < len(l.data) && isRegular(l.data[l.pos]) {
			ch := l.data[l.pos]
			if ch == '#' && l.pos+2 < len(l.data) {
				if v, err := strconv.ParseUint(string(l.data[l.pos+1:l.pos+3]), 16, 8); err == nil {
					b = append(b, byte(v))
					l.pos += 3
					continue
				}
			}
			b = append(b, ch)
			l.pos++
		}
		return Name(b), nil
	case '(':
		return l.literalString()
	case '<':
		if l.pos+1 < len(l.data) && l.data[l.pos+1] == '<' {
			l.pos += 2
			return keyword("<<"), nil
		}
		return l.hexString()
	case '>':
		if l.pos+1 < len(l.data) && l.data[l.pos+1] == '>' {
			l.pos += 2
			return keyword(">>"), nil
		}
		return nil, syntaxErr(start, "unexpected '>'")
	case '[', ']', '{', '}':
		l.pos++
		return keyword(string(c)), nil
	case ')':
		return nil, syntaxErr(start, "unexpected ')'")
	}
	for l.pos < len(l.data) && isRegular(l.data[l.pos]) {
		l.pos++
	}
	tok := l.data[start:l.pos]
	if num, ok := parseNumber(tok); ok {
		return num, nil
	}
	return keyword(tok), nil
}

func parseNumber(tok []byte) (Object, bool) {
	if len(tok) == 0 {
		return nil, false
	}
	dot := false
	for i, c := range tok {
		switch {
		case c >= '0' && c <= '9':
		case (c == '+' || c == '-') && i == 0:
		case c == '.' && !dot:
			dot = true
		default:
			return nil, false
		}
	}
	if !dot {
		v, err := strconv.ParseInt(string(tok), 10, 64)
		if err != nil {
			// Too large: treat as real.
			f, ferr := strconv.ParseFloat(string(tok), 64)
			if ferr != nil {
				return nil, false
			}
			return Real(f), true
		}
		return Integer(v), true
	}
	s := string(tok)
	if s == "." || s == "+." || s == "-." || s == "+" || s == "-" {
		return Real(0), true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, false
	}
	return Real(f), true
}

func (l *lexer) literalString() (any, error) {
	start := l.pos
	l.pos++ // (
	depth := 1
	var b []byte
	for l.pos < len(l.data) {
		c := l.data[l.pos]
		l.pos++
		switch c {
		case '(':
			depth++
			b = append(b, c)
		case ')':
			depth--
			if depth == 0 {
				return &String{Bytes: b}, nil
			}
			b = append(b, c)
		case '\\':
			if l.pos >= len(l.data) {
				return nil, syntaxErr(start, "unterminated string")
			}
			e := l.data[l.pos]
			l.pos++
			switch e {
			case 'n':
				b = append(b, '\n')
			case 'r':
				b = append(b, '\r')
			case 't':
				b = append(b, '\t')
			case 'b':
				b = append(b, '\b')
			case 'f':
				b = append(b, '\f')
			case '\r':
				if l.pos < len(l.data) && l.data[l.pos] == '\n' {
					l.pos++
				}
			case '\n':
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for k := 0; k < 2 && l.pos < len(l.data); k++ {
						d := l.data[l.pos]
						if d < '0' || d > '7' {
							break
						}
						v = v*8 + int(d-'0')
						l.pos++
					}
					b = append(b, byte(v))
				} else {
					b = append(b, e)
				}
			}
		default:
			b = append(b, c)
		}
	}
	return nil, syntaxErr(start, "unterminated string")
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func (l *lexer) hexString() (any, error) {
	start := l.pos
	l.pos++ // <
	var b []byte
	var hi byte
	half := false
	for l.pos < len(l.data) {
		c := l.data[l.pos]
		l.pos++
		if c == '>' {
			if half {
				b = append(b, hi<<4)
			}
			return &String{Bytes: b, Hex: true}, nil
		}
		if isWhite(c) {
			continue
		}
		v, ok := unhex(c)
		if !ok {
			return nil, syntaxErr(l.pos-1, "bad hex digit %q", c)
		}
		if half {
			b = append(b, hi<<4|v)
			half = false
		} else {
			hi = v
			half = true
		}
	}
	return nil, syntaxErr(start, "unterminated hex string")
}

// parser builds objects from tokens. It does not resolve references.
type parser struct {
	lex   lexer
	depth int
}

const maxDepth = 256

func newParser(data []byte, pos int) *parser {
	return &parser{lex: lexer{data: data, pos: pos}}
}

// object parses one direct object (and recognizes "N G R").
func (p *parser) object() (Object, error) {
	tok, err := p.lex.token()
	if err != nil {
		return nil, err
	}
	return p.objectFrom(tok)
}

func (p *parser) objectFrom(tok any) (Object, error) {
	switch t := tok.(type) {
	case Name, *String, Real:
		return t, nil
	case Integer:
		// Lookahead for "G R".
		save := p.lex.pos
		t2, err := p.lex.token()
		if err == nil {
			if g, ok := t2.(Integer); ok {
				t3, err := p.lex.token()
				if err == nil && t3 == keyword("R") && t >= 0 && g >= 0 && g <= 65535 {
					return Ref{Num: uint32(t), Gen: uint16(g)}, nil
				}
			}
		}
		p.lex.pos = save
		return t, nil
	case keyword:
		switch t {
		case "true":
			return Boolean(true), nil
		case "false":
			return Boolean(false), nil
		case "null":
			return Null{}, nil
		case "[":
			return p.array()
		case "<<":
			return p.dict()
		}
		return nil, syntaxErr(p.lex.pos, "unexpected keyword %q", string(t))
	}
	return nil, syntaxErr(p.lex.pos, "unexpected token")
}

func (p *parser) array() (Object, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxDepth {
		return nil, syntaxErr(p.lex.pos, "nesting too deep")
	}
	arr := Array{}
	for {
		tok, err := p.lex.token()
		if err != nil {
			return nil, err
		}
		if tok == keyword("]") {
			return arr, nil
		}
		o, err := p.objectFrom(tok)
		if err != nil {
			return nil, err
		}
		arr = append(arr, o)
	}
}

func (p *parser) dict() (Object, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxDepth {
		return nil, syntaxErr(p.lex.pos, "nesting too deep")
	}
	d := Dict{}
	for {
		tok, err := p.lex.token()
		if err != nil {
			return nil, err
		}
		if tok == keyword(">>") {
			return d, nil
		}
		k, ok := tok.(Name)
		if !ok {
			return nil, syntaxErr(p.lex.pos, "dictionary key is not a name")
		}
		vt, err := p.lex.token()
		if err != nil {
			return nil, err
		}
		if vt == keyword(">>") { // missing value: tolerate as null
			d[k] = Null{}
			return d, nil
		}
		v, err := p.objectFrom(vt)
		if err != nil {
			return nil, err
		}
		if _, isNull := v.(Null); !isNull {
			d[k] = v
		}
	}
}

// indirectHeader parses "N G obj" at the current position.
func (p *parser) indirectHeader() (Ref, error) {
	t1, err := p.lex.token()
	if err != nil {
		return Ref{}, err
	}
	t2, err := p.lex.token()
	if err != nil {
		return Ref{}, err
	}
	t3, err := p.lex.token()
	if err != nil {
		return Ref{}, err
	}
	n, ok1 := t1.(Integer)
	g, ok2 := t2.(Integer)
	if !ok1 || !ok2 || t3 != keyword("obj") || n < 0 || g < 0 || g > 65535 {
		return Ref{}, syntaxErr(p.lex.pos, "expected 'N G obj'")
	}
	return Ref{Num: uint32(n), Gen: uint16(g)}, nil
}

// streamStart checks for the "stream" keyword after a dictionary and returns
// the offset of the first data byte, or -1 if no stream follows.
func (p *parser) streamStart() int {
	save := p.lex.pos
	p.lex.skipWS()
	d := p.lex.data
	if bytes.HasPrefix(d[p.lex.pos:], []byte("stream")) {
		i := p.lex.pos + len("stream")
		if i < len(d) && d[i] == '\r' {
			i++
		}
		if i < len(d) && d[i] == '\n' {
			i++
		}
		return i
	}
	p.lex.pos = save
	return -1
}
