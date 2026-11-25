// Package pdfcrypt implements the PDF Standard security handler
// (ISO 32000-1 7.6.3, ISO 32000-2 7.6.4): revisions 2-6, RC4 and AES.
package pdfcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// Crypt filter methods.
const (
	MethodIdentity = "Identity" // no encryption
	MethodRC4      = "V2"
	MethodAESV2    = "AESV2"
	MethodAESV3    = "AESV3"
)

var (
	// ErrBadPassword means neither the user nor owner password matched.
	ErrBadPassword = errors.New("pdfcrypt: incorrect password")
	// ErrUnsupported is returned for unsupported handler parameters.
	ErrUnsupported = errors.New("pdfcrypt: unsupported encryption")
)

// Params are the values of a Standard security handler /Encrypt dictionary
// with crypt filters already resolved to methods.
type Params struct {
	V, R, Length    int // Length in bits
	O, U, OE, UE    []byte
	Perms           []byte
	P               int32
	StrMethod       string
	StmMethod       string
	EncryptMetadata bool
	ID0             []byte
}

// Handler holds the file key after successful authentication.
type Handler struct {
	p     Params
	key   []byte
	owner bool
}

// Owner reports whether the owner password was supplied (full access).
func (h *Handler) Owner() bool { return h.owner }

// P returns the permission flags.
func (h *Handler) P() int32 { return h.p.P }

// R returns the security handler revision.
func (h *Handler) R() int { return h.p.R }

// EncryptMetadata reports whether metadata streams are encrypted.
func (h *Handler) EncryptMetadata() bool { return h.p.EncryptMetadata }

// Permitted reports whether permission bit n (1-based, as in Table 22) is set
// or the owner password was used.
func (h *Handler) Permitted(bit uint) bool {
	if h.owner {
		return true
	}
	return h.p.P&(1<<(bit-1)) != 0
}

var padding = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

func pad(pw []byte) []byte {
	out := make([]byte, 32)
	n := copy(out, pw)
	copy(out[n:], padding)
	return out
}

// Authenticate tries password as the owner password first, then as the user
// password, and returns a Handler with the derived file key.
func Authenticate(p Params, password []byte) (*Handler, error) {
	switch {
	case p.R >= 2 && p.R <= 4:
		if p.R == 2 {
			p.Length = 40
		}
		if p.Length == 0 {
			p.Length = 40
		}
		if p.Length < 40 || p.Length > 128 || p.Length%8 != 0 {
			return nil, fmt.Errorf("%w: key length %d", ErrUnsupported, p.Length)
		}
		if len(p.O) < 32 || len(p.U) < 32 {
			return nil, fmt.Errorf("%w: short /O or /U", ErrUnsupported)
		}
		if upw, ok := ownerToUser(p, password); ok {
			if key, ok := checkUser(p, upw); ok {
				return &Handler{p: p, key: key, owner: true}, nil
			}
		}
		if key, ok := checkUser(p, password); ok {
			return &Handler{p: p, key: key}, nil
		}
		return nil, ErrBadPassword
	case p.R == 5 || p.R == 6:
		if len(p.O) < 48 || len(p.U) < 48 || len(p.OE) < 32 || len(p.UE) < 32 {
			return nil, fmt.Errorf("%w: short /O /U /OE /UE", ErrUnsupported)
		}
		pw := password
		if len(pw) > 127 {
			pw = pw[:127]
		}
		h := func(salt, udata []byte) []byte { return hashR56(p.R, pw, salt, udata) }
		if bytes.Equal(h(p.O[32:40], p.U[:48]), p.O[:32]) {
			key, err := aesUnwrap(h(p.O[40:48], p.U[:48]), p.OE[:32])
			if err != nil {
				return nil, err
			}
			return &Handler{p: p, key: key, owner: true}, nil
		}
		if bytes.Equal(h(p.U[32:40], nil), p.U[:32]) {
			key, err := aesUnwrap(h(p.U[40:48], nil), p.UE[:32])
			if err != nil {
				return nil, err
			}
			return &Handler{p: p, key: key}, nil
		}
		return nil, ErrBadPassword
	}
	return nil, fmt.Errorf("%w: revision %d", ErrUnsupported, p.R)
}

// fileKeyR4 implements Algorithm 2.
func fileKeyR4(p Params, pw []byte) []byte {
	n := p.Length / 8
	m := md5.New()
	m.Write(pad(pw))
	m.Write(p.O[:32])
	var pb [4]byte
	binary.LittleEndian.PutUint32(pb[:], uint32(p.P))
	m.Write(pb[:])
	m.Write(p.ID0)
	if p.R >= 4 && !p.EncryptMetadata {
		m.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	sum := m.Sum(nil)
	if p.R >= 3 {
		for i := 0; i < 50; i++ {
			s := md5.Sum(sum[:n])
			sum = s[:]
		}
	}
	return sum[:n]
}

// checkUser implements Algorithms 4/5 (user password check).
func checkUser(p Params, pw []byte) ([]byte, bool) {
	key := fileKeyR4(p, pw)
	if p.R == 2 {
		out := rc4Crypt(key, padding)
		return key, bytes.Equal(out, p.U[:32])
	}
	m := md5.New()
	m.Write(padding)
	m.Write(p.ID0)
	out := rc4Crypt(key, m.Sum(nil))
	for i := 1; i <= 19; i++ {
		out = rc4Crypt(xorKey(key, byte(i)), out)
	}
	return key, bytes.Equal(out[:16], p.U[:16])
}

// ownerToUser implements the first part of Algorithm 7: recover the padded
// user password from /O using the owner password.
func ownerToUser(p Params, opw []byte) ([]byte, bool) {
	n := p.Length / 8
	if p.R == 2 {
		n = 5
	}
	s := md5.Sum(pad(opw))
	sum := s[:]
	if p.R >= 3 {
		for i := 0; i < 50; i++ {
			s := md5.Sum(sum)
			sum = s[:]
		}
	}
	key := sum[:n]
	if p.R == 2 {
		return rc4Crypt(key, p.O[:32]), true
	}
	out := append([]byte(nil), p.O[:32]...)
	for i := 19; i >= 0; i-- {
		out = rc4Crypt(xorKey(key, byte(i)), out)
	}
	return out, true
}

func xorKey(key []byte, b byte) []byte {
	k := make([]byte, len(key))
	for i := range key {
		k[i] = key[i] ^ b
	}
	return k
}

func rc4Crypt(key, data []byte) []byte {
	c, err := rc4.NewCipher(key)
	if err != nil {
		panic(err) // key length is always valid here
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// hashR56 implements the R5 SHA-256 hash and the R6 Algorithm 2.B.
func hashR56(r int, pw, salt, udata []byte) []byte {
	h := sha256.New()
	h.Write(pw)
	h.Write(salt)
	h.Write(udata)
	k := h.Sum(nil)
	if r == 5 {
		return k
	}
	for round := 0; ; round++ {
		var k1 []byte
		unit := make([]byte, 0, len(pw)+len(k)+len(udata))
		unit = append(unit, pw...)
		unit = append(unit, k...)
		unit = append(unit, udata...)
		k1 = bytes.Repeat(unit, 64)
		block, _ := aes.NewCipher(k[:16])
		e := make([]byte, len(k1))
		cipher.NewCBCEncrypter(block, k[16:32]).CryptBlocks(e, k1)
		sum := 0
		for _, b := range e[:16] {
			sum += int(b)
		}
		var hh hash.Hash
		switch sum % 3 {
		case 0:
			hh = sha256.New()
		case 1:
			hh = sha512.New384()
		default:
			hh = sha512.New()
		}
		hh.Write(e)
		k = hh.Sum(nil)
		if round >= 63 && int(e[len(e)-1]) <= round+1-32 {
			break
		}
	}
	return k[:32]
}

func aesUnwrap(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 32)
	cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(out, data[:32])
	return out, nil
}

func (h *Handler) method(stream bool) string {
	if stream {
		return h.p.StmMethod
	}
	return h.p.StrMethod
}

func (h *Handler) objKey(num uint32, gen uint16, aesv2 bool) []byte {
	if h.p.R >= 5 {
		return h.key
	}
	m := md5.New()
	m.Write(h.key)
	m.Write([]byte{byte(num), byte(num >> 8), byte(num >> 16), byte(gen), byte(gen >> 8)})
	if aesv2 {
		m.Write([]byte("sAlT"))
	}
	n := len(h.key) + 5
	if n > 16 {
		n = 16
	}
	return m.Sum(nil)[:n]
}

// Decrypt decrypts a string (stream=false) or stream body of object num/gen.
func (h *Handler) Decrypt(num uint32, gen uint16, data []byte, stream bool) ([]byte, error) {
	switch m := h.method(stream); m {
	case MethodIdentity, "":
		return data, nil
	case MethodRC4:
		return rc4Crypt(h.objKey(num, gen, false), data), nil
	case MethodAESV2, MethodAESV3:
		key := h.objKey(num, gen, m == MethodAESV2)
		if len(data) == 0 {
			return data, nil
		}
		if len(data) < 16 || len(data)%16 != 0 {
			// Lenient: tolerate garbage rather than failing the whole document.
			if len(data) < 32 {
				return nil, errors.New("pdfcrypt: AES data too short")
			}
			data = data[:len(data)/16*16]
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data)-16)
		cipher.NewCBCDecrypter(block, data[:16]).CryptBlocks(out, data[16:])
		if n := len(out); n > 0 {
			padLen := int(out[n-1])
			if padLen >= 1 && padLen <= 16 && padLen <= n {
				out = out[:n-padLen]
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: crypt method %s", ErrUnsupported, m)
	}
}

// Encrypt encrypts a string or stream body for object num/gen. rnd supplies
// AES initialization vectors.
func (h *Handler) Encrypt(num uint32, gen uint16, data []byte, stream bool, rnd io.Reader) ([]byte, error) {
	switch m := h.method(stream); m {
	case MethodIdentity, "":
		return data, nil
	case MethodRC4:
		return rc4Crypt(h.objKey(num, gen, false), data), nil
	case MethodAESV2, MethodAESV3:
		key := h.objKey(num, gen, m == MethodAESV2)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		padLen := 16 - len(data)%16
		buf := make([]byte, 16+len(data)+padLen)
		if _, err := io.ReadFull(rnd, buf[:16]); err != nil {
			return nil, err
		}
		copy(buf[16:], data)
		for i := 16 + len(data); i < len(buf); i++ {
			buf[i] = byte(padLen)
		}
		cipher.NewCBCEncrypter(block, buf[:16]).CryptBlocks(buf[16:], buf[16:])
		return buf, nil
	default:
		return nil, fmt.Errorf("%w: crypt method %s", ErrUnsupported, m)
	}
}
