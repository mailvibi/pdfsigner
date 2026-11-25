package pdf

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
)

// ErrUnsupportedFilter is returned when a stream filter cannot be decoded.
var ErrUnsupportedFilter = errors.New("pdf: unsupported stream filter")

// maxDecoded bounds decompressed stream sizes to protect against zip bombs.
const maxDecoded = 256 << 20

// DecodeStream returns the fully decoded stream data. Only FlateDecode (with
// predictors) is supported, which is all the signer needs (xref and object
// streams).
func (r *Reader) DecodeStream(s *Stream) ([]byte, error) {
	filters, err := r.asArray(s.Dict["Filter"])
	if err != nil {
		return nil, err
	}
	parms, _ := r.asArray(s.Dict["DecodeParms"])
	data := s.Data
	for i, f := range filters {
		fn, ok := f.(Name)
		if !ok {
			return nil, fmt.Errorf("%w: filter is not a name", ErrUnsupportedFilter)
		}
		var parm Dict
		if i < len(parms) {
			if pd, err := r.Resolve(parms[i]); err == nil {
				parm, _ = pd.(Dict)
			}
		}
		switch fn {
		case "FlateDecode", "Fl":
			data, err = flateDecode(data)
			if err != nil {
				return nil, err
			}
			data, err = applyPredictor(data, parm)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedFilter, fn)
		}
	}
	return data, nil
}

// asArray resolves o and wraps a single object in an Array; nil -> empty.
func (r *Reader) asArray(o Object) (Array, error) {
	if o == nil {
		return nil, nil
	}
	v, err := r.Resolve(o)
	if err != nil {
		return nil, err
	}
	switch t := v.(type) {
	case Array:
		return t, nil
	case Null:
		return nil, nil
	}
	return Array{v}, nil
}

func flateDecode(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("pdf: flate: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxDecoded+1))
	if len(out) > maxDecoded {
		return nil, errors.New("pdf: flate: decoded stream too large")
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		// Many producers write truncated zlib streams; accept what we got.
		if len(out) == 0 {
			return nil, fmt.Errorf("pdf: flate: %w", err)
		}
	}
	return out, nil
}

// FlateEncode compresses data with zlib.
func FlateEncode(data []byte) []byte {
	var b bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&b, zlib.BestCompression)
	zw.Write(data)
	zw.Close()
	return b.Bytes()
}

func applyPredictor(data []byte, parm Dict) ([]byte, error) {
	if parm == nil {
		return data, nil
	}
	pred, _ := parm.Int("Predictor")
	if pred <= 1 {
		return data, nil
	}
	colors, ok := parm.Int("Colors")
	if !ok || colors < 1 {
		colors = 1
	}
	bpc, ok := parm.Int("BitsPerComponent")
	if !ok || bpc < 1 {
		bpc = 8
	}
	columns, ok := parm.Int("Columns")
	if !ok || columns < 1 {
		columns = 1
	}
	if colors > 32 || bpc > 16 || columns > 1<<24 {
		return nil, errors.New("pdf: predictor parameters out of range")
	}
	bpp := int((colors*bpc + 7) / 8)
	rowLen := int((colors*bpc*columns + 7) / 8)
	if pred == 2 {
		if bpc != 8 {
			return nil, errors.New("pdf: TIFF predictor only supported for 8 bpc")
		}
		out := append([]byte(nil), data...)
		for row := 0; row+rowLen <= len(out); row += rowLen {
			for i := bpp; i < rowLen; i++ {
				out[row+i] += out[row+i-bpp]
			}
		}
		return out, nil
	}
	if pred < 10 {
		return nil, fmt.Errorf("pdf: unsupported predictor %d", pred)
	}
	// PNG predictors: each row prefixed with a filter-type byte.
	var out []byte
	prev := make([]byte, rowLen)
	cur := make([]byte, rowLen)
	for pos := 0; pos < len(data); {
		ft := data[pos]
		pos++
		n := copy(cur, data[pos:])
		pos += n
		for i := n; i < rowLen; i++ {
			cur[i] = 0
		}
		switch ft {
		case 0:
		case 1:
			for i := bpp; i < rowLen; i++ {
				cur[i] += cur[i-bpp]
			}
		case 2:
			for i := 0; i < rowLen; i++ {
				cur[i] += prev[i]
			}
		case 3:
			for i := 0; i < rowLen; i++ {
				var left byte
				if i >= bpp {
					left = cur[i-bpp]
				}
				cur[i] += byte((int(left) + int(prev[i])) / 2)
			}
		case 4:
			for i := 0; i < rowLen; i++ {
				var a, c byte
				if i >= bpp {
					a = cur[i-bpp]
					c = prev[i-bpp]
				}
				cur[i] += paeth(a, prev[i], c)
			}
		default:
			return nil, fmt.Errorf("pdf: bad PNG predictor row filter %d", ft)
		}
		out = append(out, cur[:n]...)
		prev, cur = cur, prev
	}
	return out, nil
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
