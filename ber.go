package pkcs7

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
	TagBytes() []byte
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) TagBytes() []byte {
	return s.tagBytes
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	inner := new(bytes.Buffer)
	for _, obj := range s.content {
		err := obj.EncodeTo(inner)
		if err != nil {
			return err
		}
	}
	out.Write(s.tagBytes)
	encodeLength(out, inner.Len())
	out.Write(inner.Bytes())
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (s asn1Primitive) TagBytes() []byte {
	return s.tagBytes
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	out.Write(p.content)

	return nil
}

func ber2der(data []byte) ([]byte, error) {
	out := new(bytes.Buffer)

	obj, err := readObject(bytes.NewReader(data), 0)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("error to parse BER")
	}
	if isEndOfContents(obj) {
		return nil, errors.New("ber2der: unexpected end-of-contents octets")
	}
	obj.EncodeTo(out)

	return out.Bytes(), nil
}

// encodes lengths that are longer than 127 into string of bytes
func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

// computes the byte length of an encoded length value
func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//  length | byte 1 | bytes n
//  0      | 0x00   | -
//  120    | 0x78   | -
//  200    | 0x81   | 0xC8
//  500    | 0x82   | 0x01 0xF4
//
func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

// maxBERNesting limits how deeply constructed values may nest. Real CMS
// structures stay well below it. The limit keeps hostile input from
// overflowing the stack and bounds the content copied per nesting level.
const maxBERNesting = 64

// isEndOfContents reports whether obj is the end-of-contents octets (00 00).
// readObject rejects tag 0 with content, so this is the only tag-0 value that
// can reach it. Outside an indefinite-length value it is an error.
func isEndOfContents(obj asn1Object) bool {
	po, ok := obj.(asn1Primitive)
	return ok && po.length == 0 && po.tagBytes[0] == 0
}

// readObject reads one BER value from r. depth is the number of constructed
// values enclosing it.
func readObject(r *bytes.Reader, depth int) (obj asn1Object, err error) {
	var tagB byte
	if tagB, err = r.ReadByte(); err != nil {
		return
	}

	primitive := tagB&0x20 == 0

	var l byte
	if l, err = r.ReadByte(); err != nil {
		return nil, fmt.Errorf("end of ber data reached")
	}
	length := (int)(l & 0x7F)
	// A definite length of zero (0x00) is an empty value, not the indefinite
	// form (0x80).
	indefinite := false
	if l == 0x80 {
		if primitive {
			// X.690 8.1.3.2: the indefinite form is only allowed for
			// constructed encodings.
			return nil, errors.New("ber2der: indefinite length on primitive tag")
		}
		indefinite = true
	} else if l > 0x80 {
		numberOfBytes := length
		length = 0
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, errors.New("ber2der: BER tag length too long")
		}
		for i := 0; i < numberOfBytes; i++ {
			var sl byte
			if sl, err = r.ReadByte(); err != nil {
				return nil, fmt.Errorf("length is more than available data")
			}
			if i == 0 {
				if numberOfBytes == 4 && (int)(sl) > 0x7F {
					return nil, errors.New("ber2der: BER tag length is negative")
				}
				if 0x0 == (int)(sl) {
					return nil, errors.New("ber2der: BER tag length has leading zero")
				}
			}
			length = length*256 + (int)(sl)
		}
	}

	if tagB == 0 && length != 0 {
		// Tag 0 is only valid as the end-of-contents octets (X.690 8.1.5).
		return nil, errors.New("ber2der: tag 0 with content")
	}

	if primitive {
		// Check the declared length against the remaining input before
		// allocating, so a hostile length cannot force a large allocation.
		if length > r.Len() {
			return nil, fmt.Errorf("Invalid BER format")
		}
		p := asn1Primitive{
			tagBytes: []byte{tagB},
			length:   length,
			content:  make([]byte, length),
		}
		if length > 0 {
			if _, err = io.ReadFull(r, p.content); err != nil {
				return nil, fmt.Errorf("Invalid BER format")
			}
		}
		obj = p
		return
	}

	if depth >= maxBERNesting {
		return nil, errors.New("ber2der: BER nesting too deep")
	}
	subObjects := make([]asn1Object, 0)
	if !indefinite {
		if length > r.Len() {
			return nil, fmt.Errorf("length is more than available data")
		}
		content := make([]byte, length)
		if _, err = io.ReadFull(r, content); err != nil {
			return nil, fmt.Errorf("length is more than available data")
		}
		r = bytes.NewReader(content)
	}
	for {
		if !indefinite && r.Len() == 0 {
			// Definite length: the content has been consumed exactly.
			break
		}
		var sobj asn1Object
		sobj, err = readObject(r, depth+1)
		if err != nil {
			if err == io.EOF {
				// Only the indefinite form can reach here: the input ended
				// before the end-of-contents octets.
				return nil, errors.New("ber2der: missing end-of-contents octets")
			}
			return nil, err
		}
		if isEndOfContents(sobj) {
			if !indefinite {
				return nil, errors.New("ber2der: unexpected end-of-contents octets")
			}
			// End-of-contents (00 00) terminates the indefinite value.
			break
		}
		subObjects = append(subObjects, sobj)
	}
	obj = asn1Structured{
		tagBytes: []byte{tagB},
		content:  subObjects,
	}
	return
}
