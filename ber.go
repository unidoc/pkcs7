package pkcs7

import (
	"bytes"
	"errors"
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

// errBERTruncated is returned when the input ends before a value does: a
// missing tag or length octet, or content shorter than its declared length.
var errBERTruncated = errors.New("ber2der: length is more than available data")

func ber2der(data []byte) ([]byte, error) {
	out := new(bytes.Buffer)

	// Bytes after the top-level value are ignored: PDF signature contents
	// are padded to a reserved size, and detached signature files often end
	// with a newline.
	obj, _, err := readObject(data, 0)
	if err != nil {
		return nil, err
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
// overflowing the stack.
const maxBERNesting = 64

// isEndOfContents reports whether obj is the end-of-contents octets (00 00).
// readObject rejects tag 0 with content, so this is the only tag-0 value that
// can reach it. Outside an indefinite-length value it is an error.
func isEndOfContents(obj asn1Object) bool {
	po, ok := obj.(asn1Primitive)
	return ok && po.length == 0 && po.tagBytes[0] == 0
}

// maxTagContinuation is the most continuation octets a high-tag-number form
// tag may have: 28 bits of tag number, more than any real use.
const maxTagContinuation = 4

// readTag returns the identifier octets at the start of data and the data
// after them. Tag numbers up to 30 take one octet. Larger ones use the
// high-tag-number form (X.690 8.1.2.4): the low five bits are all set and
// the number follows in base 128, high bit set on all but the last octet.
func readTag(data []byte) (tag, rest []byte, err error) {
	if len(data) == 0 {
		return nil, nil, errBERTruncated
	}
	if data[0]&0x1F != 0x1F {
		return data[:1], data[1:], nil
	}
	if len(data) > 1 && data[1] == 0x80 {
		// 8.1.2.4.2 c: the first continuation octet must not be zero.
		return nil, nil, errors.New("ber2der: BER tag number has leading zero")
	}
	number := 0
	for i := 1; ; i++ {
		if i >= len(data) {
			return nil, nil, errBERTruncated
		}
		if i > maxTagContinuation {
			return nil, nil, errors.New("ber2der: BER tag number too long")
		}
		number = number<<7 | int(data[i]&0x7F)
		if data[i]&0x80 == 0 {
			if number < 0x1F {
				// 8.1.2.2: numbers below 31 use the single-octet form.
				return nil, nil, errors.New("ber2der: BER tag number is not minimal")
			}
			return data[:i+1], data[i+1:], nil
		}
	}
}

// readObject reads one BER value from the start of data and returns it with
// the data that follows it. depth is the number of constructed values
// enclosing it. The returned object aliases data rather than copying it.
func readObject(data []byte, depth int) (obj asn1Object, rest []byte, err error) {
	tagBytes, data, err := readTag(data)
	if err != nil {
		return nil, nil, err
	}
	if len(data) == 0 {
		return nil, nil, errBERTruncated
	}
	l := data[0]
	data = data[1:]

	primitive := tagBytes[0]&0x20 == 0

	length := int(l & 0x7F)
	// A definite length of zero (0x00) is an empty value, not the indefinite
	// form (0x80).
	indefinite := false
	if l == 0x80 {
		if primitive {
			// X.690 8.1.3.2: the indefinite form is only allowed for
			// constructed encodings.
			return nil, nil, errors.New("ber2der: indefinite length on primitive tag")
		}
		indefinite = true
	} else if l > 0x80 {
		numberOfBytes := length
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, nil, errors.New("ber2der: BER tag length too long")
		}
		if len(data) < numberOfBytes {
			return nil, nil, errBERTruncated
		}
		if numberOfBytes == 4 && data[0] > 0x7F {
			return nil, nil, errors.New("ber2der: BER tag length is negative")
		}
		if data[0] == 0 {
			return nil, nil, errors.New("ber2der: BER tag length has leading zero")
		}
		length = 0
		for _, sl := range data[:numberOfBytes] {
			length = length<<8 | int(sl)
		}
		data = data[numberOfBytes:]
	}

	if tagBytes[0] == 0 && length != 0 {
		// Tag 0 is only valid as the end-of-contents octets (X.690 8.1.5).
		return nil, nil, errors.New("ber2der: tag 0 with content")
	}

	if primitive {
		if length > len(data) {
			return nil, nil, errBERTruncated
		}
		obj = asn1Primitive{
			tagBytes: tagBytes,
			length:   length,
			content:  data[:length],
		}
		return obj, data[length:], nil
	}

	if depth >= maxBERNesting {
		return nil, nil, errors.New("ber2der: BER nesting too deep")
	}
	subObjects := make([]asn1Object, 0)
	if indefinite {
		// The content runs until the end-of-contents octets.
		for {
			// Every value, the end-of-contents octets included, takes at
			// least two bytes.
			if len(data) < 2 {
				return nil, nil, errors.New("ber2der: missing end-of-contents octets")
			}
			var sobj asn1Object
			if sobj, data, err = readObject(data, depth+1); err != nil {
				return nil, nil, err
			}
			if isEndOfContents(sobj) {
				break
			}
			subObjects = append(subObjects, sobj)
		}
		rest = data
	} else {
		if length > len(data) {
			return nil, nil, errBERTruncated
		}
		content := data[:length]
		rest = data[length:]
		// The declared length must be consumed exactly by whole values.
		for len(content) > 0 {
			var sobj asn1Object
			if sobj, content, err = readObject(content, depth+1); err != nil {
				return nil, nil, err
			}
			if isEndOfContents(sobj) {
				return nil, nil, errors.New("ber2der: unexpected end-of-contents octets")
			}
			subObjects = append(subObjects, sobj)
		}
	}
	obj = asn1Structured{
		tagBytes: tagBytes,
		content:  subObjects,
	}
	return obj, rest, nil
}
