package pkcs7

import (
	"bytes"
	"errors"
)

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
	// encodedLen returns the length of the DER encoding, so that a
	// constructed value can write its length before its content without
	// first encoding the content into a scratch buffer.
	encodedLen() int
}

// encodedLengthLen returns the number of bytes encodeLength writes for n.
func encodedLengthLen(n int) int {
	if n < 128 {
		return 1
	}
	return 1 + lengthLength(n)
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
	// contentLen is the encoded length of content, summed once when the
	// value is read so that encoding stays linear in the number of values.
	contentLen int
}

func (s asn1Structured) encodedLen() int {
	return len(s.tagBytes) + encodedLengthLen(s.contentLen) + s.contentLen
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	out.Write(s.tagBytes)
	if err := encodeLength(out, s.contentLen); err != nil {
		return err
	}
	for _, obj := range s.content {
		if err := obj.EncodeTo(out); err != nil {
			return err
		}
	}
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	content  []byte
}

// asn1String is a constructed string value merged into its primitive form.
// It keeps its segments, which alias the input, and writes their bodies one
// after another when encoded, so merging copies no content and each nesting
// level only does work for its own segments.
type asn1String struct {
	tag      byte // primitive tag of the merged value
	unused   byte // BIT STRING unused-bits octet of the merged value
	segments []asn1Object
	bodyLen  int // content length, without the BIT STRING unused-bits octet
}

// isBitString reports whether s is a BIT STRING, whose segments each carry
// an unused-bits octet.
func (s asn1String) isBitString() bool {
	return s.tag == 3
}

func (s asn1String) contentLen() int {
	if s.isBitString() {
		return s.bodyLen + 1
	}
	return s.bodyLen
}

func (s asn1String) encodedLen() int {
	n := s.contentLen()
	return 1 + encodedLengthLen(n) + n
}

func (s asn1String) EncodeTo(out *bytes.Buffer) error {
	out.WriteByte(s.tag)
	if err := encodeLength(out, s.contentLen()); err != nil {
		return err
	}
	if s.isBitString() {
		out.WriteByte(s.unused)
	}
	s.writeBody(out)
	return nil
}

// writeBody writes the segment bodies, without BIT STRING unused-bits octets.
func (s asn1String) writeBody(out *bytes.Buffer) {
	for _, seg := range s.segments {
		switch v := seg.(type) {
		case asn1Primitive:
			if s.isBitString() {
				out.Write(v.content[1:])
			} else {
				out.Write(v.content)
			}
		case asn1String:
			v.writeBody(out)
		}
	}
}

func (p asn1Primitive) encodedLen() int {
	return len(p.tagBytes) + encodedLengthLen(len(p.content)) + len(p.content)
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, len(p.content)); err != nil {
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
	out.Grow(obj.encodedLen())
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

// encodeLength encodes the length in DER format.
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//
//	length | byte 1 | bytes n
//	0      | 0x00   | -
//	120    | 0x78   | -
//	200    | 0x81   | 0xC8
//	500    | 0x82   | 0x01 0xF4
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
	return ok && len(po.content) == 0 && po.tagBytes[0] == 0
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
	number := 0
	for i := 1; ; i++ {
		if i >= len(data) {
			return nil, nil, errBERTruncated
		}
		if i > maxTagContinuation {
			return nil, nil, errors.New("ber2der: BER tag number too long")
		}
		if i == 1 && data[i] == 0x80 {
			// 8.1.2.4.2 c: the first continuation octet must not be zero.
			return nil, nil, errors.New("ber2der: BER tag number has leading zero")
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
	} else if l == 0xFF {
		// X.690 8.1.3.5 c: reserved for future extensions.
		return nil, nil, errors.New("ber2der: reserved length octet 0xFF")
	} else if l > 0x80 {
		numberOfBytes := length
		if len(data) < numberOfBytes {
			return nil, nil, errBERTruncated
		}
		lengthOctets := data[:numberOfBytes]
		data = data[numberOfBytes:]
		// BER allows leading zero octets in a length (X.690 8.1.3.5); the
		// DER output re-encodes it minimally.
		for len(lengthOctets) > 0 && lengthOctets[0] == 0 {
			lengthOctets = lengthOctets[1:]
		}
		// int is only guaranteed to be 32 bits.
		if len(lengthOctets) > 4 || len(lengthOctets) == 4 && lengthOctets[0] > 0x7F {
			return nil, nil, errors.New("ber2der: BER tag length too long")
		}
		length = 0
		for _, sl := range lengthOctets {
			length = length<<8 | int(sl)
		}
	}

	if tagBytes[0] == 0 && length != 0 {
		// Tag 0 is only valid as the end-of-contents octets (X.690 8.1.5).
		return nil, nil, errors.New("ber2der: tag 0 with content")
	}
	if tagBytes[0] == 0 && l != 0 {
		// The end-of-contents octets are exactly 00 00 (X.690 8.1.5).
		return nil, nil, errors.New("ber2der: end-of-contents octets with a long-form length")
	}

	if primitive {
		if length > len(data) {
			return nil, nil, errBERTruncated
		}
		obj = asn1Primitive{
			tagBytes: tagBytes,
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
	if isConstructedString(tagBytes) {
		if obj, err = mergeConstructedString(tagBytes[0], subObjects); err != nil {
			return nil, nil, err
		}
		return obj, rest, nil
	}
	contentLen := 0
	for _, sobj := range subObjects {
		contentLen += sobj.encodedLen()
	}
	obj = asn1Structured{
		tagBytes:   tagBytes,
		content:    subObjects,
		contentLen: contentLen,
	}
	return obj, rest, nil
}

// isConstructedString reports whether tag is the identifier octet of a
// universal string type in constructed form (X.690 8.21). DER requires
// string types in primitive form (10.2), so their segments are merged.
// Implicitly tagged strings cannot be recognised without the schema and
// are left as they are.
func isConstructedString(tag []byte) bool {
	if len(tag) != 1 || tag[0]&0xC0 != 0 || tag[0]&0x20 == 0 {
		return false
	}
	switch tag[0] & 0x1F {
	case 3, // BIT STRING
		4,  // OCTET STRING
		7,  // ObjectDescriptor
		12, // UTF8String
		18, // NumericString
		19, // PrintableString
		20, // T61String
		21, // VideotexString
		22, // IA5String
		23, // UTCTime
		24, // GeneralizedTime
		25, // GraphicString
		26, // VisibleString
		27, // GeneralString
		28, // UniversalString
		30: // BMPString
		return true
	}
	return false
}

// mergeConstructedString returns the primitive form of a constructed string
// value from its segments (X.690 8.21). A nested constructed segment has
// already been merged by readObject. BIT STRING segments are BIT STRINGs
// (8.6.4) and OCTET STRING segments are OCTET STRINGs; the other string
// types are encoded as an implicit OCTET STRING (8.23.5), so their segments
// are OCTET STRINGs, and segments of the type's own tag are accepted too.
func mergeConstructedString(tag byte, segments []asn1Object) (asn1String, error) {
	merged := asn1String{tag: tag &^ 0x20, segments: segments}
	bitString := merged.isBitString()
	for i, seg := range segments {
		var segTag, unused byte
		var bodyLen int
		switch v := seg.(type) {
		case asn1Primitive:
			if len(v.tagBytes) != 1 {
				return asn1String{}, errors.New("ber2der: constructed string segment of a different type")
			}
			segTag, bodyLen = v.tagBytes[0], len(v.content)
			if bitString && segTag == 3 {
				if bodyLen == 0 {
					return asn1String{}, errors.New("ber2der: BIT STRING segment without unused-bits octet")
				}
				unused, bodyLen = v.content[0], bodyLen-1
			}
		case asn1String:
			segTag, unused, bodyLen = v.tag, v.unused, v.bodyLen
		default:
			return asn1String{}, errors.New("ber2der: constructed string segment of a different type")
		}
		if segTag != merged.tag && (bitString || segTag != 4) {
			return asn1String{}, errors.New("ber2der: constructed string segment of a different type")
		}
		if bitString {
			// Only the last segment may leave bits unused (8.6.4), at most
			// 7, and only when it has bits at all (8.6.2.3).
			if unused > 7 {
				return asn1String{}, errors.New("ber2der: BIT STRING with more than 7 unused bits")
			}
			if unused != 0 && bodyLen == 0 {
				return asn1String{}, errors.New("ber2der: BIT STRING segment with unused bits but no bits")
			}
			if unused != 0 && i != len(segments)-1 {
				return asn1String{}, errors.New("ber2der: BIT STRING segment with unused bits before the last")
			}
			merged.unused = unused
		}
		merged.bodyLen += bodyLen
	}
	return merged, nil
}
