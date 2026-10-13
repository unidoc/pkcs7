package pkcs7

import (
	"bytes"
	"encoding/asn1"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestBer2Der(t *testing.T) {
	// indefinite length fixture
	ber := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}
	expected := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	der, err := ber2der(ber)
	if err != nil {
		t.Fatalf("ber2der failed with error: %v", err)
	}
	if !bytes.Equal(der, expected) {
		t.Errorf("ber2der result did not match.\n\tExpected: % X\n\tActual: % X", expected, der)
	}

	if der2, err := ber2der(der); err != nil {
		t.Errorf("ber2der on DER bytes failed with error: %v", err)
	} else {
		if !bytes.Equal(der, der2) {
			t.Error("ber2der is not idempotent")
		}
	}
	var thing struct {
		Number int
	}
	rest, err := asn1.Unmarshal(der, &thing)
	if err != nil {
		t.Errorf("Cannot parse resulting DER because: %v", err)
	} else if len(rest) > 0 {
		t.Errorf("Resulting DER has trailing data: % X", rest)
	}
}

func TestBer2Der_Negatives(t *testing.T) {
	fixtures := []struct {
		Input         []byte
		ErrorContains string
	}{
		{[]byte{0x30, 0x85}, "tag length too long"},
		{[]byte{0x30, 0x84, 0x80, 0x0, 0x0, 0x0}, "length is negative"},
		{[]byte{0x30, 0x82, 0x0, 0x1}, "length has leading zero"},
		{[]byte{0x30, 0x80, 0x1, 0x2}, "Invalid BER format"},
		{[]byte{0x30, 0x03, 0x01, 0x02}, "length is more than available data"},
		{[]byte{0x30}, "end of ber data reached"},
	}

	for _, fixture := range fixtures {
		_, err := ber2der(fixture.Input)
		if err == nil {
			t.Errorf("No error thrown. Expected: %s", fixture.ErrorContains)
			t.FailNow()
		}
		if !strings.Contains(err.Error(), fixture.ErrorContains) {
			t.Errorf("Unexpected error thrown.\n\tExpected: /%s/\n\tActual: %s", fixture.ErrorContains, err.Error())
		}
	}
}

func TestParseMalformedBERNoPanic(t *testing.T) {
	// Truncated and malformed BER must make ber2der (and therefore Parse)
	// return an error rather than panic, allocate proportionally to a hostile
	// declared length, or silently accept truncated content.
	fixtures := []struct {
		name  string
		input []byte
	}{
		{"indefinite length on primitive tag", []byte{0x04, 0x80}},
		{"primitive length past end of input", []byte{0x04, 0x05}},
		{"long-form length with no length octets", []byte{0x30, 0x81}},
		{"long-form length truncated", []byte{0x30, 0x84, 0x01}},
		{"truncated primitive content", []byte{0x04, 0x05, 0x01, 0x02}},
		{"oversized declared length (256 MB)", []byte{0x30, 0x84, 0x10, 0x00, 0x00, 0x00}},
		{"oversized declared length (2 GB)", []byte{0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF}},
		{"indefinite length missing end-of-contents", []byte{0x30, 0x80, 0x02, 0x01, 0x01}},
		{"indefinite length with no content at all", []byte{0x30, 0x80}},
		{"indefinite primitive nested in indefinite constructed", []byte{0x30, 0x80, 0x04, 0x80, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00}},
		{"empty constructed value followed by truncated sibling", []byte{0x30, 0x05, 0x30, 0x00, 0x02, 0x01}},
		{"end-of-contents inside a definite-length value", []byte{0x30, 0x02, 0x00, 0x00}},
		{"end-of-contents at top level", []byte{0x00, 0x00}},
		{"tag 0 with content", []byte{0x00, 0x01, 0xAA}},
		{"tag 0 with content inside a sequence", []byte{0x30, 0x03, 0x00, 0x01, 0xAA}},
	}
	for _, f := range fixtures {
		if _, err := ber2der(f.input); err == nil {
			t.Errorf("%s: ber2der(% X): expected error, got nil", f.name, f.input)
		}
		if _, err := Parse(f.input); err == nil {
			t.Errorf("%s: Parse(% X): expected error, got nil", f.name, f.input)
		}
	}
}

func TestBer2DerOversizedLengthNoAlloc(t *testing.T) {
	// A declared length beyond the remaining input must be rejected before the
	// content buffer is allocated, for both primitive and constructed values.
	fixtures := []struct {
		name  string
		input []byte
	}{
		{"constructed, 256 MB", []byte{0x30, 0x84, 0x10, 0x00, 0x00, 0x00}},
		{"constructed, 2 GB", []byte{0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF}},
		{"primitive, 256 MB", []byte{0x04, 0x84, 0x10, 0x00, 0x00, 0x00}},
		{"primitive, 2 GB", []byte{0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF}},
	}
	const limit = 1 << 20
	for _, f := range fixtures {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := ber2der(f.input)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("%s: expected error, got nil", f.name)
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > limit {
			t.Errorf("%s: allocated %d bytes, want at most %d", f.name, alloc, limit)
		}
	}
}

func TestBer2DerValidUnchanged(t *testing.T) {
	// Well-formed BER and DER must transcode to the expected DER; DER input
	// must pass through byte for byte.
	fixtures := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			"empty definite-length sequence",
			[]byte{0x30, 0x00},
			[]byte{0x30, 0x00},
		},
		{
			"empty sequence does not swallow its siblings",
			[]byte{0x30, 0x05, 0x30, 0x00, 0x02, 0x01, 0x01},
			[]byte{0x30, 0x05, 0x30, 0x00, 0x02, 0x01, 0x01},
		},
		{
			"empty indefinite-length sequence",
			[]byte{0x30, 0x80, 0x00, 0x00},
			[]byte{0x30, 0x00},
		},
		{
			"nested indefinite-length sequences",
			[]byte{0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x04, 0x01, 0xFF, 0x00, 0x00},
			[]byte{0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x01, 0x04, 0x01, 0xFF},
		},
		{
			"indefinite-length sequence inside a definite one",
			[]byte{0x30, 0x07, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
			[]byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01},
		},
		{
			"empty primitive",
			[]byte{0x04, 0x00},
			[]byte{0x04, 0x00},
		},
		{
			"primitive with exact content",
			[]byte{0x04, 0x02, 0x01, 0x02},
			[]byte{0x04, 0x02, 0x01, 0x02},
		},
		{
			"long-form definite length",
			append([]byte{0x04, 0x81, 0x80}, bytes.Repeat([]byte{0xAB}, 128)...),
			append([]byte{0x04, 0x81, 0x80}, bytes.Repeat([]byte{0xAB}, 128)...),
		},
	}
	for _, f := range fixtures {
		der, err := ber2der(f.input)
		if err != nil {
			t.Errorf("%s: ber2der(% X) failed: %v", f.name, f.input, err)
			continue
		}
		if !bytes.Equal(der, f.expected) {
			t.Errorf("%s: ber2der result did not match.\n\tExpected: % X\n\tActual: % X", f.name, f.expected, der)
		}
		if der2, err := ber2der(der); err != nil || !bytes.Equal(der, der2) {
			t.Errorf("%s: ber2der is not idempotent (err=%v): % X vs % X", f.name, err, der, der2)
		}
	}
}

// nestedDefinite returns depth nested definite-length SEQUENCEs around a NULL,
// with minimal (DER) length encodings.
func nestedDefinite(depth int) []byte {
	l := 2
	headers := make([][]byte, depth)
	for i := range headers {
		h := new(bytes.Buffer)
		h.WriteByte(0x30)
		encodeLength(h, l)
		headers[i] = h.Bytes()
		l += len(headers[i])
	}
	out := make([]byte, 0, l)
	for i := depth - 1; i >= 0; i-- {
		out = append(out, headers[i]...)
	}
	return append(out, 0x05, 0x00)
}

// nestedIndefinite returns depth nested indefinite-length SEQUENCEs around a
// NULL, each closed by its end-of-contents octets.
func nestedIndefinite(depth int) []byte {
	out := bytes.Repeat([]byte{0x30, 0x80}, depth)
	out = append(out, 0x05, 0x00)
	return append(out, bytes.Repeat([]byte{0x00, 0x00}, depth)...)
}

func TestBer2DerNestingLimit(t *testing.T) {
	// Nesting up to maxBERNesting constructed values is accepted, one more
	// level is rejected, for both length forms.
	atLimit := nestedDefinite(maxBERNesting)
	der, err := ber2der(atLimit)
	if err != nil {
		t.Fatalf("definite nesting at the limit: %v", err)
	}
	if !bytes.Equal(der, atLimit) {
		t.Error("definite nesting at the limit did not pass through unchanged")
	}
	if _, err := ber2der(nestedDefinite(maxBERNesting + 1)); err == nil || !strings.Contains(err.Error(), "nesting too deep") {
		t.Errorf("definite nesting past the limit: got %v, want nesting error", err)
	}

	der, err = ber2der(nestedIndefinite(maxBERNesting))
	if err != nil {
		t.Fatalf("indefinite nesting at the limit: %v", err)
	}
	if !bytes.Equal(der, atLimit) {
		t.Errorf("indefinite nesting at the limit did not transcode to the definite form")
	}
	if _, err := ber2der(nestedIndefinite(maxBERNesting + 1)); err == nil || !strings.Contains(err.Error(), "nesting too deep") {
		t.Errorf("indefinite nesting past the limit: got %v, want nesting error", err)
	}
}

func TestBer2DerHostileNesting(t *testing.T) {
	// About a million unterminated indefinite-length SEQUENCEs (2 MB).
	// Unbounded recursion on this input exceeds the lowered stack limit, a
	// fatal error that recover cannot catch.
	defer debug.SetMaxStack(debug.SetMaxStack(32 << 20))
	deep := bytes.Repeat([]byte{0x30, 0x80}, 1<<20)
	if _, err := ber2der(deep); err == nil {
		t.Error("deep indefinite nesting: expected error, got nil")
	}
	if _, err := Parse(deep); err == nil {
		t.Error("Parse of deep indefinite nesting: expected error, got nil")
	}

	// 8000 nested definite-length SEQUENCEs (about 31 KB). Each nesting level
	// copies its content, so the depth limit must keep the total small.
	nested := nestedDefinite(8000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := ber2der(nested)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Error("deep definite nesting: expected error, got nil")
	}
	const limit = 16 << 20
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > limit {
		t.Errorf("deep definite nesting allocated %d bytes, want at most %d", alloc, limit)
	}
}
