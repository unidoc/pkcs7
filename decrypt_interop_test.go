package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/unidoc/pkcs7/internal/rc2"
)

// loadTestIdentity reads testdata/<name>.crt and testdata/<name>.key (PKCS#8).
func loadTestIdentity(t *testing.T, name string) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join("testdata", name+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join("testdata", name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		t.Fatalf("testdata/%s: bad PEM", name)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecryptInterop decrypts EnvelopedData produced by other
// implementations: primitive [0] IMPLICIT OCTET STRING content from OpenSSL
// and BouncyCastle (the PDFBox one with RC2-CBC), plus this package's own
// constructed-form output.
func TestDecryptInterop(t *testing.T) {
	const counting = "000102030405060708090a0b0c0d0e0f1011121314151617"
	tests := []struct {
		file  string
		plain string
	}{
		{"openssl_aes128cbc.der", counting},
		{"openssl_aes256cbc.der", counting},
		{"openssl_des3cbc.der", counting},
		// Apache PDFBox 3.0.8 / BouncyCastle: RC2-CBC 128-bit, parameter version 58.
		{"pdfbox_rc2cbc.der", "3133e080c3a13fc9d8c77320fc1c4a896dca40e200000f3d"},
		// Written by this package at v0.3.0: constructed [0] wrapping an OCTET STRING.
		{"legacy_v030_aes256cbc_constructed.der", counting},
	}
	cert, key := loadTestIdentity(t, "recipient")
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			der, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := p7.Decrypt(cert, key)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if want := mustHex(t, tt.plain); !bytes.Equal(got, want) {
				t.Errorf("plaintext mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

// TestDecryptWrongRecipient checks that a certificate that is not among the
// recipients is rejected rather than producing garbage.
func TestDecryptWrongRecipient(t *testing.T) {
	der, err := os.ReadFile(filepath.Join("testdata", "openssl_aes128cbc.der"))
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := loadTestIdentity(t, "other")
	if _, err := p7.Decrypt(cert, key); err == nil {
		t.Fatal("expected an error for a non-recipient certificate")
	}
}

// encryptedContentOf parses an EnvelopedData produced by this package and
// returns the raw EncryptedContent value.
func encryptedContentOf(t *testing.T, der []byte) asn1.RawValue {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		t.Fatal(err)
	}
	return ed.EncryptedContentInfo.EncryptedContent
}

// TestEncryptWithAlgorithm covers every content encryption algorithm through
// the global-free entry point, checks the standard primitive encoding of
// EncryptedContent and round-trips through Parse and Decrypt.
func TestEncryptWithAlgorithm(t *testing.T) {
	algs := map[string]int{
		"DES-CBC":     EncryptionAlgorithmDESCBC,
		"AES-128-CBC": EncryptionAlgorithmAES128CBC,
		"AES-256-CBC": EncryptionAlgorithmAES256CBC,
		"AES-128-GCM": EncryptionAlgorithmAES128GCM,
		"AES-256-GCM": EncryptionAlgorithmAES256GCM,
		"RC2-CBC":     EncryptionAlgorithmRC2CBC,
	}
	cert, key := loadTestIdentity(t, "recipient")
	plaintext := []byte("Hello Secret World!")
	for name, alg := range algs {
		t.Run(name, func(t *testing.T) {
			der, err := EncryptWithAlgorithm(plaintext, []*x509.Certificate{cert}, alg)
			if err != nil {
				t.Fatal(err)
			}
			ec := encryptedContentOf(t, der)
			if ec.IsCompound || ec.Class != asn1.ClassContextSpecific || ec.Tag != 0 {
				t.Errorf("EncryptedContent should be a primitive [0], got class=%d tag=%d compound=%v", ec.Class, ec.Tag, ec.IsCompound)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p7.Decrypt(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("round trip mismatch: %q", got)
			}
		})
	}

	if _, err := EncryptWithAlgorithm(plaintext, []*x509.Certificate{cert}, 999); !errors.Is(err, ErrUnsupportedEncryptionAlgorithm) {
		t.Errorf("unknown algorithm: got %v, want ErrUnsupportedEncryptionAlgorithm", err)
	}
}

// TestEncryptRC2Parameters checks the RC2-CBC AlgorithmIdentifier carries the
// SEQUENCE { version 58, iv } form that PDF readers expect.
func TestEncryptRC2Parameters(t *testing.T) {
	cert, _ := loadTestIdentity(t, "recipient")
	der, err := EncryptWithAlgorithm([]byte("x"), []*x509.Certificate{cert}, EncryptionAlgorithmRC2CBC)
	if err != nil {
		t.Fatal(err)
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		t.Fatal(err)
	}
	algID := ed.EncryptedContentInfo.ContentEncryptionAlgorithm
	if !algID.Algorithm.Equal(OIDEncryptionAlgorithmRC2CBC) {
		t.Fatalf("algorithm %v", algID.Algorithm)
	}
	iv, bits, err := rc2Params(algID.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	if bits != 128 || len(iv) != 8 {
		t.Errorf("effective bits %d, iv len %d", bits, len(iv))
	}
}

func TestRC2EffectiveKeyBits(t *testing.T) {
	for version, want := range map[int]int{160: 40, 120: 64, 58: 128, 256: 256, 1024: 1024} {
		got, err := rc2EffectiveKeyBits(version)
		if err != nil || got != want {
			t.Errorf("version %d: got %d, %v; want %d", version, got, err, want)
		}
	}
	if _, err := rc2EffectiveKeyBits(7); err == nil {
		t.Error("version 7 should be rejected")
	}
}

// TestDecryptUnsupportedAlgorithmError checks the error names the algorithm
// and wraps ErrUnsupportedAlgorithm.
func TestDecryptUnsupportedAlgorithmError(t *testing.T) {
	eci := encryptedContentInfo{
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}},
		EncryptedContent:           asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	}
	_, err := eci.decrypt([]byte("0123456789abcdef"))
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("got %v, want ErrUnsupportedAlgorithm", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("1.2.3.4")) {
		t.Errorf("error should name the OID: %v", err)
	}
}

// rc2EncryptedContent builds an RC2-CBC encryptedContentInfo directly, so
// that parameter and key shapes the encrypt side never produces can be fed
// to decrypt.
func rc2EncryptedContent(t *testing.T, key []byte, effectiveBits int, params []byte, plaintext []byte) encryptedContentInfo {
	t.Helper()
	block, err := rc2.New(key, effectiveBits)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 8)
	padded, _ := pad(plaintext, 8)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(params, &raw); err != nil {
		t.Fatal(err)
	}
	return encryptedContentInfo{
		ContentType:                OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRC2CBC, Parameters: raw},
		EncryptedContent:           asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ct},
	}
}

// TestDecryptRC2BareIVParameters covers the first alternative of
// RC2-CBCParameter (RFC 2268 §6): a bare 8-byte IV, meaning 32 effective
// key bits. The SEQUENCE form always carries a version.
func TestDecryptRC2BareIVParameters(t *testing.T) {
	key := []byte("0123456789abcdef")
	ivParam, _ := asn1.Marshal(make([]byte, 8))
	eci := rc2EncryptedContent(t, key, 32, ivParam, []byte("bare iv"))
	got, err := eci.decrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bare iv" {
		t.Errorf("got %q", got)
	}
}

// TestDecryptRC2RejectsOutOfRangeInputs: the content key and the parameter
// version come from the envelope, and the RC2 key schedule panics on an
// empty key, a key over 128 bytes or more than 1024 effective bits.
func TestDecryptRC2RejectsOutOfRangeInputs(t *testing.T) {
	key := []byte("0123456789abcdef")
	okParams, _ := asn1.Marshal(rc2CBCParameters{Version: rc2Version128, IV: make([]byte, 8)})
	eci := rc2EncryptedContent(t, key, 128, okParams, []byte("x"))

	for _, bad := range [][]byte{nil, make([]byte, 129)} {
		if _, err := eci.decrypt(bad); err == nil {
			t.Errorf("key of %d bytes: expected error", len(bad))
		}
	}

	for _, version := range []int{1025, 4096, 0, 7} {
		params, _ := asn1.Marshal(rc2CBCParameters{Version: version, IV: make([]byte, 8)})
		var raw asn1.RawValue
		asn1.Unmarshal(params, &raw)
		eci.ContentEncryptionAlgorithm.Parameters = raw
		if _, err := eci.decrypt(key); err == nil {
			t.Errorf("version %d: expected error", version)
		}
	}

	// The upper bound itself is valid.
	if _, err := rc2EffectiveKeyBits(1024); err != nil {
		t.Errorf("version 1024: %v", err)
	}
}

// TestDecryptRejectsMalformedCiphertext: the ciphertext and its padding come
// from the envelope. A length that is not a whole number of blocks, a
// padding byte outside 1..blocksize, or a constructed [0] with a chunk that
// is not an OCTET STRING must produce an error, not a panic.
func TestDecryptRejectsMalformedCiphertext(t *testing.T) {
	key := []byte("0123456789abcdef")
	params, _ := asn1.Marshal(rc2CBCParameters{Version: rc2Version128, IV: make([]byte, 8)})
	eci := rc2EncryptedContent(t, key, 128, params, []byte("x"))

	primitive := func(ct []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ct}
	}

	eci.EncryptedContent = primitive(make([]byte, 7))
	if _, err := eci.decrypt(key); err == nil {
		t.Error("7-byte ciphertext: expected error")
	}
	eci.EncryptedContent = primitive(nil)
	if _, err := eci.decrypt(key); err == nil {
		t.Error("empty ciphertext: expected error")
	}

	// Every possible last plaintext byte of a tampered block: the padding
	// check must reject or accept, never index out of range.
	for b := 0; b < 256; b++ {
		ct := make([]byte, 8)
		ct[7] = byte(b)
		eci.EncryptedContent = primitive(ct)
		eci.decrypt(key)
	}

	// Constructed [0] whose second chunk is an INTEGER, not an OCTET STRING.
	chunk, _ := asn1.Marshal(make([]byte, 8))
	eci.EncryptedContent = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: append(chunk, 0x02, 0x01, 0x05)}
	if _, err := eci.decrypt(key); err == nil {
		t.Error("constructed content with a non-OCTET STRING chunk: expected error")
	}
}

func TestUnpad(t *testing.T) {
	for _, tc := range []struct {
		data []byte
		ok   bool
	}{
		{[]byte{1, 2, 3, 4, 5, 6, 7, 1}, true},
		{[]byte{1, 2, 3, 4, 4, 4, 4, 4}, true},
		{[]byte{8, 8, 8, 8, 8, 8, 8, 8}, true},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 0}, false},   // zero padding length
		{[]byte{1, 2, 3, 4, 5, 6, 7, 9}, false},   // longer than the block
		{[]byte{1, 2, 3, 4, 5, 6, 3, 2}, false},   // inconsistent bytes
		{[]byte{1, 2, 3, 4, 5, 6, 7}, false},      // not a whole block
		{[]byte{1, 2, 3, 4, 5, 6, 7, 255}, false}, // would index before the slice
	} {
		_, err := unpad(tc.data, 8)
		if (err == nil) != tc.ok {
			t.Errorf("unpad(% X): err=%v, want ok=%v", tc.data, err, tc.ok)
		}
	}
}

// TestEncryptRC2RejectsWrongKeyLength: the RC2 parameters always declare 128
// effective bits, so a caller-supplied key must be 16 bytes.
func TestEncryptRC2RejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{8, 24} {
		if _, _, err := encryptRC2CBC([]byte("x"), make([]byte, n)); err == nil {
			t.Errorf("%d-byte key: expected error", n)
		}
	}
	if _, _, err := encryptRC2CBC([]byte("x"), make([]byte, 16)); err != nil {
		t.Errorf("16-byte key: %v", err)
	}
}
