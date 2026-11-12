package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestEncrypt(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128CBC,
		EncryptionAlgorithmAES256CBC,
		EncryptionAlgorithmAES128GCM,
		EncryptionAlgorithmAES256GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
	}
	for _, mode := range modes {
		for _, sigalg := range sigalgs {
			ContentEncryptionAlgorithm = mode

			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptUsingPSK(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		ContentEncryptionAlgorithm = mode
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch mode {
		case EncryptionAlgorithmDESCBC:
			key = []byte("64BitKey")
		case EncryptionAlgorithmAES128GCM:
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptUsingPSK(plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestEncryptUsingPSKWrongKeyLength(t *testing.T) {
	// A key of the wrong length must be rejected when encrypting, not
	// silently used to produce content labelled with the wrong algorithm.
	defer func(alg int) { ContentEncryptionAlgorithm = alg }(ContentEncryptionAlgorithm)
	for _, alg := range []int{EncryptionAlgorithmAES128GCM, EncryptionAlgorithmAES256GCM} {
		ContentEncryptionAlgorithm = alg
		for _, n := range []int{8, 16, 24, 32} {
			want := 16
			if alg == EncryptionAlgorithmAES256GCM {
				want = 32
			}
			_, err := EncryptUsingPSK([]byte("secret"), make([]byte, n))
			if n == want && err != nil {
				t.Errorf("alg %d, %d-byte key: %v", alg, n, err)
			}
			if n != want && (err == nil || !strings.Contains(err.Error(), "invalid content key length")) {
				t.Errorf("alg %d, %d-byte key: got %v, want key length error", alg, n, err)
			}
		}
	}
	for _, alg := range []int{EncryptionAlgorithmAES128CBC, EncryptionAlgorithmAES256CBC} {
		if _, _, err := encryptAESCBC([]byte("secret"), make([]byte, 24), alg); err == nil || !strings.Contains(err.Error(), "invalid content key length") {
			t.Errorf("encryptAESCBC alg %d with a 24-byte key: got %v, want key length error", alg, err)
		}
	}
}

func TestEncryptAESGCMParametersRFC5084(t *testing.T) {
	// The parameters must be a constructed GCMParameters SEQUENCE with an
	// OCTET STRING nonce and the tag length, not the legacy layout.
	for _, alg := range []int{EncryptionAlgorithmAES128GCM, EncryptionAlgorithmAES256GCM} {
		_, eci, err := encryptAESGCM([]byte("x"), nil, alg)
		if err != nil {
			t.Fatal(err)
		}
		// The encrypter sets only FullBytes; decode to see the tag.
		var params asn1.RawValue
		if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
			t.Fatal(err)
		}
		if params.Class != asn1.ClassUniversal || params.Tag != asn1.TagSequence || !params.IsCompound {
			t.Errorf("alg %d: parameters are not a constructed SEQUENCE: % X", alg, params.FullBytes)
		}
		var p struct {
			Nonce  []byte
			ICVLen int
		}
		if rest, err := asn1.Unmarshal(params.FullBytes, &p); err != nil || len(rest) != 0 {
			t.Errorf("alg %d: GCMParameters decode: err=%v rest=% X", alg, err, rest)
			continue
		}
		if len(p.Nonce) != nonceSize || p.ICVLen != 16 {
			t.Errorf("alg %d: nonce %d bytes, ICVlen %d", alg, len(p.Nonce), p.ICVLen)
		}
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded, err := pad(test.Original, test.BlockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if !bytes.Equal(test.Expected, padded) {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
}
