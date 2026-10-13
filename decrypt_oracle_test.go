package pkcs7

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

// badPaddingKey returns an RSA ciphertext under pub whose decryption starts
// 00 03, so it never carries PKCS#1 v1.5 encryption padding (00 02).
func badPaddingKey(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	block := make([]byte, pub.Size())
	if _, err := rand.Read(block[2:]); err != nil {
		t.Fatal(err)
	}
	block[1] = 0x03
	c := new(big.Int).Exp(new(big.Int).SetBytes(block), big.NewInt(int64(pub.E)), pub.N).Bytes()
	out := make([]byte, pub.Size())
	copy(out[len(out)-len(c):], c)
	return out
}

// withEncryptedKey returns a copy of p7 whose first recipient carries ek.
func withEncryptedKey(t *testing.T, p7 *PKCS7, ek []byte) *PKCS7 {
	t.Helper()
	ed, ok := p7.raw.(envelopedData)
	if !ok {
		t.Fatal("not EnvelopedData")
	}
	ed.RecipientInfos = append([]recipientInfo(nil), ed.RecipientInfos...)
	ed.RecipientInfos[0].EncryptedKey = ek
	return &PKCS7{raw: ed}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecryptImplicitRejection checks that an EncryptedKey with bad PKCS#1
// v1.5 padding fails exactly like one with valid padding and a wrong-size or
// wrong key, so Decrypt is not a padding oracle. AES-GCM authentication makes
// every wrong key fail; TestDecryptBadPaddingKeyIsDeterministic covers the
// unauthenticated modes.
func TestDecryptImplicitRejection(t *testing.T) {
	cert, key := loadTestIdentity(t, "recipient")
	pub := cert.PublicKey.(*rsa.PublicKey)
	plaintext := []byte("Hello Secret World!")

	for name, alg := range map[string]int{
		"AES-128-GCM": EncryptionAlgorithmAES128GCM,
		"AES-256-GCM": EncryptionAlgorithmAES256GCM,
	} {
		t.Run(name, func(t *testing.T) {
			der, err := EncryptWithAlgorithm(plaintext, []*x509.Certificate{cert}, alg)
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			keyLen, err := p7.raw.(envelopedData).EncryptedContentInfo.contentKeyLength()
			if err != nil {
				t.Fatal(err)
			}
			encrypt := func(k []byte) []byte {
				ek, err := rsa.EncryptPKCS1v15(rand.Reader, pub, k)
				if err != nil {
					t.Fatal(err)
				}
				return ek
			}
			cases := []struct {
				name string
				ek   []byte
			}{
				{"bad padding", badPaddingKey(t, pub)},
				{"valid padding, wrong-size key", encrypt(randomBytes(t, keyLen-3))},
				{"valid padding, wrong key", encrypt(randomBytes(t, keyLen))},
			}

			var first string
			for _, c := range cases {
				_, err := withEncryptedKey(t, p7, c.ek).Decrypt(cert, key)
				if err == nil {
					t.Fatalf("%s: expected an error", c.name)
				}
				if first == "" {
					first = err.Error()
					continue
				}
				if err.Error() != first {
					t.Errorf("%s: error %q differs from the bad-padding case %q", c.name, err, first)
				}
			}

			got, err := p7.Decrypt(cert, key)
			if err != nil {
				t.Fatalf("genuine envelope: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("genuine envelope: got %q", got)
			}
		})
	}
}

// TestDecryptBadPaddingKeyIsDeterministic checks that for an EncryptedKey with
// bad padding, Decrypt uses exactly implicitRejectionKey as the content key:
// content encrypted under that key decrypts. With CBC content, this keeps
// repeated queries from telling bad padding apart from a wrong key.
func TestDecryptBadPaddingKeyIsDeterministic(t *testing.T) {
	cert, key := loadTestIdentity(t, "recipient")
	priv := key.(*rsa.PrivateKey)
	plaintext := []byte("implicit rejection")
	ek := badPaddingKey(t, &priv.PublicKey)
	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		t.Fatal(err)
	}

	for name, enc := range map[string]func(k []byte) (*encryptedContentInfo, error){
		"DES-CBC": func(k []byte) (*encryptedContentInfo, error) {
			_, eci, err := encryptDESCBC(plaintext, k)
			return eci, err
		},
		"AES-128-CBC": func(k []byte) (*encryptedContentInfo, error) {
			_, eci, err := encryptAESCBC(plaintext, k, EncryptionAlgorithmAES128CBC)
			return eci, err
		},
		"AES-256-CBC": func(k []byte) (*encryptedContentInfo, error) {
			_, eci, err := encryptAESCBC(plaintext, k, EncryptionAlgorithmAES256CBC)
			return eci, err
		},
		"RC2-CBC": func(k []byte) (*encryptedContentInfo, error) {
			_, eci, err := encryptRC2CBC(plaintext, k)
			return eci, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Learn the key length from a throwaway envelope of this type.
			probe, err := enc(nil)
			if err != nil {
				t.Fatal(err)
			}
			keyLen, err := probe.contentKeyLength()
			if err != nil {
				t.Fatal(err)
			}
			eci, err := enc(implicitRejectionKey(priv, ek, keyLen))
			if err != nil {
				t.Fatal(err)
			}
			p7 := &PKCS7{raw: envelopedData{
				RecipientInfos:       []recipientInfo{{IssuerAndSerialNumber: ias, EncryptedKey: ek}},
				EncryptedContentInfo: *eci,
			}}
			got, err := p7.Decrypt(cert, key)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("Decrypt: got %q", got)
			}
		})
	}
}

// TestDecryptShortEncodingSameFallback checks that a bad-padding EncryptedKey
// with its leading zero byte stripped gets the same fallback key as the full
// encoding. crypto/rsa decrypts both encodings to the same real key, so
// different fallback keys would tell bad padding apart from valid padding.
func TestDecryptShortEncodingSameFallback(t *testing.T) {
	cert, key := loadTestIdentity(t, "recipient")
	priv := key.(*rsa.PrivateKey)
	var ek []byte
	for i := 0; i < 10000 && ek == nil; i++ {
		if c := badPaddingKey(t, &priv.PublicKey); c[0] == 0 {
			ek = c
		}
	}
	if ek == nil {
		t.Fatal("no bad-padding ciphertext with a leading zero byte found")
	}
	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("short encoding")
	_, eci, err := encryptAESCBC(plaintext, implicitRejectionKey(priv, ek, 16), EncryptionAlgorithmAES128CBC)
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string][]byte{"full": ek, "leading zero stripped": ek[1:]} {
		p7 := &PKCS7{raw: envelopedData{
			RecipientInfos:       []recipientInfo{{IssuerAndSerialNumber: ias, EncryptedKey: e}},
			EncryptedContentInfo: *eci,
		}}
		got, err := p7.Decrypt(cert, key)
		if err != nil {
			t.Errorf("%s: Decrypt: %v", name, err)
		} else if !bytes.Equal(got, plaintext) {
			t.Errorf("%s: Decrypt: got %q", name, got)
		}
	}
}

// TestDecryptIncompleteKey checks that a private key without a modulus or
// private exponent is reported as an error, not a panic.
func TestDecryptIncompleteKey(t *testing.T) {
	cert, key := loadTestIdentity(t, "recipient")
	priv := key.(*rsa.PrivateKey)
	der, err := EncryptWithAlgorithm([]byte("x"), []*x509.Certificate{cert}, EncryptionAlgorithmAES128CBC)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]*rsa.PrivateKey{
		"no private exponent": {PublicKey: priv.PublicKey},
		"no modulus":          {PublicKey: rsa.PublicKey{E: priv.E}, D: priv.D},
		"zero value":          {},
	} {
		if _, err := p7.Decrypt(cert, k); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestImplicitRejectionKey(t *testing.T) {
	_, key := loadTestIdentity(t, "recipient")
	_, other := loadTestIdentity(t, "other")
	priv, otherPriv := key.(*rsa.PrivateKey), other.(*rsa.PrivateKey)
	c1, c2 := randomBytes(t, priv.Size()), randomBytes(t, priv.Size())

	for _, n := range []int{8, 16, 24, 32, 33, 128} {
		k := implicitRejectionKey(priv, c1, n)
		if len(k) != n {
			t.Fatalf("n=%d: got %d bytes", n, len(k))
		}
		if !bytes.Equal(k, implicitRejectionKey(priv, c1, n)) {
			t.Errorf("n=%d: not deterministic", n)
		}
		if bytes.Equal(k, implicitRejectionKey(priv, c2, n)) {
			t.Errorf("n=%d: same key for different ciphertexts", n)
		}
		if bytes.Equal(k, implicitRejectionKey(otherPriv, c1, n)) {
			t.Errorf("n=%d: same key for different private keys", n)
		}
		// Keys of different lengths must be unrelated, not prefixes.
		if longer := implicitRejectionKey(priv, c1, n+1); bytes.Equal(k, longer[:n]) {
			t.Errorf("n=%d: key is a prefix of the %d-byte key", n, n+1)
		}
	}

	// Every encoding of one integer gets one key.
	c3 := randomBytes(t, priv.Size())
	c3[0] = 0
	if !bytes.Equal(implicitRejectionKey(priv, c3, 16), implicitRejectionKey(priv, c3[1:], 16)) {
		t.Error("leading-zero and stripped encodings give different keys")
	}
}
