package pkcs7

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
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
			lengths, err := p7.raw.(envelopedData).EncryptedContentInfo.contentKeyLengths()
			if err != nil {
				t.Fatal(err)
			}
			keyLen := lengths[0]
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
			lengths, err := probe.contentKeyLengths()
			if err != nil {
				t.Fatal(err)
			}
			keyLen := lengths[0]
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

// TestDecryptCiphertextEncodings checks that every encoding of a bad-padding
// EncryptedKey, with its leading zero byte stripped or with extra leading zero
// bytes, gets the same fallback key as the modulus-length encoding. crypto/rsa
// decrypts them to the same real key, so different fallback keys would tell
// bad padding apart from valid padding. A longer encoding that is not just
// leading zeros is rejected.
func TestDecryptCiphertextEncodings(t *testing.T) {
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
	envelope := func(e []byte) *PKCS7 {
		return &PKCS7{raw: envelopedData{
			RecipientInfos:       []recipientInfo{{IssuerAndSerialNumber: ias, EncryptedKey: e}},
			EncryptedContentInfo: *eci,
		}}
	}
	for name, e := range map[string][]byte{
		"modulus length":         ek,
		"leading zero stripped":  ek[1:],
		"one extra zero byte":    append([]byte{0}, ek...),
		"eight extra zero bytes": append(make([]byte, 8), ek...),
	} {
		got, err := envelope(e).Decrypt(cert, key)
		if err != nil {
			t.Errorf("%s: Decrypt: %v", name, err)
		} else if !bytes.Equal(got, plaintext) {
			t.Errorf("%s: Decrypt: got %q", name, got)
		}
	}
	if _, err := envelope(append([]byte{1}, ek...)).Decrypt(cert, key); err == nil {
		t.Error("encoding longer than the modulus: expected an error")
	}
}

// rc2Envelope wraps key for cert and returns an EnvelopedData whose RC2-CBC
// content was encrypted with key under the given effective key length and
// parameters.
func rc2Envelope(t *testing.T, cert *x509.Certificate, key []byte, effectiveBits int, params []byte, plaintext []byte) *PKCS7 {
	t.Helper()
	eci := rc2EncryptedContent(t, key, effectiveBits, params, plaintext)
	ek, err := rsa.EncryptPKCS1v15(rand.Reader, cert.PublicKey.(*rsa.PublicKey), key)
	if err != nil {
		t.Fatal(err)
	}
	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		t.Fatal(err)
	}
	return &PKCS7{raw: envelopedData{
		RecipientInfos:       []recipientInfo{{IssuerAndSerialNumber: ias, EncryptedKey: ek}},
		EncryptedContentInfo: eci,
	}}
}

// TestDecryptRC2KeyLengths checks the RC2 key lengths Decrypt accepts: the
// effective key length, and 16 bytes with a shorter effective length as some
// S/MIME clients transport it. Other lengths do not decrypt; with CBC content
// the fallback key passes the padding check for about 1 key in 256, so the
// rejected case is checked by its plaintext, not by an error.
func TestDecryptRC2KeyLengths(t *testing.T) {
	cert, key := loadTestIdentity(t, "recipient")
	plaintext := []byte("rc2 key length")
	bareIV, _ := asn1.Marshal(make([]byte, 8))
	v40, _ := asn1.Marshal(rc2CBCParameters{Version: 160, IV: make([]byte, 8)})
	v128, _ := asn1.Marshal(rc2CBCParameters{Version: rc2Version128, IV: make([]byte, 8)})

	for _, c := range []struct {
		name   string
		keyLen int
		bits   int
		params []byte
		ok     bool
	}{
		{"128 bits, 16-byte key", 16, 128, v128, true},
		{"40 bits, 5-byte key", 5, 40, v40, true},
		{"40 bits, 16-byte key", 16, 40, v40, true},
		{"bare IV (32 bits), 4-byte key", 4, 32, bareIV, true},
		{"bare IV (32 bits), 16-byte key", 16, 32, bareIV, true},
		{"40 bits, 8-byte key", 8, 40, v40, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p7 := rc2Envelope(t, cert, randomBytes(t, c.keyLen), c.bits, c.params, plaintext)
			got, err := p7.Decrypt(cert, key)
			if !c.ok {
				if err == nil && bytes.Equal(got, plaintext) {
					t.Error("decrypted with an unsupported key length")
				}
				return
			}
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("Decrypt: got %q", got)
			}
		})
	}
}

// TestDecryptRC2PrefersTransportedKey checks that when an RC2 envelope carries
// a 16-byte key with a shorter effective length, Decrypt uses that key and not
// the fallback for the effective length, even when content encrypted under
// that fallback would pass the padding check.
func TestDecryptRC2PrefersTransportedKey(t *testing.T) {
	cert, key := loadTestIdentity(t, "recipient")
	priv := key.(*rsa.PrivateKey)
	decoy := []byte("decrypted with the fallback key")
	v40, _ := asn1.Marshal(rc2CBCParameters{Version: 160, IV: make([]byte, 8)})

	ek, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, randomBytes(t, 16))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalCiphertext(priv, ek)
	if err != nil {
		t.Fatal(err)
	}
	// Content that opens cleanly under the 5-byte fallback key.
	eci := rc2EncryptedContent(t, implicitRejectionKey(priv, canonical, 5), 40, v40, decoy)
	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		t.Fatal(err)
	}
	p7 := &PKCS7{raw: envelopedData{
		RecipientInfos:       []recipientInfo{{IssuerAndSerialNumber: ias, EncryptedKey: ek}},
		EncryptedContentInfo: eci,
	}}
	if got, err := p7.Decrypt(cert, key); err == nil && bytes.Equal(got, decoy) {
		t.Error("Decrypt used the fallback key instead of the transported 16-byte key")
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

}

func TestCanonicalCiphertext(t *testing.T) {
	_, key := loadTestIdentity(t, "recipient")
	priv := key.(*rsa.PrivateKey)
	k := priv.Size()
	c := randomBytes(t, k)
	c[0] = 0
	for name, in := range map[string][]byte{
		"modulus length": c,
		"stripped":       c[1:],
		"extra zeros":    append(make([]byte, 3), c...),
	} {
		got, err := canonicalCiphertext(priv, in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if !bytes.Equal(got, c) {
			t.Errorf("%s: not canonical", name)
		}
	}
	if _, err := canonicalCiphertext(priv, append([]byte{1}, c...)); err == nil {
		t.Error("longer than the modulus: expected an error")
	}
}
