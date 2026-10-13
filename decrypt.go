package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/unidoc/pkcs7/internal/rc2"
)

// ErrUnsupportedAlgorithm is returned when the key transport or content
// encryption algorithm is not one this package implements.
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA key transport with DES-CBC, DES-EDE3-CBC, AES-CBC, AES-GCM or RC2-CBC content encryption is supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// ErrNoRecipient is returned by Decrypt when none of the enveloped
// recipients matches the provided certificate.
var ErrNoRecipient = errors.New("pkcs7: no enveloped recipient for provided certificate")

// Decrypt decrypts encrypted content info for recipient cert and private key.
//
// A wrong private key, or a tampered encrypted key, fails like a wrong content
// key. Content in an unauthenticated mode (CBC) then decrypts to garbage with
// no error for about one such key in 256, so callers that cannot rule out a
// mismatch should validate the plaintext.
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, ErrNoRecipient
	}
	switch priv := pkey.(type) {
	case *rsa.PrivateKey:
		// Implicit rejection (Bleichenbacher): DecryptPKCS1v15SessionKey
		// replaces the fallback key only when the PKCS#1 v1.5 padding is
		// valid, and content decryption runs either way, so neither the error
		// nor the timing reveals whether the padding was valid. The fallback
		// is deterministic, so repeating a query does not reveal it either.
		if priv.N == nil || priv.D == nil {
			return nil, errors.New("pkcs7: incomplete RSA private key")
		}
		ciphertext, err := canonicalCiphertext(priv, recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		lengths, err := data.EncryptedContentInfo.contentKeyLengths()
		if err != nil {
			return nil, err
		}
		// The RSA plaintext has one length, so at most one candidate is
		// replaced by the real key. Pick that one, or the first fallback when
		// none is, without branching on which, and decrypt the content once.
		keys := make([][]byte, len(lengths))
		idx := 0
		for i, n := range lengths {
			fallback := implicitRejectionKey(priv, ciphertext, n)
			keys[i] = append([]byte(nil), fallback...)
			// Only ciphertext and key size problems are reported here, and
			// those are public.
			if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, priv, ciphertext, keys[i]); err != nil {
				return nil, err
			}
			replaced := 1 - subtle.ConstantTimeCompare(keys[i], fallback)
			idx = subtle.ConstantTimeSelect(replaced, i, idx)
		}
		return data.EncryptedContentInfo.decrypt(keys[idx])
	}
	return nil, ErrUnsupportedAlgorithm
}

// canonicalCiphertext returns ciphertext as exactly priv.Size() bytes.
// crypto/rsa accepts shorter encodings of the same integer, and longer ones
// with leading zero bytes for some modulus sizes, so one integer must map to
// one byte string before it is used to derive the fallback key.
func canonicalCiphertext(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	k := priv.Size()
	for len(ciphertext) > 0 && ciphertext[0] == 0 {
		ciphertext = ciphertext[1:]
	}
	if len(ciphertext) > k {
		return nil, errors.New("pkcs7: encrypted key is longer than the RSA modulus")
	}
	out := make([]byte, k)
	copy(out[k-len(ciphertext):], ciphertext)
	return out, nil
}

// implicitRejectionKey returns an n-byte fallback key: HMAC-SHA256, keyed by a
// hash of the private exponent, over n and the ciphertext. It is deterministic
// and unpredictable without the private key. n is included so that keys of
// different lengths are not prefixes of each other.
func implicitRejectionKey(priv *rsa.PrivateKey, ciphertext []byte, n int) []byte {
	kdk := sha256.Sum256(priv.D.Bytes())
	mac := hmac.New(sha256.New, kdk[:])
	key := make([]byte, 0, n+sha256.Size)
	for i := 0; len(key) < n; i++ {
		mac.Reset()
		mac.Write([]byte{byte(n >> 8), byte(n), byte(i >> 8), byte(i)})
		mac.Write(ciphertext)
		key = mac.Sum(key)
	}
	return key[:n]
}

// contentKeyLengths returns the content-encryption key lengths in bytes that
// the algorithm in eci accepts. The first is used when the padding is invalid.
func (eci encryptedContentInfo) contentKeyLengths() ([]int, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	switch {
	case alg.Equal(OIDEncryptionAlgorithmDESCBC):
		return []int{8}, nil
	case alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC):
		return []int{24}, nil
	case alg.Equal(OIDEncryptionAlgorithmAES128CBC), alg.Equal(OIDEncryptionAlgorithmAES128GCM):
		return []int{16}, nil
	case alg.Equal(OIDEncryptionAlgorithmAES256CBC), alg.Equal(OIDEncryptionAlgorithmAES256GCM):
		return []int{32}, nil
	case alg.Equal(OIDEncryptionAlgorithmRC2CBC):
		// The RC2 key length is not encoded. Producers use the effective key
		// length, but some S/MIME clients transport a 16-byte key with a
		// shorter effective length, so both are accepted.
		_, bits, err := rc2Params(eci.ContentEncryptionAlgorithm.Parameters)
		if err != nil {
			return nil, err
		}
		if n := (bits + 7) / 8; n != 16 {
			return []int{n, 16}, nil
		}
		return []int{16}, nil
	}
	return nil, fmt.Errorf("%w: content encryption algorithm %v", ErrUnsupportedAlgorithm, alg)
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret
func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return data.EncryptedContentInfo.decrypt(key)
}

// rc2MaxKeyBytes and rc2MaxEffectiveBits are the limits of the RC2 key
// schedule (RFC 2268 §2): the key is 1 to 128 bytes and the effective key
// length 1 to 1024 bits. The cipher implementation does not check them.
const (
	rc2MaxKeyBytes      = 128
	rc2MaxEffectiveBits = 1024
)

// rc2EffectiveKeyBits maps the RC2 parameter version to the effective key
// length in bits (RFC 2268 §6). Values from 256 to 1024 are the key length
// itself; below 256 only the three well-known table entries are recognised,
// which is what OpenSSL accepts as well.
func rc2EffectiveKeyBits(version int) (int, error) {
	switch {
	case version >= 256 && version <= rc2MaxEffectiveBits:
		return version, nil
	case version == 160:
		return 40, nil
	case version == 120:
		return 64, nil
	case version == 58:
		return 128, nil
	}
	return 0, fmt.Errorf("pkcs7: unsupported RC2 parameter version %d", version)
}

// rc2Params decodes RC2-CBC-Parameter, which is either a bare 8-byte IV
// (effective key length 32 bits) or SEQUENCE { version, iv }.
func rc2Params(params asn1.RawValue) (iv []byte, effectiveBits int, err error) {
	if params.Tag == asn1.TagOctetString && params.Class == asn1.ClassUniversal {
		return params.Bytes, 32, nil
	}
	var p rc2CBCParameters
	if _, err := asn1.Unmarshal(params.FullBytes, &p); err != nil {
		return nil, 0, fmt.Errorf("pkcs7: malformed RC2 parameters: %v", err)
	}
	bits, err := rc2EffectiveKeyBits(p.Version)
	if err != nil {
		return nil, 0, err
	}
	return p.IV, bits, nil
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm

	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for len(cypherbytes) > 0 {
			var part []byte
			rest, err := asn1.Unmarshal(cypherbytes, &part)
			if err != nil {
				return nil, fmt.Errorf("pkcs7: malformed encrypted content: %v", err)
			}
			buf.Write(part)
			cypherbytes = rest
		}
		cyphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block
	var err error
	// iv is the CBC initialisation vector; nil until the algorithm's
	// parameters have been decoded.
	var iv []byte

	switch {
	case alg.Equal(OIDEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
		iv = eci.ContentEncryptionAlgorithm.Parameters.Bytes
	case alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
		iv = eci.ContentEncryptionAlgorithm.Parameters.Bytes
	case alg.Equal(OIDEncryptionAlgorithmAES256CBC), alg.Equal(OIDEncryptionAlgorithmAES256GCM):
		fallthrough
	case alg.Equal(OIDEncryptionAlgorithmAES128GCM), alg.Equal(OIDEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
		iv = eci.ContentEncryptionAlgorithm.Parameters.Bytes
	case alg.Equal(OIDEncryptionAlgorithmRC2CBC):
		// The key and the parameters come from the envelope, so both are
		// attacker-controlled; the RC2 implementation panics outside these
		// ranges.
		if len(key) < 1 || len(key) > rc2MaxKeyBytes {
			return nil, fmt.Errorf("pkcs7: invalid RC2 key length %d", len(key))
		}
		var bits int
		iv, bits, err = rc2Params(eci.ContentEncryptionAlgorithm.Parameters)
		if err != nil {
			return nil, err
		}
		block, err = rc2.New(key, bits)
	default:
		return nil, fmt.Errorf("%w: content encryption algorithm %v", ErrUnsupportedAlgorithm, alg)
	}

	if err != nil {
		return nil, err
	}

	if alg.Equal(OIDEncryptionAlgorithmAES128GCM) || alg.Equal(OIDEncryptionAlgorithmAES256GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	if len(iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	if len(cyphertext) == 0 || len(cyphertext)%block.BlockSize() != 0 {
		return nil, errors.New("pkcs7: invalid ciphertext length")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])
	if padlen == 0 || padlen > blocklen {
		return nil, errors.New("invalid padding")
	}

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}
