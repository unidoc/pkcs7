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
		cc, err := data.EncryptedContentInfo.resolveCipher()
		if err != nil {
			return nil, err
		}
		// The RSA plaintext has one length, so at most one candidate is
		// replaced by the real key. Pick that one, or the first fallback when
		// none is, without branching on which, and decrypt the content once.
		kdk := implicitRejectionKDK(priv)
		keys := make([][]byte, len(cc.keyLengths))
		idx := 0
		for i, n := range cc.keyLengths {
			fallback := implicitRejectionKey(kdk, ciphertext, n)
			keys[i] = append([]byte(nil), fallback...)
			// Only ciphertext and key size problems are reported here, and
			// those are public.
			if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, priv, ciphertext, keys[i]); err != nil {
				return nil, err
			}
			replaced := 1 - subtle.ConstantTimeCompare(keys[i], fallback)
			idx = subtle.ConstantTimeSelect(replaced, i, idx)
		}
		return data.EncryptedContentInfo.decryptWith(cc, keys[idx])
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

// implicitRejectionKDK returns the key-derivation key for
// implicitRejectionKey: a hash of the private exponent.
func implicitRejectionKDK(priv *rsa.PrivateKey) []byte {
	kdk := sha256.Sum256(priv.D.Bytes())
	return kdk[:]
}

// implicitRejectionKey returns an n-byte fallback key: HMAC-SHA256, keyed by
// kdk from implicitRejectionKDK, over n and the ciphertext. It is
// deterministic and unpredictable without the private key. n is included so
// that keys of different lengths are not prefixes of each other.
func implicitRejectionKey(kdk, ciphertext []byte, n int) []byte {
	mac := hmac.New(sha256.New, kdk)
	key := make([]byte, 0, n+sha256.Size)
	for i := 0; len(key) < n; i++ {
		mac.Reset()
		mac.Write([]byte{byte(n >> 8), byte(n), byte(i >> 8), byte(i)})
		mac.Write(ciphertext)
		key = mac.Sum(key)
	}
	return key[:n]
}

// contentCipher is a content-encryption algorithm with its parameters
// decoded: everything decryptWith needs besides the key.
type contentCipher struct {
	// keyLengths are the key lengths in bytes the algorithm accepts. The
	// first is used when the RSA padding is invalid.
	keyLengths []int
	// newCipher builds the block cipher for key. It rejects a key whose
	// length the algorithm does not allow.
	newCipher func(key []byte) (cipher.Block, error)
	// iv is the CBC initialisation vector; unused for GCM.
	iv []byte
	// gcm holds the AES-GCM parameters, or nil for a CBC algorithm.
	gcm *gcmParameters
	// legacyAES lets DecryptUsingPSK use the other AES key sizes as well.
	// EncryptUsingPSK before v0.5.0 offered AES-GCM only and used whatever
	// AES key size it was given, labelling the content with the configured
	// algorithm.
	legacyAES bool
}

// gcmParameters is GCMParameters from RFC 5084 §3.2.
type gcmParameters struct {
	Nonce  []byte
	ICVLen int `asn1:"optional,default:12"`
}

// aesGCMParameters is the AES-GCM parameter layout this package wrote
// before v0.5.0: this SEQUENCE, with the nonce tagged [4], inside a
// primitive-tagged outer SEQUENCE. decrypt still reads it.
type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

// contentCipherSpec ties a content-encryption algorithm OID to the decoding
// of its parameters.
type contentCipherSpec struct {
	oid     asn1.ObjectIdentifier
	resolve func(params asn1.RawValue) (contentCipher, error)
}

// contentCipherSpecs lists the content-encryption algorithms this package
// can decrypt. Both key selection and content decryption consult it, and the
// cipher constructors enforce the key lengths, so the two cannot drift apart.
var contentCipherSpecs = []contentCipherSpec{
	{OIDEncryptionAlgorithmDESCBC, cbcCipher(8, des.NewCipher)},
	{OIDEncryptionAlgorithmDESEDE3CBC, cbcCipher(24, des.NewTripleDESCipher)},
	{OIDEncryptionAlgorithmAES128CBC, cbcCipher(16, aesCipher(16))},
	{OIDEncryptionAlgorithmAES256CBC, cbcCipher(32, aesCipher(32))},
	{OIDEncryptionAlgorithmAES128GCM, gcmCipher(16)},
	{OIDEncryptionAlgorithmAES256GCM, gcmCipher(32)},
	{OIDEncryptionAlgorithmRC2CBC, rc2CBCCipher},
}

// resolveCipher looks up the content-encryption algorithm in eci and decodes
// its parameters.
func (eci encryptedContentInfo) resolveCipher() (contentCipher, error) {
	alg := eci.ContentEncryptionAlgorithm
	for _, spec := range contentCipherSpecs {
		if spec.oid.Equal(alg.Algorithm) {
			return spec.resolve(alg.Parameters)
		}
	}
	return contentCipher{}, fmt.Errorf("%w: content encryption algorithm %v", ErrUnsupportedAlgorithm, alg.Algorithm)
}

// cbcCipher describes a CBC algorithm with a fixed key length whose
// parameters are the bare IV.
func cbcCipher(keyLen int, newCipher func(key []byte) (cipher.Block, error)) func(asn1.RawValue) (contentCipher, error) {
	return func(params asn1.RawValue) (contentCipher, error) {
		return contentCipher{
			keyLengths: []int{keyLen},
			newCipher:  newCipher,
			iv:         params.Bytes,
		}, nil
	}
}

// aesCipher returns an AES constructor that accepts only keyLen-byte keys.
// aes.NewCipher alone accepts every AES key size, so it would run AES-256
// for content labelled AES-128. The encrypters use it as well. The DES
// constructors already reject other key sizes themselves.
func aesCipher(keyLen int) func(key []byte) (cipher.Block, error) {
	return func(key []byte) (cipher.Block, error) {
		if len(key) != keyLen {
			return nil, fmt.Errorf("pkcs7: invalid content key length %d, want %d", len(key), keyLen)
		}
		return aes.NewCipher(key)
	}
}

// gcmCipher describes AES-GCM with a fixed key length.
func gcmCipher(keyLen int) func(asn1.RawValue) (contentCipher, error) {
	return func(params asn1.RawValue) (contentCipher, error) {
		p, err := parseGCMParameters(params)
		if err != nil {
			return contentCipher{}, err
		}
		return contentCipher{
			keyLengths: []int{keyLen},
			newCipher:  aesCipher(keyLen),
			gcm:        p,
			legacyAES:  true,
		}, nil
	}
}

// gcmTagSize is the only GCM tag length accepted. RFC 5084 allows 12 to 16
// bytes, but the parameters are not authenticated and a GCM tag is a prefix
// of the longer tag for the same key and nonce, so accepting a shorter
// declared length would let anyone truncate the tag of existing content.
// Nothing this package can read writes shorter tags.
const gcmTagSize = 16

// parseGCMParameters decodes the AES-GCM algorithm parameters. A
// constructed SEQUENCE is RFC 5084 GCMParameters; the primitive-tagged
// SEQUENCE this package wrote before v0.5.0 is the aesGCMParameters layout.
func parseGCMParameters(params asn1.RawValue) (*gcmParameters, error) {
	if params.Class != asn1.ClassUniversal || params.Tag != asn1.TagSequence {
		return nil, errors.New("pkcs7: malformed AES-GCM parameters: not a SEQUENCE")
	}
	var p gcmParameters
	if params.IsCompound {
		if _, err := asn1.Unmarshal(params.FullBytes, &p); err != nil {
			return nil, fmt.Errorf("pkcs7: malformed AES-GCM parameters: %v", err)
		}
	} else {
		var legacy aesGCMParameters
		if _, err := asn1.Unmarshal(params.Bytes, &legacy); err != nil {
			return nil, fmt.Errorf("pkcs7: malformed AES-GCM parameters: %v", err)
		}
		p = gcmParameters{Nonce: legacy.Nonce, ICVLen: legacy.ICVLen}
	}
	if p.ICVLen != gcmTagSize {
		return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
	}
	return &p, nil
}

// rc2CBCCipher describes RC2-CBC. The effective key length comes from the
// parameters, the key length is not encoded at all, so newCipher accepts any
// key length RC2 supports; keyLengths only lists the likely candidates.
func rc2CBCCipher(params asn1.RawValue) (contentCipher, error) {
	iv, bits, err := rc2Params(params)
	if err != nil {
		return contentCipher{}, err
	}
	// Producers use the effective key length, but some S/MIME clients
	// transport a 16-byte key with a shorter effective length, so both are
	// accepted.
	lengths := []int{16}
	if n := (bits + 7) / 8; n != 16 {
		lengths = []int{n, 16}
	}
	return contentCipher{
		keyLengths: lengths,
		newCipher: func(key []byte) (cipher.Block, error) {
			// The key and the parameters come from the envelope, so both
			// are attacker-controlled; the RC2 implementation panics outside
			// these ranges.
			if len(key) < 1 || len(key) > rc2MaxKeyBytes {
				return nil, fmt.Errorf("pkcs7: invalid RC2 key length %d", len(key))
			}
			return rc2.New(key, bits)
		},
		iv: iv,
	}, nil
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret.
//
// For AES content, a key of a different AES size than the labelled
// algorithm is accepted, because EncryptUsingPSK before v0.5.0 encrypted
// with whatever key size it was given and labelled the content with the
// configured algorithm.
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

// decrypt decrypts the content with a caller-provided key. See
// DecryptUsingPSK for the AES key sizes it accepts.
func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	cc, err := eci.resolveCipher()
	if err != nil {
		return nil, err
	}
	if n := len(key); cc.legacyAES && (n == 16 || n == 24 || n == 32) {
		cc.newCipher = aes.NewCipher
	}
	return eci.decryptWith(cc, key)
}

// decryptWith decrypts the content with key using the algorithm resolved by
// resolveCipher.
func (eci encryptedContentInfo) decryptWith(cc contentCipher, key []byte) ([]byte, error) {
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

	block, err := cc.newCipher(key)
	if err != nil {
		return nil, err
	}

	if cc.gcm != nil {
		gcm, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
		if err != nil {
			return nil, err
		}
		if len(cc.gcm.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		return gcm.Open(nil, cc.gcm.Nonce, cyphertext, nil)
	}

	if len(cc.iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	if len(cyphertext) == 0 || len(cyphertext)%block.BlockSize() != 0 {
		return nil, errors.New("pkcs7: invalid ciphertext length")
	}
	mode := cipher.NewCBCDecrypter(block, cc.iv)
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
