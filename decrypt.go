package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
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

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	switch pkey.(type) {
	case *rsa.PrivateKey:
		var contentKey []byte
		contentKey, err := rsa.DecryptPKCS1v15(rand.Reader, pkey.(*rsa.PrivateKey), recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
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

// rc2EffectiveKeyBits maps the RC2 parameter version to the effective key
// length in bits (RFC 2268 §6). Values of 256 and above are the key length
// itself; below 256 only the three well-known table entries are recognised,
// which is what OpenSSL accepts as well.
func rc2EffectiveKeyBits(version int) (int, error) {
	switch {
	case version >= 256:
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
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
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
