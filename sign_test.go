package pkcs7

import (
	"bytes"
	"crypto/dsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"testing"
)

func TestSign(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			var parents []*x509.Certificate
			parents = append(parents, interCert.Certificate)
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				for _, testDetach := range []bool{false, true} {
					log.Printf("test %s/%s/%s detached %t\n", sigalgroot, sigalginter, sigalgsigner, testDetach)
					toBeSigned, err := NewSignedData(content)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}

					// Set the digest to match the end entity cert
					signerDigest, _ := getDigestOIDForSignatureAlgorithm(signerCert.Certificate.SignatureAlgorithm)
					toBeSigned.SetDigestAlgorithm(signerDigest)

					if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
						t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						toBeSigned.Detach()
					}
					signed, err := toBeSigned.Finish()
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
					p7, err := Parse(signed)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						p7.Content = content
					}
					if !bytes.Equal(content, p7.Content) {
						t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
					}
					if err := p7.VerifyWithChain(truststore); err != nil {
						t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
						t.Errorf("test %s/%s/%s: expected digest algorithm %q but got %q",
							sigalgroot, sigalginter, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
					}
				}
			}
		}
	}
}

func TestSignAndVerifyWithOpenSSL(t *testing.T) {
	content := []byte("Hello World")
	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "TestDSASignAndVerifyWithOpenSSL_content")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpContentFile.Name(), content, 0755)

	block, _ := pem.Decode([]byte(dsaPublicCert))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}
	signerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("failed to parse certificate: " + err.Error())
	}

	// write the signer cert to a temp file
	tmpSignerCertFile, err := ioutil.TempFile("", "TestDSASignAndVerifyWithOpenSSL_signer")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpSignerCertFile.Name(), dsaPublicCert, 0755)

	priv := dsa.PrivateKey{
		PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: fromHex("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7"),
			Q: fromHex("9760508F15230BCCB292B982A2EB840BF0581CF5"),
			G: fromHex("F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A"),
		},
		},
		X: fromHex("7D6E1A3DD4019FD809669D8AB8DA73807CEF7EC1"),
	}
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("test case: cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.SignWithoutAttr(signerCert, &priv, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	toBeSigned.Detach()
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("test case: cannot finish signing data: %s", err)
	}

	// write the signature to a temp file
	tmpSignatureFile, err := ioutil.TempFile("", "TestDSASignAndVerifyWithOpenSSL_signature")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpSignatureFile.Name(), pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: signed}), 0755)

	// call openssl to verify the signature on the content using the root
	opensslCMD := exec.Command("openssl", "smime", "-verify", "-noverify",
		"-in", tmpSignatureFile.Name(), "-inform", "PEM",
		"-content", tmpContentFile.Name())
	out, err := opensslCMD.CombinedOutput()
	if err != nil {
		t.Fatalf("test case: openssl command failed with %s: %s", err, out)
	}
	os.Remove(tmpSignatureFile.Name())  // clean up
	os.Remove(tmpContentFile.Name())    // clean up
	os.Remove(tmpSignerCertFile.Name()) // clean up
}

func TestExampleSignedData(t *testing.T) {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestSignedDataWithContentType(t *testing.T) {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatalf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedDataWithContentType(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}, []byte("Example data to be signed"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSignerNoChain(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{Attribute{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := ioutil.TempFile("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}

}
func fromHex(s string) *big.Int {
	result, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return result
}

func TestUnmarshal(t *testing.T) {
	t.Log("itext")
	testUnmarshal(t, `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`)

	t.Log("unipdf")
	testUnmarshal(t, `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`)

	t.Log("unipdf PRD")
	testUnmarshal(t, `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`)
}

func testUnmarshal(t *testing.T, sig string) {
	b, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	var content contentInfo
	_, err = asn1.Unmarshal(b, &content)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(content.ContentType)

	var inner signedData
	_, err = asn1.Unmarshal(content.Content.Bytes, &inner)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("version: %d", inner.Version)
	t.Log("digest algorithm:")
	t.Log("==================")
	for _, di := range inner.DigestAlgorithmIdentifiers {
		t.Logf("\t %v: %v", di.Algorithm, di.Parameters)
	}
	t.Logf("content info: %v", inner.ContentInfo)
	t.Log("==================")
	t.Logf("\tcontent type: %v", inner.ContentInfo.ContentType)
	t.Logf("\tcontent: %v", inner.ContentInfo.Content)
	t.Log("certificates:")
	t.Log("==================")
	certs, err := inner.Certificates.Parse()
	if err == nil {
		for _, cert := range certs {
			t.Logf("\tissuer: %v", cert.Issuer)
			t.Logf("\tserialNumber: %v", cert.SerialNumber)
			t.Logf("\tCA: %v", cert.IsCA)
		}
	}
	t.Log("CRL:")
	t.Log("==================")
	for _, crl := range inner.CRLs {
		t.Logf("\talgorithm: %v", crl.SignatureAlgorithm)
		t.Logf("\tvalue: %v", crl.SignatureValue)
		t.Logf("\ttbs: %v", crl.TBSCertList)
	}

	t.Log("signers", len(inner.SignerInfos))
	t.Log("==================")
	if len(inner.SignerInfos) > 0 {
		si := inner.SignerInfos[0]
		t.Logf("version: %d", si.Version)
		t.Log("issuer:")
		var issuer pkix.RDNSequence
		_, err = asn1.Unmarshal(si.IssuerAndSerialNumber.IssuerName.FullBytes, &issuer)
		if err != nil {
			t.Logf("\terr: %v", err)
		}

		t.Logf("issuer: %v\n", issuer)

		t.Logf("\tissuer Name: %v", string(si.IssuerAndSerialNumber.IssuerName.Bytes))
		t.Logf("\tserial Number: %v", si.IssuerAndSerialNumber.SerialNumber)
		t.Logf("\tdigest alg: %v", si.DigestAlgorithm)

		t.Log("authentication attributes:")
		for _, attr := range si.AuthenticatedAttributes {
			t.Log("\toid", attr.Type)

			if attr.Type.Equal(OIDAttributeContentType) {
				var v asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(attr.Value.Bytes, &v); err != nil {
					t.Log("err", err)
					continue
				}

				t.Logf("\tvalue: %v", v)
			} else if attr.Type.Equal(OIDAttributeMessageDigest) {
				t.Log("\tmessage digest:")
				t.Log("\tvalue", string(attr.Value.Bytes))
			} else if attr.Type.Equal(OIDAttributeSigningCertificateV2) {
				var signingCert signingCertificateV2
				if _, err := asn1.Unmarshal(attr.Value.Bytes, &signingCert); err != nil {
					t.Log("err", err)
					continue
				}
				t.Log("\tSigning Certificates:")
				for _, cert := range signingCert.Certs {
					t.Logf("\t\tHash Algoritm: %v", cert.HashAlgorithm)
					t.Logf("\t\tCert hash: %v", string(cert.CertHash))
					t.Logf("\t\tIssuer and Serial: %v", cert.IssuerSerial)
				}
			} else {
				var test string
				if _, err := asn1.Unmarshal(attr.Value.Bytes, &test); err == nil {
					t.Log("\tvalue string:", test)
				} else {
					t.Log("\tvalue", attr.Value.Bytes)
				}
			}
		}

		t.Logf("encrypt algo: %v", si.DigestEncryptionAlgorithm)
	}

	t.Log("<=====================================>")
	t.Log("<=====================================>")
}
