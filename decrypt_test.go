package pkcs7

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecrypt(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
	if err != nil {
		t.Errorf("Cannot Decrypt with error: %v", err)
	}
	expected := []byte("This is a test")
	if !bytes.Equal(content, expected) {
		t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
	}
}

// Content is "This is a test"
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBFwYJKoZIhvcNAQcDoIIBCDCCAQQCAQAxgcowgccCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMAsGCSqGSIb3
DQEBAQSBgKyP/5WlRTZD3dWMrLOX6QRNDrXEkQjhmToRwFZdY3LgUh25ZU0S/q4G
dHPV21Fv9lQD+q7l3vfeHw8M6Z1PKi9sHMVfxAkQpvaI96DTIT3YHtuLC1w3geCO
8eFWTq2qS4WChSuS/yhYosjA1kTkE0eLnVZcGw0z/WVuEZznkdyIMDIGCSqGSIb3
DQEHATARBgUrDgMCBwQImpKsUyMPpQigEgQQRcWWrCRXqpD5Njs0GkJl+g==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END PRIVATE KEY-----`

func TestDecryptUsingPSKWrongKey(t *testing.T) {
	// A key of another AES size is tried and fails authentication; a key
	// of a size AES does not have is rejected by length; the right key
	// still works.
	defer func(alg int) { ContentEncryptionAlgorithm = alg }(ContentEncryptionAlgorithm)
	ContentEncryptionAlgorithm = EncryptionAlgorithmAES128GCM
	key := []byte("128BitKey4AESGCM")
	der, err := EncryptUsingPSK([]byte("secret"), key)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range [][]byte{append(key, key...), append(key, key[:8]...)} {
		if _, err := p7.DecryptUsingPSK(k); err == nil {
			t.Errorf("%d-byte key: no error", len(k))
		}
	}
	if _, err := p7.DecryptUsingPSK(key[:7]); err == nil || !strings.Contains(err.Error(), "invalid content key length 7, want 16") {
		t.Errorf("7-byte key: got %v, want key length error", err)
	}
	if _, err := p7.DecryptUsingPSK(key); err != nil {
		t.Errorf("correct key: %v", err)
	}
}

func TestDecryptAESCBCWrongKeyLength(t *testing.T) {
	// EncryptUsingPSK never offered AES-CBC, so there is no legacy AES-CBC
	// content with a mismatched key and the key length stays strict.
	key := []byte("128BitKey4AESCBC")
	_, eci, err := encryptAESCBC([]byte("secret"), key, EncryptionAlgorithmAES128CBC)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{24, 32} {
		_, err := eci.decrypt(make([]byte, n))
		if err == nil || !strings.Contains(err.Error(), "invalid content key length") {
			t.Errorf("%d-byte key: got %v, want key length error", n, err)
		}
	}
	if _, err := eci.decrypt(key); err != nil {
		t.Errorf("correct key: %v", err)
	}
}

// legacyPSKFixtures were written by v0.4.2's EncryptUsingPSK with a key of
// bytes 0, 1, 2, ... of the wrong AES size for the configured algorithm,
// which it encrypted with anyway. They must stay decryptable.
var legacyPSKFixtures = map[string]struct {
	keyLen int
	der    string
}{
	"AES-128-GCM label, 32-byte key": {32, "306506092a864886f70d010706a0583056020100305106092a864886f70d0107013020060960864801650304010610133011840c31af4a00c56e82ad728fd6820201108022cff53328370ff30d01f855c24225bb5b364c7e7470f89d53bf0c5f797576e8057593"},
	"AES-256-GCM label, 16-byte key": {16, "306506092a864886f70d010706a0583056020100305106092a864886f70d0107013020060960864801650304012e10133011840c201ec5148055cede6f28e06c020110802288516b0ff65799f6eb5bb5110596150c22951b735db8a5da3a958b681e2a8f3e70c7"},
}

func TestDecryptUsingPSKLegacyKeySize(t *testing.T) {
	for name, f := range legacyPSKFixtures {
		der, err := hex.DecodeString(f.der)
		if err != nil {
			t.Fatal(err)
		}
		p7, err := Parse(der)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		key := make([]byte, f.keyLen)
		for i := range key {
			key[i] = byte(i)
		}
		got, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if string(got) != "legacy PSK content" {
			t.Errorf("%s: decrypted %q", name, got)
		}
		key[0]++
		if _, err := p7.DecryptUsingPSK(key); err == nil {
			t.Errorf("%s: wrong key of the legacy size: no error", name)
		}
	}
}
