package pkcs7

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestVerifyEC2RejectsDSA(t *testing.T) {
	fixture := UnmarshalDSATestFixture(EC2IdentityDocumentFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatalf("Parse encountered unexpected error: %v", err)
	}
	p7.Certificates = []*x509.Certificate{fixture.Certificate}
	if err := p7.Verify(); err != x509.ErrUnsupportedAlgorithm {
		t.Fatalf("Verify of a DSA signature returned %v, want x509.ErrUnsupportedAlgorithm", err)
	}
}

var EC2IdentityDocumentFixture = `
-----BEGIN PKCS7-----
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCA
JIAEggGmewogICJwcml2YXRlSXAiIDogIjE3Mi4zMC4wLjI1MiIsCiAgImRldnBh
eVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1
cy1lYXN0LTFhIiwKICAidmVyc2lvbiIgOiAiMjAxMC0wOC0zMSIsCiAgImluc3Rh
bmNlSWQiIDogImktZjc5ZmU1NmMiLAogICJiaWxsaW5nUHJvZHVjdHMiIDogbnVs
bCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAgImFjY291bnRJZCIg
OiAiMTIxNjU5MDE0MzM0IiwKICAiaW1hZ2VJZCIgOiAiYW1pLWZjZTNjNjk2IiwK
ICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDQtMDhUMDM6MDE6MzhaIiwKICAiYXJj
aGl0ZWN0dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJy
YW1kaXNrSWQiIDogbnVsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTEiCn0AAAAA
AAAxggEYMIIBFAIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5n
dG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2Vi
IFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA0MDgwMzAxNDRaMCMG
CSqGSIb3DQEJBDEWBBTuUc28eBXmImAautC+wOjqcFCBVjAJBgcqhkjOOAQDBC8w
LQIVAKA54NxGHWWCz5InboDmY/GHs33nAhQ6O/ZI86NwjA9Vz3RNMUJrUPU5tAAA
AAAAAA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----`

var dsaPublicCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDOjCCAvWgAwIBAgIEPCY/UDANBglghkgBZQMEAwIFADBsMRAwDgYDVQQGEwdV
bmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYD
VQQKEwdVbmtub3duMRAwDgYDVQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtub3du
MB4XDTE4MTAyMjEzNDMwN1oXDTQ2MDMwOTEzNDMwN1owbDEQMA4GA1UEBhMHVW5r
bm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5rbm93bjEQMA4GA1UE
ChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93bjCC
AbgwggEsBgcqhkjOOAQBMIIBHwKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADD
Hj+AtlEmaUVdQCJR+1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gE
exAiwk+7qdf+t8Yb+DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/Ii
Axmd0UgBxwIVAJdgUI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4
V7l5lK+7+jrqgvlXTAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozI
puE8FnqLVHyNKOCjrh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4Vrl
nwaSi2ZegHtVJWQBTDv+z0kqA4GFAAKBgQDCriMPbEVBoRK4SOUeFwg7+VRf4TTp
rcOQC9IVVoCjXzuWEGrp3ZI7YWJSpFnSch4lk29RH8O0HpI/NOzKnOBtnKr782pt
1k/bJVMH9EaLd6MKnAVjrCDMYBB0MhebZ8QHY2elZZCWoqDYAcIDOsEx+m4NLErT
ypPnjS5M0jm1PKMhMB8wHQYDVR0OBBYEFC0Yt5XdM0Kc95IX8NQ8XRssGPx7MA0G
CWCGSAFlAwQDAgUAAzAAMC0CFQCIgQtrZZ9hdZG1ROhR5hc8nYEmbgIUAIlgC688
qzy/7yePTlhlpj+ahMM=
-----END CERTIFICATE-----`)

type DSATestFixture struct {
	Input       []byte
	Certificate *x509.Certificate
}

func UnmarshalDSATestFixture(testPEMBlock string) DSATestFixture {
	var result DSATestFixture
	var derBlock *pem.Block
	var pemBlock = []byte(testPEMBlock)
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			break
		}
		switch derBlock.Type {
		case "PKCS7":
			result.Input = derBlock.Bytes
		case "CERTIFICATE":
			result.Certificate, _ = x509.ParseCertificate(derBlock.Bytes)
		}
	}

	return result
}
