package tlsutils

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	certzpb "github.com/openconfig/gnsi/certz"
)

const (
	testDataDir = "testdata"
)

// Simply read a file from disk and return the bytes.
func readFile(t *testing.T, path string) []byte {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %v", err)
	}
	data, err := ioutil.ReadFile(filepath.Join(cwd, testDataDir, path))
	if err != nil {
		t.Fatalf("failed to read certificate from file: %v", err)
	}
	return data
}

// Build a *certzpb.Certificate from a file read from disk.
func buildCertificateFromFile(t *testing.T, certFile string) *certzpb.Certificate {
	pemData := readFile(t, certFile)
	return &certzpb.Certificate{
		Type:            certzpb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding:        certzpb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
		CertificateType: &certzpb.Certificate_RawCertificate{RawCertificate: pemData},
	}
}

// Read a pem file from disk, parse and return an *x509.Certificate.
func readPemAsX509(t *testing.T, certFile string) *x509.Certificate {
	pemData := readFile(t, certFile)
	block, rest := pem.Decode(pemData)
	if len(rest) > 0 {
		t.Fatalf("parsing PEM block returned more than 1 item: %q", rest)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing PEM block to X509 certificate failed: %q", err)
	}
	return c
}

func TestProcessBundleCertificate(t *testing.T) {
	tests := []struct {
		desc         string
		cert         *certzpb.Certificate
		wantIssuerID string
		wantCert     *x509.Certificate
		wantErr      bool
	}{{
		desc:         "ValidCert",
		cert:         buildCertificateFromFile(t, "singlecert.pem"),
		wantIssuerID: "C4:39:49:3C:A4:53:09:0B:9F:BD:5F:3D:0A:CD:C3:34:18:2A:BC:40",
		wantCert:     readPemAsX509(t, "singlecert.pem"),
		wantCert:     readPemAsX509(t, "singlecert.pem"),
	}, {
		desc:    "BadCert - is key",
		cert:    buildCertificateFromFile(t, "bad.pem"),
		wantErr: true,
	}}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotID, gotCert, err := processBundleCertificate(test.cert)
			gotID, gotCert, err := processBundleCertificate(test.cert)

			switch {
			case err != nil && !test.wantErr:
				t.Errorf("[%v]: got unexpected error = %v", test.desc, err)
			case err == nil && test.wantErr:
				t.Errorf("[%v]: did not get error when expeting one", test.desc)
			case err == nil:
				if gotID != test.wantIssuerID {
					t.Errorf("[%v]: mismatch IssuerId:\n got: %v\nwant: %v", test.desc, gotID, test.wantIssuerID)
				}

				// Potentially the Equal check is cheap enough to skip the cmp, the diff from cmp.Diff is useful in testing.
				if test.wantCert.Equal(gotCert) {
					break
				}
				if diff := cmp.Diff(gotCert, test.wantCert); diff != "" {
					t.Errorf("[%v]: Certificate Differences (+got/-want):\n%v", test.desc, diff)
				}
			}
		})
	}
}
