package tlsutils

import (
	"crypto/x509"
	"encoding/pem"
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
	data, err := os.ReadFile(filepath.Join(cwd, testDataDir, path))
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
	}, {
		desc:    "BadCert - is key",
		cert:    buildCertificateFromFile(t, "bad.pem"),
		wantErr: true,
	}}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// func processBundleCertificate(cert *certzpb.Certificate) (string, *x509.Certificate, error) {

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

				if diff := cmp.Diff(gotCert, test.wantCert); diff != "" {
					t.Errorf("[%v]: Certificate Differences (+got/-want):\n%v", test.desc, diff)
				}
			}
		})
	}
}

func buildCertificateChainFromFiles(t *testing.T, certFiles []string) *certzpb.CertificateChain {
	if len(certFiles) == 0 {
		t.Fatalf("no certificate files provided")
	}

	var buildChain func(int) *certzpb.CertificateChain
	// Run buildChain recursively to build the chain of certificates.
	buildChain = func(index int) *certzpb.CertificateChain {
		if index >= len(certFiles) {
			return nil
		}
		return &certzpb.CertificateChain{
			Certificate: buildCertificateFromFile(t, certFiles[index]),
			Parent:      buildChain(index + 1),
		}
	}

	return buildChain(0)
}

func TestParseTrustBundle(t *testing.T) {
	tests := []struct {
		desc    string
		bundle  *certzpb.CertificateChain
		want    map[string]*x509.Certificate
		wantErr bool
	}{
		{
			desc: "ValidChain",
			bundle: buildCertificateChainFromFiles(t, []string{
				"cert1.pem",
				"cert2.pem",
				"cert3.pem",
			}),
			want: map[string]*x509.Certificate{
				"7A:52:B5:8F:C2:1E:8B:35:A1:34:59:77:A2:BC:AC:CD:D7:0E:55:1A": readPemAsX509(t, "cert1.pem"),
				"2B:6D:51:B7:DA:1C:BC:E4:C9:1B:2D:85:1B:75:8A:F3:C5:D2:22:26": readPemAsX509(t, "cert2.pem"),
				"F3:11:20:D4:44:5C:30:EF:F5:25:DA:A4:7C:AE:BC:B7:FF:2C:A7:53": readPemAsX509(t, "cert3.pem"),
			},
		},
		{
			desc:    "NilBundle",
			bundle:  nil,
			wantErr: true,
		},
		{
			desc: "DuplicateSKID",
			bundle: buildCertificateChainFromFiles(t, []string{
				"cert1.pem",
				"cert1.pem",
			}),
			wantErr: true,
		},
		{
			desc: "InvalidCertificate",
			bundle: buildCertificateChainFromFiles(t, []string{
				"cert1.pem",
				"bad.pem",
			}),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := ParseTrustBundle(test.bundle)
			if (err != nil) != test.wantErr {
				t.Fatalf("[%v]: unexpected error status: got %v, wantErr %v", test.desc, err, test.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(got, test.want); diff != "" {
					t.Errorf("[%v]: TrustBundle Differences (+got/-want):\n%v", test.desc, diff)
				}
			}
		})
	}
}
