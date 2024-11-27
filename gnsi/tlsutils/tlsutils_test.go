package tlsutils

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	certzpb "github.com/openconfig/gnsi/certz"
)

const (
	testDataDir = "testdata"
)

func buildCertificateFromFile(t *testing.T, certFile string) *certzpb.Certificate {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %v", err)
	}
	pemData, err := ioutil.ReadFile(filepath.Join(cwd, testDataDir, certFile))
	if err != nil {
		t.Fatalf("failed to read certificate from file: %v", err)
	}
	return &certzpb.Certificate{
		Type:            certzpb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding:        certzpb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
		CertificateType: &certzpb.Certificate_RawCertificate{RawCertificate: pemData},
	}
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
	}}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			gotID, _, err := processBundleCertificate(test.cert)

			switch {
			case err != nil && !test.wantErr:
				t.Errorf("[%v]: got unexpected error = %v", test.desc, err)
			case err == nil && test.wantErr:
				t.Errorf("[%v]: did not get error when expeting one", test.desc)
			case err == nil:
				if gotID != test.wantIssuerID {
					t.Errorf("[%v]: mismatch IssuerId:\n got: %v\nwant: %v", test.desc, gotID, test.wantIssuerID)
				}
				/*
				   if !reflect.DeepEqual(cert, test.wantCert) {
				       t.Errorf("processBundleCertificate() cert = %v, want %v", cert, test.wantCert)
				   }
				*/
			}
		})
	}
}
