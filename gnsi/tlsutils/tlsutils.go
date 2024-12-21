// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Package tlsutil is a set of utility functions for processing gNSI TLS artifacts.
package tlsutils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	certzpb "github.com/openconfig/gnsi/certz"
)

// parse a certz certificate, return the issuerID and the *x509.Certificate, only of the following criteria are met:
//   - Certificate is type X509
//   - Certificate Encoding is PEM
//     TODO(morrowc): Handle a trustbundle where the certificate is not sent, where there is reliance upon an existing source.
//   - RawCertificate is not nil (a trustbundle, initially, may not be defined with a source)
//   - There is no PrivateKey material (a trustbundle can not have key material)
func processBundleCertificate(cert *certzpb.Certificate) (string, *x509.Certificate, error) {
	if cert == nil {
		return "", nil, fmt.Errorf("received nil Certificate")
	}
	// Qualify the content of the certz.Certifcate
	if cert.GetType() != certzpb.CertificateType_CERTIFICATE_TYPE_X509 {
		return "", nil, fmt.Errorf("expected CertificateType to be X509, got %v", cert.GetType())
	}
	if cert.GetEncoding() != certzpb.CertificateEncoding_CERTIFICATE_ENCODING_PEM {
		return "", nil, fmt.Errorf("expected CertificateEncoding to be PEM, got %v", cert.GetEncoding())
	}
	if cert.GetRawCertificate() == nil {
		return "", nil, fmt.Errorf("expected RawCertificate to be non-nil")
	}
	if cert.GetRawPrivateKey() != nil {
		return "", nil, fmt.Errorf("expected KeyMaterial to be nil, got a key")
	}

	// Parse the certificate and return it
	block, rest := pem.Decode(cert.GetRawCertificate())
	if len(rest) > 0 {
		return "", nil, fmt.Errorf("parsing PEM block returned more than 1 item: %q", rest)
	}
	if block.Type != "CERTIFICATE" {
		return "", nil, fmt.Errorf("expected PEM block type to be CERTIFICATE, got %q", block.Type)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("parsing Certificate: %v", err)
	}
	// Build the hex encoded version of SubjectKeyId which matches OpenSSL output content.
	var skBuilder strings.Builder
	for _, b := range c.SubjectKeyId {
		skBuilder.WriteString(fmt.Sprintf("%02x:", b))
	}

	// Now build the skid and format it properly.
	skid := skBuilder.String()
	skid = strings.ToUpper(strings.TrimSuffix(skid, ":"))
	if skid == "" {
		return "", nil, fmt.Errorf("certificate does not have a SubjectKeyId")
	}
	return skid, c, nil
}

// ParseTrustBundle will parse a gnsi/certz CertificateChain to produce a map[string]*x509.Certificate.
// TODO(morrowc): Add support for a PKCS#7 format trustbundle as well.
func ParseTrustBundle(bundle *certzpb.CertificateChain) (map[string]*x509.Certificate, error) {
	if bundle == nil {
		return nil, fmt.Errorf("received nil CertificateChain")
	}

	res := make(map[string]*x509.Certificate)
	// Retrieve the first certificate, then repeate for each parent certificate.
	skid, cert, err := processBundleCertificate(bundle.GetCertificate())
	if err != nil {
		return nil, err
	}
	if _, ok := res[skid]; ok {
		return nil, fmt.Errorf("duplicate SKID: %s", skid)
	}
	res[skid] = cert

	parent := bundle.GetParent()
	// Continue walking down (up?) the parent tree collecting each certificate at each level.
	for {
		if parent == nil {
			break
		}
		skid, cert, err := processBundleCertificate(parent.GetCertificate())
		if err != nil {
			return nil, err
		}
		if _, ok := res[skid]; ok {
			return nil, fmt.Errorf("duplicate SKID: %s", skid)
		}
		res[skid] = cert
		parent = parent.GetParent()
	}
	return res, nil
}
