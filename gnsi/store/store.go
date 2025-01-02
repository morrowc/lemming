// Package store encapsulates the storage and management of TLS Artifacts for the gNSI service.
package store

import (
	"crypto/x509"
	"sync"

	certzpb "github.com/openconfig/gnsi/certz"
)

// TLSStorage is the container used to store all TLS artifacts by profile name.
type TLSStorage struct {
  Profiles map[string]*TLSArtifacts
  mu 	 *sync.Mutex
}

// TLSArtifacts encapsulates the various artifacts required for secure TLS communications.
type TLSArtifacts struct {
	Cert                 *x509.Certificate                    // *x509.Certficate
	Key                  string                               // The key's PEM block form.
	TrustBundle          map[string]*x509.Certificate         // The trustbundle used
	LastTrustBundlePems  *certzpb.CertificateChain            // The last sent trustbundle list of PEM blocks. This is deprecated, use the PCS7 if that was sent.
	LastTrustBundlePKCS7 *certzpb.TrustBundle                 // The last sent trustbundle PCKS#7 format contents. This is the preferred transfer format to a gNSI server.
	CRLs                 []*certzpb.CertificateRevocationList // The last set list of CRL content.
}

// RotateContents rotates all provided artifacts at once, it is safest to provide all artifacts at once time,
// so that there are not desynchronization effects if a key is rotated out of cycle with the certificate (for instance).
func (t *TLSArtifacts) RotateContents(cert *x509.Certificate, key string, tb map[string]*x509.Certificate,
	tbp *certzpb.CertificateChain, tb7 *certzpb.TrustBundle, crls []*certzpb.CertificateRevocationList,
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if cert != nil {
		t.Cert = cert
	}
	if key != "" {
		t.Key = key
	}
	if tb != nil {
		t.TrustBundle = tb
	}
	if tb7 != nil {
		t.LastTrustBundlePKCS7 = tb7
	}
	if tbp != nil {
		t.LastTrustBundlePems = tbp
	}
	if crls != nil {
		t.CRLs = crls
	}
	return nil
}
