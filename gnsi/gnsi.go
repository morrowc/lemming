// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gnsi

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authzpb "github.com/openconfig/gnsi/authz"
	certzpb "github.com/openconfig/gnsi/certz"
	credentialzpb "github.com/openconfig/gnsi/credentialz"
	pathzpb "github.com/openconfig/gnsi/pathz"

	log "github.com/golang/glog"

	"github.com/openconfig/lemming/gnsi/pathz"
	"github.com/openconfig/lemming/gnsi/tlsutils"
)

type authz struct {
	authzpb.UnimplementedAuthzServer
}

func (a *authz) Rotate(authzpb.Authz_RotateServer) error {
	return status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

func (a *authz) Get(context.Context, *authzpb.GetRequest) (*authzpb.GetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

// TLSArtifacts encapsulates the various artifacts required for secure TLS communications.
type TLSArtifacts struct {
	Cert                 *x509.Certificate                    // *x509.Certficate
	Key                  string                               // The key's PEM block form.
	TrustBundle          map[string]*x509.Certificate         // The trustbundle used
	LastTrustBundlePems  *certzpb.CertificateChain            // The last sent trustbundle list of PEM blocks. This is deprecated, use the PCS7 if that was sent.
	LastTrustBundlePKCS7 *certzpb.TrustBundle                 // The last sent trustbundle PCKS#7 format contents. This is the preferred transfer format to a gNSI server.
	CRLs                 []*certzpb.CertificateRevocationList // The last set list of CRL content.
	mu                   *sync.Mutex                          // Guard the
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

type certz struct {
	server       certzpb.CertzServer
	tlsartifacts *TLSArtifacts // Storage of the artifacts reqiured to use TLS as a server.
}

func (c *certz) CanGenerateCSR(context.Context, *certzpb.CanGenerateCSRRequest) (*certzpb.CanGenerateCSRResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

// AddProfile adds a new TLS profile to the server.
func (c *certz) AddProfile(ctx context.Context, req *certzpb.AddProfileRequest) (*certzpb.AddProfileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

// GetProfileList retrieves a list of TLS profiles from the server.
func (c *certz) GetProfileList(ctx context.Context, req *certzpb.GetProfileListRequest) (*certzpb.GetProfileListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

// DeleteProfile deletes a TLS profile from the server.
func (c *certz) DeleteProfile(ctx context.Context, req *certzpb.DeleteProfileRequest) (*certzpb.DeleteProfileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

func (c *certz) unpackTB(tb *certzpb.CertificateChain) (map[string]*x509.Certificate, error) {
	return tlsutils.ParseTrustBundle(tb)
}

// Rotate is a bare-bones gNSI Certz rotation server example.
// Store the tls artifacts on disk at the conclusion of a rotation.
// Format of the stored artifacts is a gnsi.RotateCertificateRequest.
// On startup use the previously stored artifacts if no other artifacts
// are offered through command-line arguments.
func (c *certz) Rotate(stream certzpb.Certz_RotateServer) error {
	type record struct {
		gcsr   bool
		rotate bool
	}
	var r record
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			log.Info("EOF on stream")
			return nil
		}
		// Handle the trustbundle contents if they exist in the input request.
		// The RotateRequest may have Certificates, GenerateCSR, or FinalizeRotation members.
		switch rcr := in.RotateRequest.(type) {
		case *certzpb.RotateCertificateRequest_Certificates:
			if r.rotate {
				return status.Error(codes.AlreadyExists, "rotate request already satisifed")
			}
			r.rotate = true
			if certs := in.GetCertificates(); certs != nil {
				// c.UploadRequest should have one or more Entity messages, these could be a number of items:
				// CertificateChain, TrustBundle, CRLBundle, AuthenPolicy, ExistingEntity, TrustbundlePKCS7.
				// Store these to update in the TLSArtifacts struct for later use.
				var cert *x509.Certificate
				var key string
				var trustbundle map[string]*x509.Certificate
				var lastTBp *certzpb.CertificateChain
				var lastTB7 *certzpb.TrustBundle
				var crls []*certzpb.CertificateRevocationList
				for _, e := range certs.GetEntities() {
					if cc := e.GetCertificateChain(); cc != nil {
						// There should be a key/leaf-cert(+intermediate-cert) here.
						log.Infof("Received CertificateChain: %s", cc.GetCertificate())
						continue
					}
					if tbp := e.GetTrustBundle(); tbp != nil {
						// This is a CertificateChain of root-certs.
						lastTBp = tbp
						log.Infof("Received TrustBundle: %s", *tbp)
						var err error
						trustbundle, err = c.unpackTB(tbp)
						if err != nil {
							log.Infof("Error unpacking TrustBundle: %v", err)
							// An error in TB unpacking is fatal to the rotation process.
							if err := stream.Send(&certzpb.RotateCertificateResponse{}); err != nil {
								log.Errorf("Error sending TrustBundle unpack failure: %v", err)
							}
							return status.Error(codes.Aborted, fmt.Sprint(err))
						}
						continue
					}
					if tb7 := e.GetTrustBundlePkcs7(); tb7 != nil {
						lastTB7 = tb7
						// This is the PKCS7 version of a trustbundle.
						log.Infof("Received a TrustBundle in PKCS#7 form: %v", *tb7)
						continue
					}
					if crl := e.GetCertificateRevocationListBundle(); crl != nil {
						crls = append(crls, crl.GetCertificateRevocationLists()...)
						log.Infof("Received CRLBundle with crls: %s", crl.GetCertificateRevocationLists())
						continue
					}
					// AuthenticationPolicy and ExistingEntity data are not yet stored in TLSArtifacts.
					if ap := e.GetAuthenticationPolicy; ap != nil {
						log.Infof("Received AuthenticationPolicy: %s", ap)
						continue
					}
					if ee := e.GetExistingEntity(); ee != nil {
						log.Infof("Received ExistingEntity: %s", ee)
						continue
					}
				}
				// Store the collected / rotated data for future use.
				if err := c.tlsartifacts.RotateContents(cert, key, trustbundle, lastTBp, lastTB7, crls); err != nil {
					return status.Error(codes.Internal, "failed to rotate final content into TLSArtifacts")
				}
			}
		case *certzpb.RotateCertificateRequest_GenerateCsr:
			log.Infof("Got an GenerateCSR request: %T", rcr)
			r.gcsr = true
			break
		case *certzpb.RotateCertificateRequest_FinalizeRotation:
			log.Infof("Got a FinalizeRotation request: %T", rcr)
			if r.rotate != true {
				return status.Error(codes.InvalidArgument, "can not finalize, no rotation made")
			}
			// An error in TB unpacking is fatal to the rotation process.
			if err := stream.Send(&certzpb.RotateCertificateResponse{}); err != nil {
				log.Errorf("Error sending TrustBundle unpack failure: %v", err)
			}
			return status.Error(codes.OK, "success")
		default:
			log.Infof("Got a different type: %T", rcr)
			return status.Error(codes.Internal, "odd type achieved, fail")
		}
	}
}

type credentialz struct {
	credentialzpb.UnimplementedCredentialzServer
}

func (c *credentialz) MutateAccountCredentials(credentialzpb.Credentialz_RotateAccountCredentialsServer) error {
	return status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

func (c *credentialz) MutateHostCredentials(credentialzpb.Credentialz_RotateHostParametersServer) error {
	return status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

// Server is a fake gNSI implementation.
type Server struct {
	s     *grpc.Server
	authz *authz
	certz *certz
	pathz *pathz.Server
	credz *credentialz
}

func (s *Server) GetPathZ() *pathz.Server {
	return s.pathz
}

// New returns a new fake gNMI server.
func New(s *grpc.Server) *Server {
	ta := TLSArtifacts{mu: &sync.Mutex{}}
	srv := &Server{
		s:     s,
		authz: &authz{},
		certz: &certz{tlsartifacts: &ta},
		pathz: &pathz.Server{},
		credz: &credentialz{},
	}
	authzpb.RegisterAuthzServer(s, srv.authz)
	certzpb.RegisterCertzServer(s, srv.certz)
	credentialzpb.RegisterCredentialzServer(s, srv.credz)
	pathzpb.RegisterPathzServer(s, srv.pathz)

	return srv
}
