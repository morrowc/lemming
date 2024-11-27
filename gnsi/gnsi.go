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
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authzpb "github.com/openconfig/gnsi/authz"
	certzpb "github.com/openconfig/gnsi/certz"
	credentialzpb "github.com/openconfig/gnsi/credentialz"
	pathzpb "github.com/openconfig/gnsi/pathz"

	"github.com/openconfig/lemming/gnsi/pathz"
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

type certz struct {
	certzpb.CertzServer
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

func (c *certz) unpackTB(tb *certzpb.TrustBundle) error {
	return status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

// Rotate is a bare-bones gNSI Certz rotation server example.
func (c *certz) Rotate(stream certzpb.Certz_RotateServer) error {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		// Handle the trustbundle contents if they exist in the input request.
		// The RotateRequest may have Certificates, GenerateCSR, or FinalizeRotation members.
		if c := in.GetCertificates(); c != nil {
			// c/UploadRequest should have one or more Entity messages, these could be a number of items:
			// CertificateChain, TrustBundle, CRLBundle, AuthenPolicy, ExistingEntity, TrustbundlePKCS7.
			for _, e := range c.GetEntity() {
				if cc := e.GetCertificateChain(); cc != nil {
					log.Infof("Received CertificateChain: %s", cc.GetCertificateChain())
					continue
				}
				if tb := e.GetTrustBundle(); tb != nil {
					log.Infof("Received TrustBundle: %s", tb.GetTrustBundle())
					err := c.unpackTB(tb)
					if err != nil {
						log.Infof("Error unpacking TrustBundle: %v", err)
						continue
					}
					if err := Send(); err != nil {
						log.Errorf("Error sending TrustBundle unpack failure: %v", err)
					}
					continue
				}
				if crl := e.GetCertificateRevocationListBundle(); crl != nil {
					log.Infof("Received CRLBundle: %s", crl.GetCrlBundle())
					continue
				}
				if ap := e.GetAuthenticationPolicy; ap != nil {
					log.Infof("Received AuthenticationPolicy: %s", ap.GetAuthenticationPolicy())
					continue
				}
				if ee := e.GetExistingEntity(); ee != nil {
					log.Infof("Received ExistingEntity: %s", ee.GetExistingEntity())
					continue
				}
				if tb7 := e.GetTrustbundlePKCS7(); tb7 != nil {
					log.Infof("Received TrustbundlePKCS7: %s", tb7.GetTrustbundlePKCS7())
					continue
				}
			}
		}

	}
	return status.Errorf(codes.Unimplemented, "Fake UnImplemented")
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
	srv := &Server{
		s:     s,
		authz: &authz{},
		certz: &certz{},
		pathz: &pathz.Server{},
		credz: &credentialz{},
	}
	authzpb.RegisterAuthzServer(s, srv.authz)
	certzpb.RegisterCertzServer(s, srv.certz)
	credentialzpb.RegisterCredentialzServer(s, srv.credz)
	pathzpb.RegisterPathzServer(s, srv.pathz)

	return srv
}
