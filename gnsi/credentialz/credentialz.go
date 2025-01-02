package gnsi

import (
	credentialzpb "github.com/openconfig/gnsi/credentialz"
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
