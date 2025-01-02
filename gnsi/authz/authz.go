package gnsi

import (
	authzpb "github.com/openconfig/gnsi/authz"
}

type authz struct {
	authzpb.UnimplementedAuthzServer
}

func (a *authz) Rotate(authzpb.Authz_RotateServer) error {
	return status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}

func (a *authz) Get(context.Context, *authzpb.GetRequest) (*authzpb.GetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Fake UnImplemented")
}
