package grpc_jwtauth

import (
	"context"

	"google.golang.org/grpc"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"gopkg.daemonl.com/jwtauth"
)

type Verifier interface {
	VerifyJWT(rawKey string) (*jwtauth.VerifiedJWT, error)
}

func authFunc(verifier Verifier) grpc_auth.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		rawToken, err := grpc_auth.AuthFromMD(ctx, "Bearer")
		if err != nil {
			return ctx, err
		}

		claims, err := verifier.VerifyJWT(rawToken)
		if err != nil {
			return ctx, err
		}

		return jwtauth.ToContext(ctx, claims), nil
	}
}

func UnaryServerInterceptor(verifier Verifier) grpc.UnaryServerInterceptor {
	return grpc_auth.UnaryServerInterceptor(authFunc(verifier))
}

func StreamServerInterceptor(verifier Verifier) grpc.StreamServerInterceptor {
	return grpc_auth.StreamServerInterceptor(authFunc(verifier))
}