package grpc_jwtauth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"gopkg.daemonl.com/jwtauth"
)

type Verifier interface {
	VerifyJWT(rawKey string) (*jwtauth.VerifiedJWT, error)
}

func authFunc(verifier Verifier, allowEmpty bool) grpc_auth.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		rawToken, err := grpc_auth.AuthFromMD(ctx, "Bearer")
		if err != nil {
			return ctx, nil
		}
		if rawToken == "" {
			if allowEmpty {
				return nil, nil
			}
			return nil, status.Error(codes.Unauthenticated, "No Bearer Token")
		}

		claims, err := verifier.VerifyJWT(rawToken)
		if err != nil {
			return ctx, err
		}

		return jwtauth.ToContext(ctx, claims), nil
	}
}

func UnaryServerInterceptor(verifier Verifier, allowEmpty bool) grpc.UnaryServerInterceptor {
	return grpc_auth.UnaryServerInterceptor(authFunc(verifier, allowEmpty))
}

func StreamServerInterceptor(verifier Verifier, allowEmpty bool) grpc.StreamServerInterceptor {
	return grpc_auth.StreamServerInterceptor(authFunc(verifier, allowEmpty))
}
