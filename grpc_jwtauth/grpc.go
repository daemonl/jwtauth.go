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

type options struct {
	shouldCheck DeciderFunc
	allowEmpty  bool
}

type Option func(*options)

func authFunc(verifier Verifier, opts ...Option) grpc_auth.AuthFunc {
	cfg := &options{}
	for _, option := range opts {
		option(cfg)
	}

	return func(ctx context.Context) (context.Context, error) {
		if cfg.shouldCheck != nil {
			if !cfg.shouldCheck(
		}
		rawToken, err := grpc_auth.AuthFromMD(ctx, "Bearer")
		if err != nil {
			if cfg.allowEmpty {
				return nil, nil
			}
			return ctx, err
		}
		if rawToken == "" {
			if cfg.allowEmpty {
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

func UnaryServerInterceptor(verifier Verifier, options ...Option) grpc.UnaryServerInterceptor {
	return grpc_auth.UnaryServerInterceptor(authFunc(verifier, options...))
}

func StreamServerInterceptor(verifier Verifier, opts ...Option) grpc.StreamServerInterceptor {
	return grpc_auth.StreamServerInterceptor(authFunc(verifier, options...))
}
