package http_jwtauth

import (
	"net/http"
	"strings"

	"gopkg.daemonl.com/jwtauth"
)

type Verifier interface {
	VerifyJWT(rawKey string) (*jwtauth.VerifiedJWT, error)
}

func doError(w http.ResponseWriter, req *http.Request, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	// TODO: Content Type based on Accept
	w.Write([]byte(msg)) //nolint: errcheck
}

func Middleware(verifier Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			header := req.Header.Get("Authorization")
			// Parser code taken from grpc-ecosystem/grpc-middleware to match errors
			splits := strings.SplitN(header, " ", 2)
			if len(splits) < 2 {
				doError(w, req, "Bad authorization string")
				return
			}
			if !strings.EqualFold(splits[0], "bearer") {
				doError(w, req, "Request unauthenticated with bearer")
				return
			}

			rawToken := splits[1]
			if rawToken == "" {
				doError(w, req, "No Bearer Token")
				return
			}

			ctx := req.Context()

			claims, err := verifier.VerifyJWT(rawToken)
			if err != nil {
				if ae, ok := err.(jwtauth.AuthError); ok {
					doError(w, req, string(ae))
					return
				}
				// TODO: Log properly
				doError(w, req, "Unknown Auth Error")
				return

			}

			ctx = jwtauth.ToContext(ctx, claims)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}
