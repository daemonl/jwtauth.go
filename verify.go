package jwtauth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2"
)

type AuthError string

func (err AuthError) Error() string {
	return string(err)
}

type VerifiedJWT struct {
	Raw []byte
	StandardClaims
}

var contextKey = struct{}{}

func FromContext(ctx context.Context) *VerifiedJWT {
	val, ok := ctx.Value(contextKey).(*VerifiedJWT)
	if !ok {
		return nil
	}
	return val
}

func ToContext(ctx context.Context, verified *VerifiedJWT) context.Context {
	return context.WithValue(ctx, contextKey, verified)
}

type StandardClaims struct {
	Issuer    string        `json:"iss,omitempty"`
	Subject   string        `json:"sub,omitempty"`
	Audience  ArrayOrString `json:"aud,omitempty"`
	Expiry    int64         `json:"exp,omitempty"`
	NotBefore int64         `json:"nbf,omitempty"`
	IssuedAt  int64         `json:"iat,omitempty"`
	ID        string        `json:"jti,omitempty"`
}

type ArrayOrString []string

func (s *ArrayOrString) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch v := v.(type) {
	case string:
		*s = []string{v}
	case []interface{}:
		a := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return fmt.Errorf("Must be a string or array of strings")
			}
			a[i] = s
		}
		*s = a
	default:
		return fmt.Errorf("Must be a string or array of strings")
	}

	return nil
}

type KeySource interface {
	GetKeys(string) []jose.JSONWebKey
}

type Verifier struct {
	KeySource
}

func NewVerifier(source KeySource) *Verifier {
	return &Verifier{
		KeySource: source,
	}
}

func (verifier *Verifier) VerifyJWT(rawKey string) (*VerifiedJWT, error) {
	sig, err := jose.ParseSigned(rawKey)
	if err != nil {
		return nil, AuthError("Invalid JWT")
	}
	var kid string
	headers := make([]jose.Header, len(sig.Signatures))
	for i, signature := range sig.Signatures {
		headers[i] = signature.Header
		if signature.Header.KeyID != "" {
			kid = signature.Header.KeyID
		}
	}

	keys := verifier.KeySource.GetKeys(kid)
	if len(keys) < 1 {
		return nil, AuthError(fmt.Sprintf("Unknown Key %s", kid))
	}

	var verifiedBytes []byte

	for _, key := range keys {
		verifiedBytes, err = sig.Verify(key)
		if err == nil {
			break
		}
	}

	if verifiedBytes == nil {
		return nil, AuthError("Invalid JWT Signature")
	}

	standardClaims := StandardClaims{}
	if err := json.Unmarshal(verifiedBytes, &standardClaims); err != nil {
		return nil, AuthError("Invalid Token Data")
	}

	if time.Unix(standardClaims.Expiry, 0).Before(time.Now()) {
		return nil, AuthError("Expired Token")
	}

	if standardClaims.NotBefore != 0 {
		if time.Unix(standardClaims.NotBefore, 0).After(time.Now()) {
			return nil, AuthError("Too Early to use, Not Before is still in the future")
		}
	}

	return &VerifiedJWT{
		Raw:            verifiedBytes,
		StandardClaims: standardClaims,
	}, nil
}
