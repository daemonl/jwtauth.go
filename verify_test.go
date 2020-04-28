package jwtauth

import (
	"testing"
	"time"

	"github.com/square/go-jose/jwt"
	"gopkg.in/square/go-jose.v2"
)

func sign(privateKey *jose.JSONWebKey, claims *jwt.Claims) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.EdDSA,
			Key:       privateKey.Key,
		},
		(&jose.SignerOptions{}).
			WithHeader(jose.HeaderKey("kid"), privateKey.KeyID),
	)

	if err != nil {
		panic(err.Error())
	}

	str, err := jwt.
		Signed(signer).
		Claims(claims).
		CompactSerialize()

	if err != nil {
		panic(err.Error())
	}

	return str
}

func TestVerify(t *testing.T) {

	goodKey := testKey("Key1")
	falseKey := testKey("Key1")
	badKey := testKey("Key2")

	goodToken := sign(goodKey, &jwt.Claims{
		Subject: "sub1",
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	verifier := &Verifier{
		KeySource: Keyset{goodKey.Public()},
	}

	verified, err := verifier.VerifyJWT(goodToken)
	if err != nil {
		t.Fatalf("Verifying Good Token: %s", err.Error())
	}

	if verified.Subject != "sub1" {
		t.Errorf("Subject: %s", verified.Subject)
	}

	for _, tc := range []struct {
		name  string
		token string
	}{{
		name:  "corrupt",
		token: "corrupt",
	}, {
		name: "expired",
		token: sign(goodKey, &jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		}),
	}, {
		name: "un registered key",
		token: sign(badKey, &jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}),
	}, {
		name: "wrong key, but duplicate ID",
		token: sign(falseKey, &jwt.Claims{
			Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.VerifyJWT(tc.token); err == nil {
				t.Errorf("Expected an error")
			} else {
				t.Log(err.Error())
			}
		})
	}
}
