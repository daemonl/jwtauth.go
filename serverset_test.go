package jwtauth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"gopkg.in/square/go-jose.v2"
)

func staticHandler(thing interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		bytes, err := json.Marshal(thing)
		if err != nil {
			fmt.Printf("ERR: %s\n", err.Error())
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
		w.Write(bytes)
	})
}

func testKey(kid string) *jose.JSONWebKey {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err.Error())
	}

	k := &jose.JSONWebKey{
		Key:       privKey,
		KeyID:     kid,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
	return k
}

func TestSingleServer(t *testing.T) {
	ks1 := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			testKey("Key1.a").Public(),
			testKey("Key.s").Public(),
		},
	}

	for _, tc := range []struct {
		name     string
		response interface{}
		status   int
		headers  map[string]string
		callback func(*testing.T, *Server)
	}{{
		name:     "success,cache",
		response: ks1,
		status:   200,
		headers: map[string]string{
			"Cache-Control": "private, max-age=100, otherthing",
		},
		callback: func(t *testing.T, s *Server) {
			duration, err := s.loadKeys()
			if err != nil {
				t.Fatal(err.Error())
			}

			if duration != time.Second*100 {
				t.Errorf("Bad Duration: %s", duration.String())
			}
		},
	}, {
		name:     "success,no-cache",
		response: ks1,
		status:   200,
		headers:  map[string]string{},
		callback: func(t *testing.T, s *Server) {
			duration, err := s.loadKeys()
			if err != nil {
				t.Fatal(err.Error())
			}

			if duration != 0 {
				t.Errorf("Bad Duration: %s", duration.String())
			}
		},
	}} {

		t.Run(tc.name, func(t *testing.T) {
			ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				bytes, err := json.Marshal(tc.response)
				if err != nil {
					t.Fatal(err.Error())
				}
				hdr := w.Header()
				for k, v := range tc.headers {
					hdr.Set(k, v)
				}
				w.WriteHeader(tc.status)
				w.Write(bytes)
			}))
			defer ts1.Close()

			tc.callback(t, &Server{
				url:    ts1.URL,
				client: ts1.Client(),
			})

		})

	}
}

func TestServerSetFetch(t *testing.T) {

	ks1 := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			testKey("Key1.a").Public(),
			testKey("Key.s").Public(),
		},
	}
	ks2 := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			testKey("Key2.a").Public(),
			testKey("Key.s").Public(),
		},
	}

	ts1 := httptest.NewServer(staticHandler(ks1))
	defer ts1.Close()

	ts2 := httptest.NewServer(staticHandler(ks2))
	defer ts2.Close()

	ss, err := NewServerSet(ts1.URL, ts2.URL)
	if err != nil {
		t.Fatal(err.Error())
	}

	ss.WaitForAllSuccess()

	if keys := ss.GetKeys("asdf"); len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}

	if keys := ss.GetKeys("Key1.a"); len(keys) != 1 {
		t.Errorf("Expected 1 keys, got %d", len(keys))
	}

	if keys := ss.GetKeys("Key.s"); len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}

}
