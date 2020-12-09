package jwtauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

type Keyset []jose.JSONWebKey

func (ks Keyset) GetKeys(keyID string) []jose.JSONWebKey {
	keys := make([]jose.JSONWebKey, 0, 1)
	for _, key := range ks {
		if key.KeyID == keyID {
			keys = append(keys, key)
		}
	}
	return keys
}

// ServerSet polls multiple JWKS remotes, and merges the keys from them all
type ServerSet struct {
	servers       []*Server
	directKeys    Keyset
	statusAttempt *AnyAllWaitGroup
	statusSuccess *AnyAllWaitGroup
	Client        *http.Client
	ErrorLogger   func(error)
	jwksBytes     []byte
	mutex         sync.RWMutex
	jwksMutex     sync.RWMutex
}

func NewServerSet(urls ...string) (*ServerSet, error) {
	servers := make([]*Server, len(urls))

	statusAttempt := NewAnyAllWaitGroup()
	statusSuccess := NewAnyAllWaitGroup()

	client := &http.Client{
		Timeout: time.Second * 5,
	}
	for idx, url := range urls {
		server := &Server{
			client: client,
			url:    url,
		}
		servers[idx] = server
	}

	ss := &ServerSet{
		servers:       servers,
		statusAttempt: statusAttempt,
		statusSuccess: statusSuccess,
		Client:        client,
		jwksBytes:     []byte(`{"keys":[]}`),
	}

	for _, server := range ss.servers {
		go server.loop(statusAttempt.Child(), statusSuccess.Child(), ss)
	}

	return ss, nil
}

func (ss *ServerSet) logError(err error) {
	if ss.ErrorLogger == nil {
		log.Printf("Failed to load JWKS: %s. (set ErrorLogger to supress or format this error)", err.Error())
	} else {
		ss.ErrorLogger(err)
	}
}

func (ss *ServerSet) AddKey(key jose.JSONWebKey) {
	ss.mutex.Lock()
	ss.directKeys = append(ss.directKeys, key)
	ss.mutex.Unlock()
	ss.rebuildJWKS()
}

func (ss *ServerSet) rebuildJWKS() {
	ss.jwksMutex.Lock()
	defer ss.jwksMutex.Unlock()
	keys := make([]jose.JSONWebKey, 0, 1)

	for _, server := range ss.servers {
		if server.keyset == nil {
			continue
		}
		for _, key := range server.keyset.Keys {
			keys = append(keys, key)
		}
	}

	for _, key := range ss.directKeys {
		keys = append(keys, key)
	}

	keySet := jose.JSONWebKeySet{
		Keys: keys,
	}

	keyBytes, err := json.Marshal(keySet)
	if err != nil {
		return
	}
	ss.jwksBytes = keyBytes
}

func (ss *ServerSet) JWKS() []byte {
	ss.jwksMutex.RLock()
	defer ss.jwksMutex.RUnlock()
	return ss.jwksBytes
}

func (ss *ServerSet) GetKeys(keyID string) []jose.JSONWebKey {
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()
	keys := make([]jose.JSONWebKey, 0, 1)

	for _, server := range ss.servers {
		if server.keyset == nil {
			continue
		}
		for _, key := range server.keyset.Keys {
			if key.KeyID == keyID {
				keys = append(keys, key)
			}

		}
	}

	for _, key := range ss.directKeys {
		if key.KeyID == keyID {
			keys = append(keys, key)
		}
	}

	return keys
}

func (ss *ServerSet) WaitForAnySuccess() {
	ss.statusSuccess.WaitAny()
}
func (ss *ServerSet) WaitForAllAttempt() {
	ss.statusAttempt.WaitAll()
}
func (ss *ServerSet) WaitForAllSuccess() {
	ss.statusSuccess.WaitAll()
}

type Server struct {
	keyset *jose.JSONWebKeySet
	url    string
	client *http.Client
	lock   sync.RWMutex
}

func (ss *Server) loop(doneAnything, doneSuccess interface{ Done() }, onError interface{ logError(error) }) {
	for {
		refreshTime, err := ss.loadKeys()
		if err != nil {
			onError.logError(fmt.Errorf("failed to read JWKS from %s: %w", ss.url, err))
		} else {
			doneSuccess.Done()
		}
		doneAnything.Done()

		if refreshTime < time.Second*30 {
			refreshTime = time.Second * 30
		}

		time.Sleep(refreshTime)
	}
}

func (ss *Server) loadKeys() (time.Duration, error) {
	req, err := http.NewRequest("GET", ss.url, nil)
	if err != nil {
		return 0, err
	}

	res, err := ss.client.Do(req)
	if err != nil {
		return 0, err
	}

	defer res.Body.Close()

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, fmt.Errorf("reading from %s: %w", ss.url, err)
	}

	keyset := &jose.JSONWebKeySet{}

	if err := json.Unmarshal(bodyBytes, keyset); err != nil {
		return 0, err
	}

	refreshTime := cacheDuration(res.Header.Get("Cache-Control"))

	ss.lock.Lock()
	defer ss.lock.Unlock()
	ss.keyset = keyset
	return refreshTime, nil
}

func cacheDuration(raw string) time.Duration {
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		eqParts := strings.Split(part, "=")
		if len(eqParts) != 2 {
			continue
		}
		if eqParts[0] == "max-age" {
			seconds, err := strconv.ParseInt(eqParts[1], 10, 64)
			if err != nil {
				continue
			}
			return time.Duration(seconds) * time.Second
		}
	}

	return 0
}
