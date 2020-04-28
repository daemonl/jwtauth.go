package jwtauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

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
	statusAttempt *AnyAllWaitGroup
	statusSuccess *AnyAllWaitGroup
	Client        *http.Client
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
		go server.loop(statusAttempt.Child(), statusSuccess.Child())
		servers[idx] = server
	}

	return &ServerSet{
		servers:       servers,
		statusAttempt: statusAttempt,
		statusSuccess: statusSuccess,
		Client:        client,
	}, nil
}

func (ss *ServerSet) GetKeys(keyID string) []jose.JSONWebKey {
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

func (ss *Server) loop(doneAnything, doneSuccess interface{ Done() }) {
	for {
		refreshTime, err := ss.loadKeys()
		if err != nil {
			log.WithField("url", ss.url).
				WithField("error", err.Error()).
				Info("Failed to load JWKS")
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
