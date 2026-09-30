// Package rpthandler plugin.
package traefik_rpthandler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config the plugin configuration.
type Config struct {
	Keycloak string
	Audience string
	// CacheSeconds caps how long an RPT is reused, and so how long a permission change, logout or
	// revoked session in Keycloak can go unnoticed. 0 disables the cache.
	CacheSeconds int
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{CacheSeconds: 60}
}

// When full, the cache sweeps expired entries and then clears outright; concurrent misses for one
// token each go to Keycloak. An LRU or singleflight would fix either, if load tests show the need.
const maxCacheEntries = 10000

type cachedRpt struct {
	header  string
	expires time.Time
}

type RptHandler struct {
	next     http.Handler
	keycloak string
	audience string
	name     string
	maxTTL   time.Duration
	client   *http.Client

	mu    sync.Mutex
	cache map[[32]byte]cachedRpt
}

type RptTokenBody struct {
	Upgraded           bool
	Access_token       string
	Expires_in         int
	Refresh_expires_in int
	Refresh_token      string
	Token_type         string
	Not_before_policy  int
	Error              string
}

// New created a new RptHandler plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Keycloak) == 0 {
		return nil, fmt.Errorf("keycloak cannot be empty")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The default of 2 idle connections per host makes every burst open fresh TCP connections to Keycloak.
	transport.MaxIdleConnsPerHost = 100
	return &RptHandler{
		keycloak: config.Keycloak,
		audience: config.Audience,
		next:     next,
		name:     name,
		maxTTL:   time.Duration(config.CacheSeconds) * time.Second,
		client:   &http.Client{Transport: transport, Timeout: 10 * time.Second},
		cache:    map[[32]byte]cachedRpt{},
	}, nil
}

func (a *RptHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var currentAuthHeader = req.Header.Get("Authorization")
	var currentOrigin = req.Header.Get("Origin")

	if currentAuthHeader == "" || req.Method == "OPTIONS" {
		a.next.ServeHTTP(rw, req)
		return
	}

	key := sha256.Sum256([]byte(currentAuthHeader))
	if header, ok := a.lookup(key); ok {
		req.Header.Set("Authorization", header)
		a.next.ServeHTTP(rw, req)
		return
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	data.Set("audience", a.audience)

	newRequest, err := http.NewRequest(http.MethodPost, a.keycloak, strings.NewReader(data.Encode()))
	if err != nil {
		// handle error
		log.Println("Could not create new request", err.Error())
		rw.Header().Set("Access-Control-Allow-Origin", currentOrigin)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	newRequest.Header.Add("Authorization", currentAuthHeader)
	newRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.client.Do(newRequest)
	if err != nil {
		log.Println("Could not execute request", err.Error())
		rw.Header().Set("Access-Control-Allow-Origin", currentOrigin)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Could not read body from response", err.Error())
		rw.Header().Set("Access-Control-Allow-Origin", currentOrigin)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	// json parse
	var rptTokenBody RptTokenBody
	err = json.Unmarshal(body, &rptTokenBody)
	newAuthorizationHeader := "Bearer " + rptTokenBody.Access_token
	if err != nil {
		log.Println("Unmarshalling failed :", err.Error())
		rw.Header().Set("Access-Control-Allow-Origin", currentOrigin)
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	if len(rptTokenBody.Error) > 0 {
		if strings.Trim(rptTokenBody.Error, " ") == "invalid_grant" {
			// In case the access token has expired, sent a 401 instead of a 403
			log.Println("Invalid grant :", rptTokenBody.Error)
			rw.Header().Set("Access-Control-Allow-Origin", currentOrigin)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		//newAuthorizationHeader = b64.StdEncoding.EncodeToString(body)
		log.Println("Request failed :", rptTokenBody.Error)
		rw.Header().Set("Access-Control-Allow-Origin", currentOrigin)
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	a.store(key, newAuthorizationHeader, rptTokenBody.Expires_in, currentAuthHeader)

	req.Header.Set("Authorization", newAuthorizationHeader)
	a.next.ServeHTTP(rw, req)
}

func (a *RptHandler) lookup(key [32]byte) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.cache[key]
	if !ok || time.Now().After(entry.expires) {
		return "", false
	}
	return entry.header, true
}

// store caches the RPT until the earliest of: the cache cap, the RPT's expiry, and the incoming
// token's expiry. The last one matters: Keycloak rejects an expired token, so a cached RPT must
// not outlive the token it was exchanged for.
func (a *RptHandler) store(key [32]byte, header string, rptExpiresIn int, incoming string) {
	if a.maxTTL <= 0 {
		return
	}
	tokenExp, ok := jwtExpiry(incoming)
	if !ok {
		return
	}
	now := time.Now()
	expires := now.Add(a.maxTTL)
	// A few seconds' margin so the RPT doesn't expire on its way to the backend.
	if rpt := now.Add(time.Duration(rptExpiresIn)*time.Second - 5*time.Second); rpt.Before(expires) {
		expires = rpt
	}
	if tokenExp.Before(expires) {
		expires = tokenExp
	}
	if !expires.After(now) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= maxCacheEntries {
		for k, v := range a.cache {
			if now.After(v.expires) {
				delete(a.cache, k)
			}
		}
		if len(a.cache) >= maxCacheEntries {
			a.cache = map[[32]byte]cachedRpt{}
		}
	}
	a.cache[key] = cachedRpt{header: header, expires: expires}
}

// jwtExpiry reads exp from a "Bearer <jwt>" header without verifying the signature: the header
// is only ever a cache key for a token Keycloak has already accepted.
func jwtExpiry(authHeader string) (time.Time, bool) {
	parts := strings.Split(strings.TrimPrefix(authHeader, "Bearer "), ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
