package traefik_rpthandler

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func jwt(exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return "Bearer h." + payload + ".s"
}

func TestRptIsCachedPerTokenAndNeverOutlivesIt(t *testing.T) {
	var calls int32
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		fmt.Fprint(w, `{"access_token":"rpt","expires_in":300}`)
	}))
	defer keycloak.Close()

	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("Authorization") })
	h, err := New(context.Background(), next, &Config{Keycloak: keycloak.URL, CacheSeconds: 60}, "t")
	if err != nil {
		t.Fatal(err)
	}
	send := func(token string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", token)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	long := jwt(time.Now().Add(time.Hour))
	send(long)
	send(long)
	if calls != 1 || seen != "Bearer rpt" {
		t.Fatalf("same token: want 1 Keycloak call and the RPT forwarded, got %d calls, %q", calls, seen)
	}

	send(jwt(time.Now().Add(2 * time.Hour)))
	if calls != 2 {
		t.Fatalf("different token must not share a cache entry, got %d calls", calls)
	}

	// Incoming token already expired: never cached, so Keycloak gets to reject every request.
	expired := jwt(time.Now().Add(-time.Second))
	send(expired)
	send(expired)
	if calls != 4 {
		t.Fatalf("expired token must not be served from cache, got %d calls", calls)
	}
}

func TestRptCacheHonoursRptExpiryAndCanBeDisabled(t *testing.T) {
	var calls int32
	expiresIn := 3 // under the 5s margin, so never worth caching
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		fmt.Fprintf(w, `{"access_token":"rpt","expires_in":%d}`, expiresIn)
	}))
	defer keycloak.Close()

	send := func(h http.Handler, token string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", token)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	token := jwt(time.Now().Add(time.Hour))

	short, _ := New(context.Background(), next, &Config{Keycloak: keycloak.URL, CacheSeconds: 60}, "t")
	send(short, token)
	send(short, token)
	if calls != 2 {
		t.Fatalf("an RPT about to expire must not be cached, got %d calls", calls)
	}

	expiresIn = 300
	off, _ := New(context.Background(), next, &Config{Keycloak: keycloak.URL, CacheSeconds: 0}, "t")
	send(off, token)
	send(off, token)
	if calls != 4 {
		t.Fatalf("CacheSeconds 0 must disable the cache, got %d calls", calls)
	}
}

func TestPreflightAndExpiredGrantKeepTheirBehaviour(t *testing.T) {
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer keycloak.Close()
	var reached bool
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	h, _ := New(context.Background(), next, &Config{Keycloak: keycloak.URL, CacheSeconds: 60}, "t")

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Authorization", jwt(time.Now().Add(time.Hour)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("an OPTIONS preflight must pass through without an exchange")
	}

	rec := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", jwt(time.Now().Add(time.Hour)))
	req.Header.Set("Origin", "https://app.example")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("invalid_grant: want 401 with the CORS origin, got %d %q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCacheIsOptIn(t *testing.T) {
	if CreateConfig().CacheSeconds != 0 {
		t.Fatal("the cache must be off unless a middleware sets cacheSeconds")
	}
}
