// Package rpthandler plugin.
package traefik_rpthandler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	Keycloak string
	Audience string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type RptHandler struct {
	next     http.Handler
	keycloak string
	audience string
	name     string
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
	return &RptHandler{
		keycloak: config.Keycloak,
		audience: config.Audience,
		next:     next,
		name:     name,
	}, nil
}

func (a *RptHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var currentAuthHeader = req.Header.Get("Authorization")
	var currentOrigin = req.Header.Get("Origin")

	if currentAuthHeader == "" || req.Method == "OPTIONS" {
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

	client := &http.Client{}
	resp, err := client.Do(newRequest)
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

	req.Header.Set("Authorization", newAuthorizationHeader)
	a.next.ServeHTTP(rw, req)
}
