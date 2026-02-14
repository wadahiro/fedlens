package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/oauth2"
)

// --- OIDC session ---

type JWTSignatureInfo struct {
	Algorithm string // JWT header alg (e.g. "RS256")
	KeyID     string // JWT header kid
	KeyType   string // JWKS kty (e.g. "RSA")
	KeyUse    string // JWKS use (e.g. "sig")
	KeyAlg    string // JWKS alg
	Verified  bool
}

type OidcSession struct {
	Claims              map[string]interface{}
	AuthRequestURL      string
	AuthResponseCode    string
	AuthResponseRaw     string
	TokenResponse       json.RawMessage
	IDTokenRaw          string
	AccessTokenRaw      string
	UserInfoResponse    json.RawMessage
	IDTokenSigInfo      *JWTSignatureInfo
	AccessTokenSigInfo  *JWTSignatureInfo
	JWKSResponse        json.RawMessage
}

var (
	oidcSessions   = map[string]*OidcSession{}
	oidcSessionsMu sync.RWMutex
)

// --- SAML debug session ---

type SAMLSignatureInfo struct {
	Target               string // "Response" or "Assertion"
	Algorithm            string // SignatureMethod URI
	AlgorithmShort       string // e.g. "rsa-sha256"
	DigestAlgorithm      string // DigestMethod URI
	DigestAlgorithmShort string
	CertSubject          string
	CertIssuer           string
	CertSerialNumber     string
	CertNotBefore        string
	CertNotAfter         string
	CertFingerprint      string // SHA-256 colon-separated hex
	Verified             bool
}

type SamlDebugSession struct {
	AuthnRequestXML string
	SAMLResponseXML string
	SignatureInfos  []SAMLSignatureInfo
}

var (
	samlDebugSessions   = map[string]*SamlDebugSession{}
	samlDebugSessionsMu sync.RWMutex
)

var (
	oidcHost    string
	samlHost    string
	oidcBaseURL string // scheme://host (derived from OIDC_REDIRECT_URI)
	samlBaseURL string // scheme://host (derived from SAML_ROOT_URL)
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		resp, err := http.Get("http://localhost:3000/healthz")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	oidcHost = requireEnv("OIDC_HOST")
	samlHost = requireEnv("SAML_HOST")

	// Derive base URLs (scheme://host) for navigation links
	if redirectURI, err := url.Parse(requireEnv("OIDC_REDIRECT_URI")); err == nil {
		oidcBaseURL = redirectURI.Scheme + "://" + redirectURI.Host
	} else {
		log.Fatalf("Invalid OIDC_REDIRECT_URI: %v", err)
	}
	if rootURL, err := url.Parse(requireEnv("SAML_ROOT_URL")); err == nil {
		samlBaseURL = rootURL.Scheme + "://" + rootURL.Host
	} else {
		log.Fatalf("Invalid SAML_ROOT_URL: %v", err)
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":3000"
	}

	insecureSkipVerify := strings.EqualFold(os.Getenv("INSECURE_SKIP_VERIFY"), "true")

	httpClient := &http.Client{}
	if insecureSkipVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		log.Println("WARNING: TLS certificate verification is disabled")
	}

	oidcRouter := setupOIDC(httpClient)
	samlRouter := setupSAML(httpClient)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case oidcHost:
			oidcRouter.ServeHTTP(w, r)
		case samlHost:
			samlRouter.ServeHTTP(w, r)
		default:
			http.Error(w, "Unknown host", http.StatusNotFound)
		}
	})

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Listening on %s (OIDC: %s, SAML: %s)", listenAddr, oidcHost, samlHost)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// --- OIDC setup ---

func setupOIDC(httpClient *http.Client) http.Handler {
	issuer := requireEnv("OIDC_ISSUER")
	clientID := requireEnv("OIDC_CLIENT_ID")
	clientSecret := requireEnv("OIDC_CLIENT_SECRET")
	redirectURI := requireEnv("OIDC_REDIRECT_URI")

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	var (
		provider *oidc.Provider
		err      error
	)
	for i := range 30 {
		provider, err = oidc.NewProvider(ctx, issuer)
		if err == nil {
			break
		}
		log.Printf("OIDC provider discovery attempt %d/30 failed: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to discover OIDC provider after retries: %v", err)
	}
	log.Printf("OIDC provider discovered: %s", issuer)

	// Fetch raw OIDC Discovery metadata
	var discoveryRaw json.RawMessage
	if resp, err := httpClient.Get(issuer + "/.well-known/openid-configuration"); err == nil {
		defer resp.Body.Close()
		if body, err := io.ReadAll(resp.Body); err == nil {
			discoveryRaw = json.RawMessage(body)
		}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	var providerClaims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
		UserinfoEndpoint   string `json:"userinfo_endpoint"`
		JwksURI            string `json:"jwks_uri"`
	}
	if err := provider.Claims(&providerClaims); err != nil {
		log.Printf("WARNING: Could not extract provider claims: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		session := getOidcSession(r)
		if session == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Test OIDC App</title></head>
<body>
`)
			fmt.Fprint(w, navTabs("OIDC"))
			fmt.Fprint(w, `<h1>Not logged in (OIDC)</h1>
<a href="/login">Login</a>
`)
		if len(discoveryRaw) > 0 {
			fmt.Fprint(w, `
<h2>OpenID Provider Configuration</h2>
<pre>`)
			fmt.Fprint(w, htmlEscape(prettyJSON(discoveryRaw)))
			fmt.Fprint(w, `</pre>
`)
		}
		fmt.Fprint(w, `</body></html>`)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Test OIDC App</title></head>
<body>
`)
		fmt.Fprint(w, navTabs("OIDC"))
		fmt.Fprint(w, `<h1>Logged in (OIDC)</h1>
<a href="/logout">Logout</a>

<h2>ID Token Claims</h2>
<table id="id-token-claims">
`)
		keys := sortedKeys(session.Claims)
		for _, k := range keys {
			v := formatClaimValue(k, session.Claims[k])
			fmt.Fprintf(w, `<tr data-attr="%s"><td>%s</td><td>%s</td></tr>
`, htmlEscape(k), htmlEscape(k), htmlEscape(v))
		}
		fmt.Fprint(w, `</table>
`)

		// ID Token Signature Verification
		if session.IDTokenSigInfo != nil {
			fmt.Fprint(w, `
<h2>ID Token Signature Verification</h2>
<table id="id-token-sig-info">
`)
			writeSigInfoRows(w, session.IDTokenSigInfo)
			fmt.Fprint(w, `</table>
`)
		}

		// Access Token Claims table (JWT only)
		if isJWT(session.AccessTokenRaw) {
			_, atPayloadRaw := decodeJWTRaw(session.AccessTokenRaw)
			var atClaims map[string]interface{}
			if json.Unmarshal(atPayloadRaw, &atClaims) == nil {
				fmt.Fprint(w, `
<h2>Access Token Claims</h2>
<table id="access-token-claims">
`)
				for _, k := range sortedKeys(atClaims) {
					v := formatClaimValue(k, atClaims[k])
					fmt.Fprintf(w, `<tr data-attr="%s"><td>%s</td><td>%s</td></tr>
`, htmlEscape(k), htmlEscape(k), htmlEscape(v))
				}
				fmt.Fprint(w, `</table>
`)
			}

			// Access Token Signature Verification
			if session.AccessTokenSigInfo != nil {
				fmt.Fprint(w, `
<h2>Access Token Signature Verification</h2>
<table id="access-token-sig-info">
`)
				writeSigInfoRows(w, session.AccessTokenSigInfo)
				fmt.Fprint(w, `</table>
`)
			}
		}

		// UserInfo Claims table
		if len(session.UserInfoResponse) > 0 {
			var userInfoClaims map[string]interface{}
			if json.Unmarshal(session.UserInfoResponse, &userInfoClaims) == nil {
				fmt.Fprint(w, `
<h2>UserInfo Claims</h2>
<table id="userinfo-claims">
`)
				for _, k := range sortedKeys(userInfoClaims) {
					v := formatClaimValue(k, userInfoClaims[k])
					fmt.Fprintf(w, `<tr data-attr="%s"><td>%s</td><td>%s</td></tr>
`, htmlEscape(k), htmlEscape(k), htmlEscape(v))
				}
				fmt.Fprint(w, `</table>
`)
			}
		}

		fmt.Fprint(w, `
<h2>Authorization Request</h2>
<pre>`)
		fmt.Fprint(w, htmlEscape(session.AuthRequestURL))
		fmt.Fprint(w, `</pre>

<h2>Authorization Response</h2>
<pre>`)
		fmt.Fprint(w, htmlEscape(session.AuthResponseRaw))
		fmt.Fprint(w, `</pre>

<h2>Token Response</h2>
<pre>`)
		fmt.Fprint(w, htmlEscape(prettyJSON(session.TokenResponse)))
		fmt.Fprint(w, `</pre>

<h2>ID Token</h2>
`)
		header, payload := decodeJWT(session.IDTokenRaw)
		fmt.Fprint(w, `<h3>Header</h3>
<pre>`)
		fmt.Fprint(w, htmlEscape(header))
		fmt.Fprint(w, `</pre>
<h3>Payload</h3>
<pre>`)
		fmt.Fprint(w, htmlEscape(payload))
		fmt.Fprint(w, `</pre>

<h2>Access Token</h2>
<pre>`)
		if isJWT(session.AccessTokenRaw) {
			atHeader, atPayload := decodeJWT(session.AccessTokenRaw)
			fmt.Fprintf(w, "Header:\n%s\n\nPayload:\n%s", htmlEscape(atHeader), htmlEscape(atPayload))
		} else {
			fmt.Fprint(w, htmlEscape(session.AccessTokenRaw))
		}
		fmt.Fprint(w, `</pre>

<h2>UserInfo Response</h2>
<pre>`)
		fmt.Fprint(w, htmlEscape(prettyJSON(session.UserInfoResponse)))
		fmt.Fprint(w, `</pre>
`)

		// JWKS Response
		if len(session.JWKSResponse) > 0 {
			fmt.Fprint(w, `
<h2>JWKS Response</h2>
<pre>`)
			fmt.Fprint(w, htmlEscape(prettyJSON(session.JWKSResponse)))
			fmt.Fprint(w, `</pre>
`)
		}

		if len(discoveryRaw) > 0 {
			fmt.Fprint(w, `
<h2>OpenID Provider Configuration</h2>
<pre>`)
			fmt.Fprint(w, htmlEscape(prettyJSON(discoveryRaw)))
			fmt.Fprint(w, `</pre>
`)
		}

		fmt.Fprint(w, `</body></html>`)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state, err := randomHex(16)
		if err != nil {
			log.Printf("Failed to generate state: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_state",
			Value:    state,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		authURL := oauth2Config.AuthCodeURL(state)
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_auth_request_url",
			Value:    authURL,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, authURL, http.StatusFound)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		stateCookie, err := r.Cookie("oidc_state")
		if err != nil {
			log.Printf("Missing state cookie: %v", err)
			http.Error(w, "Missing state cookie", http.StatusBadRequest)
			return
		}

		if r.URL.Query().Get("state") != stateCookie.Value {
			log.Println("State mismatch")
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}

		// Clear state cookie
		http.SetCookie(w, &http.Cookie{
			Name: "oidc_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		})

		// Retrieve auth request URL from cookie
		var authRequestURL string
		if c, err := r.Cookie("oidc_auth_request_url"); err == nil {
			authRequestURL = c.Value
		}
		http.SetCookie(w, &http.Cookie{
			Name: "oidc_auth_request_url", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		})

		code := r.URL.Query().Get("code")
		authResponseRaw := r.URL.RawQuery

		tokenCtx := context.WithValue(r.Context(), oauth2.HTTPClient, httpClient)
		token, err := oauth2Config.Exchange(tokenCtx, code)
		if err != nil {
			log.Printf("Token exchange failed: %v", err)
			http.Error(w, "Token exchange failed", http.StatusInternalServerError)
			return
		}

		tokenResponseJSON := marshalTokenResponse(token)

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Println("No id_token in token response")
			http.Error(w, "No id_token in token response", http.StatusInternalServerError)
			return
		}

		idToken, err := verifier.Verify(tokenCtx, rawIDToken)
		if err != nil {
			log.Printf("ID token verification failed: %v", err)
			http.Error(w, "ID token verification failed", http.StatusInternalServerError)
			return
		}

		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			log.Printf("Failed to extract claims: %v", err)
			http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
			return
		}

		// Fetch UserInfo
		var userInfoResponse json.RawMessage
		if providerClaims.UserinfoEndpoint != "" {
			userInfoResponse = fetchUserInfo(httpClient, providerClaims.UserinfoEndpoint, token.AccessToken)
		}

		// Fetch JWKS and build signature info
		var jwksRaw json.RawMessage
		if providerClaims.JwksURI != "" {
			jwksRaw = fetchJWKS(httpClient, providerClaims.JwksURI)
		}
		idTokenSigInfo := buildJWTSignatureInfo(rawIDToken, jwksRaw, true)
		var accessTokenSigInfo *JWTSignatureInfo
		if isJWT(token.AccessToken) {
			accessTokenSigInfo = buildJWTSignatureInfo(token.AccessToken, jwksRaw, true)
		}

		sessionID, err := randomHex(32)
		if err != nil {
			log.Printf("Failed to generate session ID: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		oidcSessionsMu.Lock()
		oidcSessions[sessionID] = &OidcSession{
			Claims:             claims,
			AuthRequestURL:     authRequestURL,
			AuthResponseCode:   code,
			AuthResponseRaw:    authResponseRaw,
			TokenResponse:      tokenResponseJSON,
			IDTokenRaw:         rawIDToken,
			AccessTokenRaw:     token.AccessToken,
			UserInfoResponse:   userInfoResponse,
			IDTokenSigInfo:     idTokenSigInfo,
			AccessTokenSigInfo: accessTokenSigInfo,
			JWKSResponse:       jwksRaw,
		}
		oidcSessionsMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Derive the top-page URL from the redirect URI for post-logout redirect
	redirectParsed, err := url.Parse(redirectURI)
	if err != nil {
		log.Fatalf("Invalid OIDC_REDIRECT_URI: %v", err)
	}
	oidcTopPageURL := redirectParsed.Scheme + "://" + redirectParsed.Host + "/"

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == nil {
			oidcSessionsMu.Lock()
			delete(oidcSessions, cookie.Value)
			oidcSessionsMu.Unlock()
		}

		http.SetCookie(w, &http.Cookie{
			Name: "session_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		})

		if providerClaims.EndSessionEndpoint != "" {
			logoutURL := providerClaims.EndSessionEndpoint + "?post_logout_redirect_uri=" + url.QueryEscape(oidcTopPageURL) + "&client_id=" + url.QueryEscape(clientID)
			http.Redirect(w, r, logoutURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	return mux
}

// --- SAML setup ---

func setupSAML(httpClient *http.Client) http.Handler {
	idpMetadataURLStr := requireEnv("SAML_IDP_METADATA_URL")
	entityID := requireEnv("SAML_ENTITY_ID")
	rootURLStr := requireEnv("SAML_ROOT_URL")

	rootURL, err := url.Parse(rootURLStr)
	if err != nil {
		log.Fatalf("Invalid SAML_ROOT_URL: %v", err)
	}

	keyPair, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	idpMetadataURL, err := url.Parse(idpMetadataURLStr)
	if err != nil {
		log.Fatalf("Invalid SAML_IDP_METADATA_URL: %v", err)
	}

	var idpMetadata *saml.EntityDescriptor
	for i := range 30 {
		idpMetadata, err = samlsp.FetchMetadata(context.Background(), httpClient, *idpMetadataURL)
		if err == nil {
			break
		}
		log.Printf("SAML IdP metadata fetch attempt %d/30 failed: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to fetch SAML IdP metadata after retries: %v", err)
	}
	log.Printf("SAML IdP metadata fetched: %s", idpMetadataURLStr)

	// Fetch raw IdP Metadata XML
	var idpMetadataRaw string
	if resp, err := httpClient.Get(idpMetadataURLStr); err == nil {
		defer resp.Body.Close()
		if body, err := io.ReadAll(resp.Body); err == nil {
			idpMetadataRaw = string(body)
		}
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.key,
		Certificate:    keyPair.cert,
		IDPMetadata:    idpMetadata,
		EntityID:       entityID,
		SignRequest:    false,
		LogoutBindings: []string{saml.HTTPPostBinding, saml.HTTPRedirectBinding},
	})
	if err != nil {
		log.Fatalf("Failed to create SAML SP: %v", err)
	}

	mux := http.NewServeMux()

	// Custom ACS handler to capture SAML Response XML
	mux.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			log.Printf("Failed to parse ACS form: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Decode SAMLResponse from Base64 and store in debug session
		if samlResponseB64 := r.PostForm.Get("SAMLResponse"); samlResponseB64 != "" {
			if samlResponseXMLBytes, err := base64.StdEncoding.DecodeString(samlResponseB64); err == nil {
				if c, err := r.Cookie("saml_debug_id"); err == nil {
					samlDebugSessionsMu.Lock()
					if ds, ok := samlDebugSessions[c.Value]; ok {
						ds.SAMLResponseXML = string(samlResponseXMLBytes)
						ds.SignatureInfos = extractSAMLSignatureInfos(string(samlResponseXMLBytes))
					}
					samlDebugSessionsMu.Unlock()
				}
			}
		}

		// Delegate to samlsp's standard ACS processing
		samlSP.ServeACS(w, r)
	})

	// SP metadata (delegate to samlsp)
	mux.Handle("/saml/metadata", samlSP)

	// SLO endpoint: receive LogoutResponse from IdP after SP-initiated logout
	mux.HandleFunc("/saml/slo", func(w http.ResponseWriter, r *http.Request) {
		// Delete SP session if still present
		samlSP.Session.DeleteSession(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		session, err := samlSP.Session.GetSession(r)
		if err != nil || session == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Test SAML App</title></head>
<body>
`)
			fmt.Fprint(w, navTabs("SAML"))
			fmt.Fprint(w, `<h1>Not logged in (SAML)</h1>
<a href="/login">Login</a>
`)
		if idpMetadataRaw != "" {
			fmt.Fprint(w, `
<h2>IdP Metadata</h2>
<pre>`)
			fmt.Fprint(w, htmlEscape(formatXML(idpMetadataRaw)))
			fmt.Fprint(w, `</pre>
`)
		}
		fmt.Fprint(w, `</body></html>`)
			return
		}

		sa, ok := session.(samlsp.SessionWithAttributes)
		if !ok {
			http.Error(w, "Invalid session", http.StatusInternalServerError)
			return
		}
		attrs := sa.GetAttributes()

		var debugSession *SamlDebugSession
		if c, err := r.Cookie("saml_debug_id"); err == nil {
			samlDebugSessionsMu.RLock()
			debugSession = samlDebugSessions[c.Value]
			samlDebugSessionsMu.RUnlock()
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Test SAML App</title></head>
<body>
`)
		fmt.Fprint(w, navTabs("SAML"))
		fmt.Fprint(w, `<h1>Logged in (SAML)</h1>
<a href="/logout">Logout</a>

<h2>Attributes</h2>
<table>
`)
		attrKeys := sortedKeys(toStringMap(attrs))
		for _, k := range attrKeys {
			v := attrs.Get(k)
			fmt.Fprintf(w, `<tr data-attr="%s"><td>%s</td><td>%s</td></tr>
`, htmlEscape(k), htmlEscape(k), htmlEscape(v))
		}
		fmt.Fprint(w, `</table>
`)

		// Signature Verification
		if debugSession != nil && len(debugSession.SignatureInfos) > 0 {
			for _, sigInfo := range debugSession.SignatureInfos {
				fmt.Fprintf(w, `
<h2>%s Signature Verification</h2>
<table>
`, htmlEscape(sigInfo.Target))
				verifiedStr := "false"
				if sigInfo.Verified {
					verifiedStr = "true"
				}
				rows := []struct{ label, value string }{
					{"Signature Algorithm", sigInfo.Algorithm},
					{"Signature Algorithm (short)", sigInfo.AlgorithmShort},
					{"Digest Algorithm", sigInfo.DigestAlgorithm},
					{"Digest Algorithm (short)", sigInfo.DigestAlgorithmShort},
					{"Certificate Subject", sigInfo.CertSubject},
					{"Certificate Issuer", sigInfo.CertIssuer},
					{"Certificate Serial Number", sigInfo.CertSerialNumber},
					{"Certificate Not Before", sigInfo.CertNotBefore},
					{"Certificate Not After", sigInfo.CertNotAfter},
					{"Certificate Fingerprint (SHA-256)", sigInfo.CertFingerprint},
					{"Verified", verifiedStr},
				}
				for _, row := range rows {
					if row.value != "" {
						fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>\n", htmlEscape(row.label), htmlEscape(row.value))
					}
				}
				fmt.Fprint(w, `</table>
`)
			}
		}

		if debugSession != nil {
			fmt.Fprint(w, `
<h2>AuthnRequest</h2>
<pre>`)
			fmt.Fprint(w, htmlEscape(formatXML(debugSession.AuthnRequestXML)))
			fmt.Fprint(w, `</pre>

<h2>SAML Response</h2>
<pre>`)
			fmt.Fprint(w, htmlEscape(formatXML(debugSession.SAMLResponseXML)))
			fmt.Fprint(w, `</pre>
`)
		}

		if idpMetadataRaw != "" {
			fmt.Fprint(w, `
<h2>IdP Metadata</h2>
<pre>`)
			fmt.Fprint(w, htmlEscape(formatXML(idpMetadataRaw)))
			fmt.Fprint(w, `</pre>
`)
		}

		fmt.Fprint(w, `</body></html>`)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		debugID, err := randomHex(16)
		if err != nil {
			log.Printf("Failed to generate debug ID: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Determine binding (same logic as HandleStartAuthFlow)
		binding := saml.HTTPRedirectBinding
		bindingLocation := samlSP.ServiceProvider.GetSSOBindingLocation(binding)
		if bindingLocation == "" {
			binding = saml.HTTPPostBinding
			bindingLocation = samlSP.ServiceProvider.GetSSOBindingLocation(binding)
		}

		// Generate AuthnRequest
		authReq, err := samlSP.ServiceProvider.MakeAuthenticationRequest(
			bindingLocation, binding, saml.HTTPPostBinding,
		)
		if err != nil {
			log.Printf("Failed to make AuthnRequest: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Serialize AuthnRequest to XML for debug display
		xmlDoc := etree.NewDocument()
		xmlDoc.SetRoot(authReq.Element())
		xmlBytes, err := xmlDoc.WriteToBytes()
		if err != nil {
			log.Printf("Failed to serialize AuthnRequest XML: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		samlDebugSessionsMu.Lock()
		samlDebugSessions[debugID] = &SamlDebugSession{
			AuthnRequestXML: string(xmlBytes),
		}
		samlDebugSessionsMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "saml_debug_id",
			Value:    debugID,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Track request (stores original URI and returns RelayState)
		// Use "/" as the redirect-back URI so ACS redirects to top page
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		r2.RequestURI = "/"
		relayState, err := samlSP.RequestTracker.TrackRequest(w, r2, authReq.ID)
		if err != nil {
			log.Printf("Failed to track request: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirect to IdP
		if binding == saml.HTTPRedirectBinding {
			redirectURL, err := authReq.Redirect(relayState, &samlSP.ServiceProvider)
			if err != nil {
				log.Printf("Failed to build redirect URL: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.Header().Add("Location", redirectURL.String())
			w.WriteHeader(http.StatusFound)
		} else {
			w.Header().Add("Content-Security-Policy", ""+
				"default-src; "+
				"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
				"reflected-xss block; "+
				"referrer no-referrer;")
			w.Header().Add("Content-type", "text/html")
			w.Write([]byte(`<!DOCTYPE html><html><body>`))
			w.Write(authReq.Post(relayState))
			w.Write([]byte(`</body></html>`))
		}
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// Get NameID from current session before deleting it
		var nameID string
		if session, err := samlSP.Session.GetSession(r); err == nil && session != nil {
			if claims, ok := session.(samlsp.JWTSessionClaims); ok {
				nameID = claims.Subject
			}
		}

		// Delete SP session cookie
		samlSP.Session.DeleteSession(w, r)

		if c, err := r.Cookie("saml_debug_id"); err == nil {
			samlDebugSessionsMu.Lock()
			delete(samlDebugSessions, c.Value)
			samlDebugSessionsMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{
			Name: "saml_debug_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		})

		// Send SAML LogoutRequest to IdP
		if nameID != "" {
			if sloURL := samlSP.ServiceProvider.GetSLOBindingLocation(saml.HTTPRedirectBinding); sloURL != "" {
				redirectURL, err := samlSP.ServiceProvider.MakeRedirectLogoutRequest(nameID, rootURLStr+"/")
				if err == nil {
					http.Redirect(w, r, redirectURL.String(), http.StatusFound)
					return
				}
				log.Printf("Failed to create SAML logout request: %v", err)
			}
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	return mux
}

// --- navigation ---

func navTabs(active string) string {
	tabs := []struct{ label, baseURL string }{
		{"OIDC", oidcBaseURL},
		{"SAML", samlBaseURL},
	}
	var sb strings.Builder
	sb.WriteString(`<nav style="display:flex;gap:0;margin-bottom:1em;border-bottom:2px solid #ccc">`)
	for _, t := range tabs {
		if t.label == active {
			sb.WriteString(fmt.Sprintf(`<span style="padding:8px 16px;border:2px solid #ccc;border-bottom:2px solid #fff;margin-bottom:-2px;font-weight:bold">%s</span>`, t.label))
		} else {
			sb.WriteString(fmt.Sprintf(`<a href="%s/" style="padding:8px 16px;text-decoration:none;color:#666">%s</a>`, t.baseURL, t.label))
		}
	}
	sb.WriteString(`</nav>`)
	return sb.String()
}

// --- helpers ---

func getOidcSession(r *http.Request) *OidcSession {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	oidcSessionsMu.RLock()
	defer oidcSessionsMu.RUnlock()
	return oidcSessions[cookie.Value]
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func requireEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return val
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func prettyJSON(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return string(data)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(b)
}

var jst = time.FixedZone("JST", 9*60*60)

var timestampClaims = map[string]bool{
	"auth_time": true,
	"exp":       true,
	"iat":       true,
	"nbf":       true,
	"updated_at": true,
}

func formatClaimValue(key string, v interface{}) string {
	raw := formatValue(v)
	if !timestampClaims[key] {
		return raw
	}
	if n, ok := v.(float64); ok && n == float64(int64(n)) {
		t := time.Unix(int64(n), 0).In(jst)
		return fmt.Sprintf("%s (%s)", raw, t.Format("2006-01-02T15:04:05 MST"))
	}
	return raw
}

func formatValue(v interface{}) string {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return fmt.Sprintf("%d", int64(n))
		}
		return fmt.Sprintf("%g", n)
	case json.Number:
		return n.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func isJWT(s string) bool {
	return strings.Count(s, ".") == 2
}

func decodeJWT(token string) (header, payload string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return token, ""
	}
	header = decodeBase64URL(parts[0])
	payload = decodeBase64URL(parts[1])
	return
}

func decodeJWTRaw(token string) (header, payload []byte) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return []byte(token), nil
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	return h, p
}

func decodeBase64URL(s string) string {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return prettyJSON(json.RawMessage(b))
}

func marshalTokenResponse(token *oauth2.Token) json.RawMessage {
	m := map[string]interface{}{
		"access_token": token.AccessToken,
		"token_type":   token.TokenType,
		"expiry":       token.Expiry,
	}
	if idToken := token.Extra("id_token"); idToken != nil {
		m["id_token"] = idToken
	}
	if refreshToken := token.Extra("refresh_token"); refreshToken != nil {
		m["refresh_token"] = refreshToken
	}
	if scope := token.Extra("scope"); scope != nil {
		m["scope"] = scope
	}
	b, _ := json.Marshal(m)
	return b
}

func fetchUserInfo(client *http.Client, userinfoURL, accessToken string) json.RawMessage {
	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		log.Printf("Failed to create userinfo request: %v", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch userinfo: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		log.Printf("Failed to decode userinfo response: %v", err)
		return nil
	}
	return raw
}

func fetchJWKS(client *http.Client, jwksURL string) json.RawMessage {
	resp, err := client.Get(jwksURL)
	if err != nil {
		log.Printf("Failed to fetch JWKS: %v", err)
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read JWKS response: %v", err)
		return nil
	}
	return json.RawMessage(body)
}

func extractJWTHeaderInfo(jwtRaw string) (alg, kid string) {
	headerRaw, _ := decodeJWTRaw(jwtRaw)
	if headerRaw == nil {
		return
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) == nil {
		alg = header.Alg
		kid = header.Kid
	}
	return
}

func buildJWTSignatureInfo(jwtRaw string, jwksRaw json.RawMessage, verified bool) *JWTSignatureInfo {
	alg, kid := extractJWTHeaderInfo(jwtRaw)
	if alg == "" {
		return nil
	}
	info := &JWTSignatureInfo{
		Algorithm: alg,
		KeyID:     kid,
		Verified:  verified,
	}
	if len(jwksRaw) > 0 && kid != "" {
		var jwks struct {
			Keys []struct {
				Kid string `json:"kid"`
				Kty string `json:"kty"`
				Use string `json:"use"`
				Alg string `json:"alg"`
			} `json:"keys"`
		}
		if json.Unmarshal(jwksRaw, &jwks) == nil {
			for _, k := range jwks.Keys {
				if k.Kid == kid {
					info.KeyType = k.Kty
					info.KeyUse = k.Use
					info.KeyAlg = k.Alg
					break
				}
			}
		}
	}
	return info
}

func writeSigInfoRows(w http.ResponseWriter, info *JWTSignatureInfo) {
	if info == nil {
		return
	}
	verifiedStr := "false"
	if info.Verified {
		verifiedStr = "true"
	}
	rows := []struct{ label, value string }{
		{"Algorithm", info.Algorithm},
		{"Key ID (kid)", info.KeyID},
		{"Key Type (kty)", info.KeyType},
		{"Key Use (use)", info.KeyUse},
		{"Key Algorithm (alg)", info.KeyAlg},
		{"Verified", verifiedStr},
	}
	for _, row := range rows {
		if row.value != "" {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>\n", htmlEscape(row.label), htmlEscape(row.value))
		}
	}
}

func extractSAMLSignatureInfos(xmlStr string) []SAMLSignatureInfo {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		log.Printf("Failed to parse SAML XML: %v", err)
		return nil
	}
	root := doc.Root()
	if root == nil {
		return nil
	}

	var infos []SAMLSignatureInfo

	// Check Response-level signature
	if info := parseSAMLSignature("Response", root); info != nil {
		infos = append(infos, *info)
	}

	// Check Assertion-level signature(s)
	for _, assertion := range root.SelectElements("Assertion") {
		if info := parseSAMLSignature("Assertion", assertion); info != nil {
			infos = append(infos, *info)
		}
	}
	// Also check with namespace prefix
	for _, assertion := range root.FindElements("//saml:Assertion") {
		if info := parseSAMLSignature("Assertion", assertion); info != nil {
			// Avoid duplicates
			dup := false
			for _, existing := range infos {
				if existing.Target == "Assertion" {
					dup = true
					break
				}
			}
			if !dup {
				infos = append(infos, *info)
			}
		}
	}

	return infos
}

func parseSAMLSignature(target string, elem *etree.Element) *SAMLSignatureInfo {
	// Look for ds:Signature or Signature as direct child
	var sigElem *etree.Element
	for _, child := range elem.ChildElements() {
		localName := child.Tag
		if localName == "Signature" {
			sigElem = child
			break
		}
	}
	if sigElem == nil {
		return nil
	}

	info := &SAMLSignatureInfo{
		Target:   target,
		Verified: true, // If we got here, crewjam/saml already validated
	}

	// Extract SignatureMethod
	if signedInfo := findChildElement(sigElem, "SignedInfo"); signedInfo != nil {
		if sigMethod := findChildElement(signedInfo, "SignatureMethod"); sigMethod != nil {
			info.Algorithm = sigMethod.SelectAttrValue("Algorithm", "")
			info.AlgorithmShort = shortenAlgorithmURI(info.Algorithm)
		}
		// Extract DigestMethod from Reference
		if ref := findChildElement(signedInfo, "Reference"); ref != nil {
			if digestMethod := findChildElement(ref, "DigestMethod"); digestMethod != nil {
				info.DigestAlgorithm = digestMethod.SelectAttrValue("Algorithm", "")
				info.DigestAlgorithmShort = shortenAlgorithmURI(info.DigestAlgorithm)
			}
		}
	}

	// Extract X509Certificate
	if keyInfo := findChildElement(sigElem, "KeyInfo"); keyInfo != nil {
		if x509Data := findChildElement(keyInfo, "X509Data"); x509Data != nil {
			if x509Cert := findChildElement(x509Data, "X509Certificate"); x509Cert != nil {
				parseCertDetails(x509Cert.Text(), info)
			}
		}
	}

	return info
}

func findChildElement(parent *etree.Element, localName string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if child.Tag == localName {
			return child
		}
	}
	return nil
}

func parseCertDetails(b64Cert string, info *SAMLSignatureInfo) {
	// Remove whitespace from base64
	cleaned := strings.Join(strings.Fields(b64Cert), "")
	certDER, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		log.Printf("Failed to decode X509Certificate: %v", err)
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Printf("Failed to parse X509Certificate: %v", err)
		return
	}
	info.CertSubject = cert.Subject.String()
	info.CertIssuer = cert.Issuer.String()
	info.CertSerialNumber = cert.SerialNumber.String()
	info.CertNotBefore = cert.NotBefore.In(jst).Format("2006-01-02T15:04:05 MST")
	info.CertNotAfter = cert.NotAfter.In(jst).Format("2006-01-02T15:04:05 MST")

	// SHA-256 fingerprint
	fingerprint := sha256.Sum256(certDER)
	parts := make([]string, len(fingerprint))
	for i, b := range fingerprint {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	info.CertFingerprint = strings.Join(parts, ":")
}

func shortenAlgorithmURI(uri string) string {
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		return uri[idx+1:]
	}
	return uri
}

func formatXML(s string) string {
	if s == "" {
		return ""
	}
	var buf strings.Builder
	decoder := xml.NewDecoder(strings.NewReader(s))
	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "  ")
	for {
		t, err := decoder.Token()
		if err != nil {
			break
		}
		encoder.EncodeToken(t)
	}
	encoder.Flush()
	if buf.Len() > 0 {
		return buf.String()
	}
	return s
}

func toStringMap(attrs samlsp.Attributes) map[string]string {
	m := make(map[string]string, len(attrs))
	for k, v := range attrs {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// --- self-signed cert ---

type selfSignedKeyPair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func generateSelfSignedCert() (*selfSignedKeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return &selfSignedKeyPair{key: key, cert: cert}, nil
}

