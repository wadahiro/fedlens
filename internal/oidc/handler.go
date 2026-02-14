package oidc

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
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/wadahiro/fedlens/internal/config"
	"github.com/wadahiro/fedlens/internal/protocol"
	"github.com/wadahiro/fedlens/internal/ui/templates"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

// Handler is a per-SP OIDC handler set.
type Handler struct {
	Config       config.OIDCConfig
	sessions     *SessionStore
	oauth2Config *oauth2.Config
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	httpClient   *http.Client
	discoveryRaw json.RawMessage
	providerInfo struct {
		EndSessionEndpoint string
		UserinfoEndpoint   string
		JwksURI            string
	}
	topPageURL   string
	navTabs      []templates.NavTab
	defaultTheme string
}

// NewHandler creates and initializes an OIDC handler for the given config.
func NewHandler(cfg config.OIDCConfig, httpClient *http.Client) (*Handler, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	var (
		provider *gooidc.Provider
		err      error
	)
	for i := range 30 {
		provider, err = gooidc.NewProvider(ctx, cfg.Issuer)
		if err == nil {
			break
		}
		log.Printf("OIDC provider discovery attempt %d/30 failed (%s): %v", i+1, cfg.Name, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider %s: %w", cfg.Name, err)
	}
	log.Printf("OIDC provider discovered: %s (%s)", cfg.Issuer, cfg.Name)

	// Fetch raw discovery metadata
	var discoveryRaw json.RawMessage
	if resp, err := httpClient.Get(cfg.Issuer + "/.well-known/openid-configuration"); err == nil {
		defer resp.Body.Close()
		if body, err := io.ReadAll(resp.Body); err == nil {
			discoveryRaw = json.RawMessage(body)
		}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	verifier := provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID})

	h := &Handler{
		Config:       cfg,
		sessions:     NewSessionStore(),
		oauth2Config: oauth2Config,
		provider:     provider,
		verifier:     verifier,
		httpClient:   httpClient,
		discoveryRaw: discoveryRaw,
	}

	// Extract provider claims
	var providerClaims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
		UserinfoEndpoint   string `json:"userinfo_endpoint"`
		JwksURI            string `json:"jwks_uri"`
	}
	if err := provider.Claims(&providerClaims); err != nil {
		log.Printf("WARNING: Could not extract provider claims (%s): %v", cfg.Name, err)
	}
	h.providerInfo.EndSessionEndpoint = providerClaims.EndSessionEndpoint
	h.providerInfo.UserinfoEndpoint = providerClaims.UserinfoEndpoint
	h.providerInfo.JwksURI = providerClaims.JwksURI

	// Derive top-page URL from redirect URI
	redirectParsed, err := url.Parse(cfg.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("parse redirect URI: %w", err)
	}
	h.topPageURL = redirectParsed.Scheme + "://" + redirectParsed.Host + "/"

	return h, nil
}

// SetNavTabs sets the navigation tabs for this handler.
func (h *Handler) SetNavTabs(tabs []templates.NavTab) {
	h.navTabs = tabs
}

// SetDefaultTheme sets the default theme for this handler.
func (h *Handler) SetDefaultTheme(theme string) {
	h.defaultTheme = theme
}

// RegisterRoutes registers OIDC handlers on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc(h.Config.CallbackPath, h.handleCallback)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.HandleFunc("/refresh", h.handleRefresh)
}

// activeTab returns the NavTab that is currently active.
func (h *Handler) activeTab() templates.NavTab {
	for _, tab := range h.navTabs {
		if tab.Active {
			return tab
		}
	}
	return templates.NavTab{}
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	session := h.sessions.Get(r)
	if session == nil {
		discoveryJSON := protocol.PrettyJSON(h.discoveryRaw)
		page := templates.PageInfo{
			Tabs:         h.navTabs,
			ActiveTab:    h.activeTab(),
			Status:       "disconnected",
			StatusLabel:  "No Session",
			LoginURL:     "/login",
			DefaultTheme: h.defaultTheme,
			References: []templates.Section{
				{ID: "sec-flow", Label: "Flow Diagram"},
				{ID: "sec-config", Label: "OpenID Provider Configuration"},
			},
		}
		templates.OIDCIndex(page, h.Config.Name, discoveryJSON, h.Config.CallbackPath).Render(r.Context(), w)
		return
	}

	// Parse URL params for display
	authRequestParams := parseToClaimRows(protocol.ParseURLParams(session.AuthRequestURL))
	authResponseParams := parseToClaimRows(protocol.ParseURLParams(session.AuthResponseRaw))

	// Build template data
	// Extract subject from ID Token claims
	var subject string
	if sub, ok := session.Claims["sub"]; ok {
		subject = protocol.FormatValue(sub)
	}

	data := templates.OIDCDebugData{
		Name:               h.Config.Name,
		Subject:            subject,
		AuthRequestURL:     session.AuthRequestURL,
		AuthRequestParams:  authRequestParams,
		AuthResponseRaw:    session.AuthResponseRaw,
		AuthResponseParams: authResponseParams,
		TokenResponseJSON: protocol.PrettyJSON(session.TokenResponse),
		UserInfoJSON:      protocol.PrettyJSON(session.UserInfoResponse),
		JWKSJSON:          protocol.PrettyJSON(session.JWKSResponse),
		DiscoveryJSON:     protocol.PrettyJSON(h.discoveryRaw),
		HasRefreshToken:   session.RefreshTokenRaw != "",
		CallbackPath:      h.Config.CallbackPath,
	}

	// ID Token Claims
	for _, k := range protocol.SortedKeys(session.Claims) {
		data.IDTokenClaims = append(data.IDTokenClaims, components.ClaimRow{
			Key:   k,
			Value: protocol.FormatClaimValue(k, session.Claims[k]),
		})
	}

	// ID Token Signature
	if session.IDTokenSigInfo != nil {
		data.IDTokenSigRows = buildJWTSigRows(session.IDTokenSigInfo)
	}

	// Access Token Claims (JWT only)
	if protocol.IsJWT(session.AccessTokenRaw) {
		_, atPayloadRaw := protocol.DecodeJWTRaw(session.AccessTokenRaw)
		var atClaims map[string]any
		if json.Unmarshal(atPayloadRaw, &atClaims) == nil {
			for _, k := range protocol.SortedKeys(atClaims) {
				data.AccessTokenClaims = append(data.AccessTokenClaims, components.ClaimRow{
					Key:   k,
					Value: protocol.FormatClaimValue(k, atClaims[k]),
				})
			}
		}
		if session.AccessTokenSigInfo != nil {
			data.AccessTokenSigRows = buildJWTSigRows(session.AccessTokenSigInfo)
		}
	}

	// UserInfo Claims
	if len(session.UserInfoResponse) > 0 {
		var userInfoClaims map[string]any
		if json.Unmarshal(session.UserInfoResponse, &userInfoClaims) == nil {
			for _, k := range protocol.SortedKeys(userInfoClaims) {
				data.UserInfoClaims = append(data.UserInfoClaims, components.ClaimRow{
					Key:   k,
					Value: protocol.FormatClaimValue(k, userInfoClaims[k]),
				})
			}
		}
	}

	// ID Token header/payload
	data.IDTokenHeader, data.IDTokenPayload = protocol.DecodeJWT(session.IDTokenRaw)

	// Access Token display
	if protocol.IsJWT(session.AccessTokenRaw) {
		atHeader, atPayload := protocol.DecodeJWT(session.AccessTokenRaw)
		data.AccessTokenDisplay = "Header:\n" + atHeader + "\n\nPayload:\n" + atPayload
	} else {
		data.AccessTokenDisplay = session.AccessTokenRaw
	}

	// Determine if all signatures are verified
	sigVerifiedAll := true
	if session.IDTokenSigInfo != nil && !session.IDTokenSigInfo.Verified {
		sigVerifiedAll = false
	}
	if session.AccessTokenSigInfo != nil && !session.AccessTokenSigInfo.Verified {
		sigVerifiedAll = false
	}
	data.SigVerifiedAll = sigVerifiedAll

	// Build RefreshResult display data
	if session.RefreshResult != nil {
		rr := session.RefreshResult
		refreshData := &templates.OIDCRefreshResultData{
			Timestamp:         formatRefreshTimestamp(rr.Timestamp),
			TokenResponseJSON: protocol.PrettyJSON(rr.TokenResponse),
		}

		if len(rr.Claims) > 0 {
			for _, k := range protocol.SortedKeys(rr.Claims) {
				refreshData.IDTokenClaims = append(refreshData.IDTokenClaims, components.ClaimRow{
					Key:   k,
					Value: protocol.FormatClaimValue(k, rr.Claims[k]),
				})
			}
		}
		if rr.IDTokenSigInfo != nil {
			refreshData.IDTokenSigRows = buildJWTSigRows(rr.IDTokenSigInfo)
		}
		if protocol.IsJWT(rr.AccessTokenRaw) {
			_, atPayloadRaw := protocol.DecodeJWTRaw(rr.AccessTokenRaw)
			var atClaims map[string]any
			if json.Unmarshal(atPayloadRaw, &atClaims) == nil {
				for _, k := range protocol.SortedKeys(atClaims) {
					refreshData.AccessTokenClaims = append(refreshData.AccessTokenClaims, components.ClaimRow{
						Key:   k,
						Value: protocol.FormatClaimValue(k, atClaims[k]),
					})
				}
			}
			if rr.AccessTokenSigInfo != nil {
				refreshData.AccessTokenSigRows = buildJWTSigRows(rr.AccessTokenSigInfo)
			}
		}
		if rr.IDTokenRaw != "" {
			refreshData.IDTokenHeader, refreshData.IDTokenPayload = protocol.DecodeJWT(rr.IDTokenRaw)
		}
		if protocol.IsJWT(rr.AccessTokenRaw) {
			atH, atP := protocol.DecodeJWT(rr.AccessTokenRaw)
			refreshData.AccessTokenDisplay = "Header:\n" + atH + "\n\nPayload:\n" + atP
		} else if rr.AccessTokenRaw != "" {
			refreshData.AccessTokenDisplay = rr.AccessTokenRaw
		}
		refreshSigOK := true
		if rr.IDTokenSigInfo != nil && !rr.IDTokenSigInfo.Verified {
			refreshSigOK = false
		}
		if rr.AccessTokenSigInfo != nil && !rr.AccessTokenSigInfo.Verified {
			refreshSigOK = false
		}
		refreshData.SigVerifiedAll = refreshSigOK
		data.RefreshResult = refreshData
	}

	page := templates.PageInfo{
		Tabs:         h.navTabs,
		ActiveTab:    h.activeTab(),
		Status:       "connected",
		StatusLabel:  "Active Session",
		LogoutURL:    "/logout",
		DefaultTheme: h.defaultTheme,
		References: []templates.Section{
			{ID: "sec-flow", Label: "Flow Diagram"},
			{ID: "sec-provider", Label: "OpenID Provider"},
		},
	}
	if data.HasRefreshToken {
		page.RefreshURL = "/refresh"
	}
	// Build Sections: Refresh Result first (if present), then the rest
	if data.RefreshResult != nil {
		page.Sections = append(page.Sections, templates.Section{ID: "sec-refresh", Label: "Refresh Result"})
	}
	page.Sections = append(page.Sections,
		templates.Section{ID: "sec-claims", Label: "Identity & Claims"},
		templates.Section{ID: "sec-sigs", Label: "Signature Verification"},
		templates.Section{ID: "sec-protocol", Label: "Protocol Details"},
		templates.Section{ID: "sec-tokens", Label: "Raw Tokens"},
	)

	templates.OIDCDebug(page, data).Render(r.Context(), w)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := protocol.RandomHex(16)
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

	// Build AuthCodeURL options
	var opts []oauth2.AuthCodeOption

	// PKCE support
	if h.Config.PKCE {
		verifier, err := protocol.RandomHex(32) // 64-char hex string
		if err != nil {
			log.Printf("Failed to generate PKCE verifier: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Store verifier in cookie for callback
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_pkce_verifier",
			Value:    verifier,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		if h.Config.PKCEMethod == "plain" {
			opts = append(opts,
				oauth2.SetAuthURLParam("code_challenge", verifier),
				oauth2.SetAuthURLParam("code_challenge_method", "plain"),
			)
		} else {
			// S256 (default)
			hash := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(hash[:])
			opts = append(opts,
				oauth2.SetAuthURLParam("code_challenge", challenge),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			)
		}
	}

	// Extra auth params from config
	for k, v := range h.Config.ExtraAuthParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}

	// Response mode
	if h.Config.ResponseMode != "" {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", h.Config.ResponseMode))
	}

	authURL := h.oauth2Config.AuthCodeURL(state, opts...)

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_auth_request_url",
		Value:    authURL,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
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

	// Build exchange options
	var exchangeOpts []oauth2.AuthCodeOption

	// PKCE: include code_verifier
	if h.Config.PKCE {
		if c, err := r.Cookie("oidc_pkce_verifier"); err == nil {
			exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("code_verifier", c.Value))
		}
		http.SetCookie(w, &http.Cookie{
			Name: "oidc_pkce_verifier", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		})
	}

	tokenCtx := context.WithValue(r.Context(), oauth2.HTTPClient, h.httpClient)
	token, err := h.oauth2Config.Exchange(tokenCtx, code, exchangeOpts...)
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

	idToken, err := h.verifier.Verify(tokenCtx, rawIDToken)
	if err != nil {
		log.Printf("ID token verification failed: %v", err)
		http.Error(w, "ID token verification failed", http.StatusInternalServerError)
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("Failed to extract claims: %v", err)
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	// Fetch UserInfo
	var userInfoResponse json.RawMessage
	if h.providerInfo.UserinfoEndpoint != "" {
		userInfoResponse = fetchUserInfo(h.httpClient, h.providerInfo.UserinfoEndpoint, token.AccessToken)
	}

	// Fetch JWKS and build signature info
	var jwksRaw json.RawMessage
	if h.providerInfo.JwksURI != "" {
		jwksRaw = fetchJWKS(h.httpClient, h.providerInfo.JwksURI)
	}
	idTokenSigInfo := protocol.BuildJWTSignatureInfo(rawIDToken, jwksRaw, true)
	var accessTokenSigInfo *protocol.JWTSignatureInfo
	if protocol.IsJWT(token.AccessToken) {
		accessTokenSigInfo = protocol.BuildJWTSignatureInfo(token.AccessToken, jwksRaw, true)
	}

	// Extract refresh token
	var refreshTokenRaw string
	if rt := token.Extra("refresh_token"); rt != nil {
		refreshTokenRaw, _ = rt.(string)
	}

	sessionID, err := protocol.RandomHex(32)
	if err != nil {
		log.Printf("Failed to generate session ID: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.sessions.Set(sessionID, &Session{
		Claims:             claims,
		AuthRequestURL:     authRequestURL,
		AuthResponseCode:   code,
		AuthResponseRaw:    authResponseRaw,
		TokenResponse:      tokenResponseJSON,
		IDTokenRaw:         rawIDToken,
		AccessTokenRaw:     token.AccessToken,
		RefreshTokenRaw:    refreshTokenRaw,
		UserInfoResponse:   userInfoResponse,
		IDTokenSigInfo:     idTokenSigInfo,
		AccessTokenSigInfo: accessTokenSigInfo,
		JWKSResponse:       jwksRaw,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		h.sessions.Delete(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name: "session_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})

	if h.providerInfo.EndSessionEndpoint != "" {
		logoutURL := h.providerInfo.EndSessionEndpoint + "?post_logout_redirect_uri=" + url.QueryEscape(h.topPageURL) + "&client_id=" + url.QueryEscape(h.Config.ClientID)
		http.Redirect(w, r, logoutURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// handleRefresh performs a token refresh using the stored refresh token (Step 7).
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "No session", http.StatusBadRequest)
		return
	}

	session := h.sessions.GetByID(cookie.Value)
	if session == nil || session.RefreshTokenRaw == "" {
		http.Error(w, "No refresh token", http.StatusBadRequest)
		return
	}

	tokenCtx := context.WithValue(r.Context(), oauth2.HTTPClient, h.httpClient)
	tokenSource := h.oauth2Config.TokenSource(tokenCtx, &oauth2.Token{
		RefreshToken: session.RefreshTokenRaw,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		log.Printf("Token refresh failed: %v", err)
		http.Error(w, "Token refresh failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Build RefreshResult (preserve original session data)
	result := &RefreshResult{
		Timestamp:      time.Now(),
		TokenResponse:  marshalTokenResponse(newToken),
		AccessTokenRaw: newToken.AccessToken,
	}

	if newIDToken, ok := newToken.Extra("id_token").(string); ok {
		result.IDTokenRaw = newIDToken
		if idToken, err := h.verifier.Verify(tokenCtx, newIDToken); err == nil {
			var claims map[string]any
			if err := idToken.Claims(&claims); err == nil {
				result.Claims = claims
			}
		}
		var jwksRaw json.RawMessage
		if h.providerInfo.JwksURI != "" {
			jwksRaw = fetchJWKS(h.httpClient, h.providerInfo.JwksURI)
		}
		result.IDTokenSigInfo = protocol.BuildJWTSignatureInfo(newIDToken, jwksRaw, true)
	}

	if protocol.IsJWT(newToken.AccessToken) {
		var jwksRaw json.RawMessage
		if h.providerInfo.JwksURI != "" {
			jwksRaw = fetchJWKS(h.httpClient, h.providerInfo.JwksURI)
		}
		result.AccessTokenSigInfo = protocol.BuildJWTSignatureInfo(newToken.AccessToken, jwksRaw, true)
	}

	session.RefreshResult = result

	// Update refresh token for subsequent refreshes
	if newRT := newToken.Extra("refresh_token"); newRT != nil {
		if rt, ok := newRT.(string); ok {
			session.RefreshTokenRaw = rt
		}
	}

	h.sessions.Set(cookie.Value, session)

	// Redirect back to index to see updated data
	http.Redirect(w, r, "/", http.StatusFound)
}
func buildJWTSigRows(info *protocol.JWTSignatureInfo) []components.SignatureRow {
	verifiedStr := "false"
	if info.Verified {
		verifiedStr = "true"
	}
	var rows []components.SignatureRow
	pairs := []struct{ label, value string }{
		{"Algorithm", info.Algorithm},
		{"Key ID (kid)", info.KeyID},
		{"Key Type (kty)", info.KeyType},
		{"Key Use (use)", info.KeyUse},
		{"Key Algorithm (alg)", info.KeyAlg},
		{"Verified", verifiedStr},
	}
	for _, p := range pairs {
		if p.value != "" {
			rows = append(rows, components.SignatureRow{Label: p.label, Value: p.value})
		}
	}
	return rows
}

func parseToClaimRows(params []protocol.KeyValue) []components.ClaimRow {
	if len(params) == 0 {
		return nil
	}
	rows := make([]components.ClaimRow, len(params))
	for i, p := range params {
		rows[i] = components.ClaimRow{Key: p.Key, Value: p.Value}
	}
	return rows
}

func marshalTokenResponse(token *oauth2.Token) json.RawMessage {
	m := map[string]any{
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

func formatRefreshTimestamp(t time.Time) string {
	if protocol.DisplayLocation != nil {
		t = t.In(protocol.DisplayLocation)
	}
	return t.Format("2006-01-02 15:04:05 MST")
}
