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
	"strconv"
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
	Config        config.OIDCConfig
	sessions      *SessionStore
	errorSessions *SessionStore
	oauth2Config  *oauth2.Config
	provider      *gooidc.Provider
	verifier      *gooidc.IDTokenVerifier
	httpClient    *http.Client
	discoveryRaw  json.RawMessage
	providerInfo  struct {
		EndSessionEndpoint string
		UserinfoEndpoint   string
		JwksURI            string
	}
	topPageURL   string
	navTabs      []templates.NavTab
	defaultTheme string
	endpointRows []components.ClaimRow
	jwksRaw      json.RawMessage
	jwksKeys     []templates.JWKSKeyData
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
		Config:        cfg,
		sessions:      NewSessionStore(),
		errorSessions: NewSessionStore(),
		oauth2Config:  oauth2Config,
		provider:      provider,
		verifier:      verifier,
		httpClient:    httpClient,
		discoveryRaw:  discoveryRaw,
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

	// Build endpoint rows from discovery
	h.endpointRows = buildEndpointRows(oauth2Config, h.providerInfo)

	// Pre-fetch JWKS for display (available even before login)
	if h.providerInfo.JwksURI != "" {
		h.jwksRaw = fetchJWKS(httpClient, h.providerInfo.JwksURI)
		h.jwksKeys = buildJWKSKeyRows(protocol.ParseJWKSKeys(h.jwksRaw))
	}

	return h, nil
}

func buildJWKSKeyRows(keys []protocol.JWKSKeyInfo) []templates.JWKSKeyData {
	var result []templates.JWKSKeyData
	for _, k := range keys {
		var rows []components.SignatureRow
		pairs := []struct{ label, value string }{
			{"Key ID (kid)", k.Kid},
			{"Key Type (kty)", k.Kty},
			{"Algorithm (alg)", k.Alg},
			{"Use (use)", k.Use},
		}
		for _, p := range pairs {
			if p.value != "" {
				rows = append(rows, components.SignatureRow{Label: p.label, Value: p.value})
			}
		}
		result = append(result, templates.JWKSKeyData{Rows: rows})
	}
	return result
}

func buildEndpointRows(oauth2Config *oauth2.Config, providerInfo struct {
	EndSessionEndpoint string
	UserinfoEndpoint   string
	JwksURI            string
}) []components.ClaimRow {
	var rows []components.ClaimRow
	endpoints := []struct{ key, value string }{
		{"authorization_endpoint", oauth2Config.Endpoint.AuthURL},
		{"token_endpoint", oauth2Config.Endpoint.TokenURL},
		{"userinfo_endpoint", providerInfo.UserinfoEndpoint},
		{"jwks_uri", providerInfo.JwksURI},
		{"end_session_endpoint", providerInfo.EndSessionEndpoint},
	}
	for _, ep := range endpoints {
		if ep.value != "" {
			rows = append(rows, components.ClaimRow{Key: ep.key, Value: ep.value})
		}
	}
	return rows
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
	mux.HandleFunc("/reauth", h.handleReauth)
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

	// Check for error session (pre-login errors)
	var errorSession *Session
	if c, err := r.Cookie("oidc_error_session"); err == nil {
		errorSession = h.errorSessions.GetByID(c.Value)
		// Clear error session cookie after reading
		http.SetCookie(w, &http.Cookie{
			Name: "oidc_error_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		})
		if errorSession != nil {
			h.errorSessions.Delete(c.Value)
		}
	}

	if session == nil {
		// Pre-login page
		discoveryJSON := protocol.PrettyJSON(h.discoveryRaw)
		jwksJSON := protocol.PrettyJSON(h.jwksRaw)
		page := templates.PageInfo{
			Tabs:         h.navTabs,
			ActiveTab:    h.activeTab(),
			Status:       "disconnected",
			StatusLabel:  "No Session",
			LoginURL:     "/login",
			DefaultTheme: h.defaultTheme,
			References: []templates.Section{
				{ID: "sec-flow", Label: "Flow Diagram"},
				{ID: "sec-provider", Label: "OpenID Provider"},
			},
		}

		// Build error entries for pre-login display
		var errorEntries []templates.OIDCResultEntryData
		if errorSession != nil {
			for i, entry := range errorSession.Results {
				entryData := h.buildResultEntryData(i, entry)
				errorEntries = append(errorEntries, entryData)
			}
			// Add error entries to sidebar sections
			for _, e := range errorEntries {
				page.Sections = append(page.Sections, templates.Section{
					ID:        e.ID,
					Label:     e.SidebarLabel,
					Timestamp: e.SidebarTimestamp,
					Dot:       e.SidebarDot,
					Children:  e.Children,
				})
			}
		}

		templates.OIDCIndex(page, h.Config.Name, discoveryJSON, h.Config.CallbackPath, h.endpointRows, jwksJSON, h.jwksKeys, errorEntries).Render(r.Context(), w)
		return
	}

	// Merge error entries into session if present
	if errorSession != nil {
		session.Results = append(errorSession.Results, session.Results...)
		// Re-save session with merged results
		if c, err := r.Cookie("session_id"); err == nil {
			h.sessions.Set(c.Value, session)
		}
	}

	// Post-login page: build timeline result entries
	var results []templates.OIDCResultEntryData
	for i, entry := range session.Results {
		entryData := h.buildResultEntryData(i, entry)
		results = append(results, entryData)
	}

	data := templates.OIDCDebugData{
		Name:            h.Config.Name,
		Results:         results,
		HasRefreshToken: session.RefreshTokenRaw != "",
		CallbackPath:    h.Config.CallbackPath,
		JWKSJSON:        protocol.PrettyJSON(h.jwksRaw),
		DiscoveryJSON:   protocol.PrettyJSON(h.discoveryRaw),
		EndpointRows:    h.endpointRows,
		JWKSKeys:        h.jwksKeys,
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

	// Build ReauthItems: always include default re-authenticate action
	page.ReauthItems = append(page.ReauthItems, templates.ReauthItem{
		Label: "Re-authenticate",
		URL:   "/reauth?step=-1",
	})
	for i, rc := range h.Config.Reauth {
		page.ReauthItems = append(page.ReauthItems, templates.ReauthItem{
			Label: rc.Name,
			URL:   "/reauth?step=" + strconv.Itoa(i),
		})
	}

	// Build Sections from result entries
	for _, re := range results {
		page.Sections = append(page.Sections, templates.Section{
			ID:        re.ID,
			Label:     re.SidebarLabel,
			Timestamp: re.SidebarTimestamp,
			Dot:       re.SidebarDot,
			Children:  re.Children,
		})
	}

	templates.OIDCDebug(page, data).Render(r.Context(), w)
}

// buildResultEntryData converts a ResultEntry to template display data.
func (h *Handler) buildResultEntryData(index int, entry ResultEntry) templates.OIDCResultEntryData {
	id := fmt.Sprintf("result-%d", index)

	data := templates.OIDCResultEntryData{
		ID:               id,
		Type:             entry.Type,
		Timestamp:        formatTimestamp(entry.Timestamp),
		SidebarTimestamp: formatSidebarTimestamp(entry.Timestamp),
	}

	// Error entry
	if entry.Type == "Error" {
		data.ErrorCode = entry.ErrorCode
		data.ErrorDescription = entry.ErrorDescription
		data.ErrorURI = entry.ErrorURI
		data.ErrorDetail = entry.ErrorDetail
		data.AuthRequestURL = entry.AuthRequestURL
		if entry.AuthRequestURL != "" {
			data.AuthRequestParams = parseToClaimRows(protocol.ParseURLParams(entry.AuthRequestURL))
		}
		if entry.AuthResponseRaw != "" {
			data.AuthResponseRaw = entry.AuthResponseRaw
			data.AuthResponseParams = parseToClaimRows(protocol.ParseURLParams(entry.AuthResponseRaw))
		}
		data.SidebarLabel = "Error"
		data.SidebarDot = "error"
		return data
	}

	// Subject
	if sub, ok := entry.Claims["sub"]; ok {
		data.Subject = protocol.FormatValue(sub)
	}

	// ID Token Claims
	for _, k := range protocol.SortedKeys(entry.Claims) {
		data.IDTokenClaims = append(data.IDTokenClaims, components.ClaimRow{
			Key:   k,
			Value: protocol.FormatClaimValue(k, entry.Claims[k]),
		})
	}

	// ID Token Signature
	if entry.IDTokenSigInfo != nil {
		data.IDTokenSigRows = buildJWTSigRows(entry.IDTokenSigInfo)
	}

	// Access Token Claims (JWT only)
	if protocol.IsJWT(entry.AccessTokenRaw) {
		_, atPayloadRaw := protocol.DecodeJWTRaw(entry.AccessTokenRaw)
		var atClaims map[string]any
		if json.Unmarshal(atPayloadRaw, &atClaims) == nil {
			for _, k := range protocol.SortedKeys(atClaims) {
				data.AccessTokenClaims = append(data.AccessTokenClaims, components.ClaimRow{
					Key:   k,
					Value: protocol.FormatClaimValue(k, atClaims[k]),
				})
			}
		}
		if entry.AccessTokenSigInfo != nil {
			data.AccessTokenSigRows = buildJWTSigRows(entry.AccessTokenSigInfo)
		}
	}

	// UserInfo Claims
	if len(entry.UserInfoResponse) > 0 {
		var userInfoClaims map[string]any
		if json.Unmarshal(entry.UserInfoResponse, &userInfoClaims) == nil {
			for _, k := range protocol.SortedKeys(userInfoClaims) {
				data.UserInfoClaims = append(data.UserInfoClaims, components.ClaimRow{
					Key:   k,
					Value: protocol.FormatClaimValue(k, userInfoClaims[k]),
				})
			}
		}
	}

	// Protocol Details
	data.AuthRequestURL = entry.AuthRequestURL
	data.AuthRequestParams = parseToClaimRows(protocol.ParseURLParams(entry.AuthRequestURL))
	data.AuthResponseRaw = entry.AuthResponseRaw
	data.AuthResponseParams = parseToClaimRows(protocol.ParseURLParams(entry.AuthResponseRaw))
	data.TokenResponseJSON = protocol.PrettyJSON(entry.TokenResponse)
	data.UserInfoJSON = protocol.PrettyJSON(entry.UserInfoResponse)

	// Raw Tokens
	if entry.IDTokenRaw != "" {
		data.IDTokenHeader, data.IDTokenPayload, data.IDTokenSignature = protocol.DecodeJWT(entry.IDTokenRaw)
	}
	if protocol.IsJWT(entry.AccessTokenRaw) {
		data.AccessTokenHeader, data.AccessTokenPayload, data.AccessTokenSignature = protocol.DecodeJWT(entry.AccessTokenRaw)
	} else if entry.AccessTokenRaw != "" {
		data.AccessTokenRaw = entry.AccessTokenRaw
	}

	// Signature verification status
	sigVerifiedAll := true
	if entry.IDTokenSigInfo != nil && !entry.IDTokenSigInfo.Verified {
		sigVerifiedAll = false
	}
	if entry.AccessTokenSigInfo != nil && !entry.AccessTokenSigInfo.Verified {
		sigVerifiedAll = false
	}
	data.SigVerifiedAll = sigVerifiedAll

	// Sidebar label and dot color
	switch {
	case entry.Type == "Login":
		data.SidebarLabel = "Login"
		data.SidebarDot = "login"
	case entry.Type == "Refresh":
		data.SidebarLabel = "Refresh"
		data.SidebarDot = "refresh"
	default: // Re-auth: *
		data.SidebarLabel = entry.Type
		data.SidebarDot = "reauth"
	}

	// Build sidebar children (sub-sections)
	if len(data.IDTokenClaims) > 0 {
		data.Children = append(data.Children, templates.Section{ID: id + "-claims", Label: "Identity & Claims"})
	}
	if len(data.IDTokenSigRows) > 0 || len(data.AccessTokenSigRows) > 0 {
		data.Children = append(data.Children, templates.Section{ID: id + "-sigs", Label: "Signature Verification"})
	}
	if entry.AuthRequestURL != "" || len(entry.TokenResponse) > 0 {
		data.Children = append(data.Children, templates.Section{ID: id + "-protocol", Label: "Protocol Details"})
	}
	if entry.IDTokenRaw != "" || entry.AccessTokenRaw != "" {
		data.Children = append(data.Children, templates.Section{ID: id + "-tokens", Label: "Raw Tokens"})
	}

	return data
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	h.startAuthFlow(w, r, nil, "")
}

func (h *Handler) handleReauth(w http.ResponseWriter, r *http.Request) {
	// Verify session exists
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "No session", http.StatusBadRequest)
		return
	}
	session := h.sessions.GetByID(cookie.Value)
	if session == nil {
		http.Error(w, "No session", http.StatusBadRequest)
		return
	}

	stepStr := r.URL.Query().Get("step")
	step, err := strconv.Atoi(stepStr)
	if err != nil {
		http.Error(w, "Invalid reauth step", http.StatusBadRequest)
		return
	}

	// step=-1 is the default re-authenticate (no extra params)
	if step == -1 {
		h.startAuthFlow(w, r, nil, "__default__")
		return
	}

	if step < 0 || step >= len(h.Config.Reauth) {
		http.Error(w, "Invalid reauth step", http.StatusBadRequest)
		return
	}

	rc := h.Config.Reauth[step]
	h.startAuthFlow(w, r, rc.ExtraAuthParams, rc.Name)
}

// startAuthFlow initiates an OIDC authorization request. extraParams are merged on top
// of the config's ExtraAuthParams. reauthName is non-empty for re-auth flows.
func (h *Handler) startAuthFlow(w http.ResponseWriter, r *http.Request, extraParams map[string]string, reauthName string) {
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

	// Store reauth name in cookie if this is a re-auth flow
	if reauthName != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_reauth_name",
			Value:    reauthName,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}

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

	// Extra auth params from reauth config (override config's)
	for k, v := range extraParams {
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

	// Retrieve reauth name from cookie
	var reauthName string
	if c, err := r.Cookie("oidc_reauth_name"); err == nil {
		reauthName = c.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name: "oidc_reauth_name", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})

	authResponseRaw := r.URL.RawQuery

	// Determine result type
	resultType := "Login"
	if reauthName == "__default__" {
		resultType = "Re-auth"
	} else if reauthName != "" {
		resultType = "Re-auth: " + reauthName
	}

	// Check for OP error response
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		errURI := r.URL.Query().Get("error_uri")

		errorEntry := ResultEntry{
			Type:             "Error",
			Timestamp:        time.Now(),
			AuthRequestURL:   authRequestURL,
			AuthResponseRaw:  authResponseRaw,
			ErrorCode:        errCode,
			ErrorDescription: errDesc,
			ErrorURI:         errURI,
		}

		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")

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
		errorEntry := ResultEntry{
			Type:            "Error",
			Timestamp:       time.Now(),
			AuthRequestURL:  authRequestURL,
			AuthResponseRaw: authResponseRaw,
			ErrorCode:       "token_exchange_failed",
			ErrorDetail:     err.Error(),
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tokenResponseJSON := marshalTokenResponse(token)

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Println("No id_token in token response")
		errorEntry := ResultEntry{
			Type:            "Error",
			Timestamp:       time.Now(),
			AuthRequestURL:  authRequestURL,
			AuthResponseRaw: authResponseRaw,
			TokenResponse:   tokenResponseJSON,
			ErrorCode:       "missing_id_token",
			ErrorDetail:     "No id_token in token response",
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	idToken, err := h.verifier.Verify(tokenCtx, rawIDToken)
	if err != nil {
		log.Printf("ID token verification failed: %v", err)
		errorEntry := ResultEntry{
			Type:            "Error",
			Timestamp:       time.Now(),
			AuthRequestURL:  authRequestURL,
			AuthResponseRaw: authResponseRaw,
			TokenResponse:   tokenResponseJSON,
			IDTokenRaw:      rawIDToken,
			ErrorCode:       "id_token_verification_failed",
			ErrorDetail:     err.Error(),
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
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

	entry := ResultEntry{
		Type:               resultType,
		Timestamp:          time.Now(),
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

	// Check if we have an existing session (re-auth case)
	if cookie, err := r.Cookie("session_id"); err == nil {
		if existing := h.sessions.GetByID(cookie.Value); existing != nil {
			// Prepend new entry to existing session
			existing.Results = append([]ResultEntry{entry}, existing.Results...)
			if refreshTokenRaw != "" {
				existing.RefreshTokenRaw = refreshTokenRaw
			}
			h.sessions.Set(cookie.Value, existing)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	// New session
	sessionID, err := protocol.RandomHex(32)
	if err != nil {
		log.Printf("Failed to generate session ID: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.sessions.Set(sessionID, &Session{
		Results:         []ResultEntry{entry},
		RefreshTokenRaw: refreshTokenRaw,
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

// saveErrorEntry saves an error result entry to the error session store.
func (h *Handler) saveErrorEntry(w http.ResponseWriter, r *http.Request, entry ResultEntry) {
	// Check if error session already exists
	var errorSession *Session
	var errorSessionID string
	if c, err := r.Cookie("oidc_error_session"); err == nil {
		errorSession = h.errorSessions.GetByID(c.Value)
		errorSessionID = c.Value
	}

	if errorSession == nil {
		errorSessionID, _ = protocol.RandomHex(32)
		errorSession = &Session{}
	}

	errorSession.Results = append([]ResultEntry{entry}, errorSession.Results...)
	h.errorSessions.Set(errorSessionID, errorSession)

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_error_session",
		Value:    errorSessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
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

// handleRefresh performs a token refresh using the stored refresh token.
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

	entry := ResultEntry{
		Type:           "Refresh",
		Timestamp:      time.Now(),
		TokenResponse:  marshalTokenResponse(newToken),
		AccessTokenRaw: newToken.AccessToken,
	}

	if newIDToken, ok := newToken.Extra("id_token").(string); ok {
		entry.IDTokenRaw = newIDToken
		if idToken, err := h.verifier.Verify(tokenCtx, newIDToken); err == nil {
			var claims map[string]any
			if err := idToken.Claims(&claims); err == nil {
				entry.Claims = claims
			}
		}
		var jwksRaw json.RawMessage
		if h.providerInfo.JwksURI != "" {
			jwksRaw = fetchJWKS(h.httpClient, h.providerInfo.JwksURI)
		}
		entry.IDTokenSigInfo = protocol.BuildJWTSignatureInfo(newIDToken, jwksRaw, true)
	}

	if protocol.IsJWT(newToken.AccessToken) {
		var jwksRaw json.RawMessage
		if h.providerInfo.JwksURI != "" {
			jwksRaw = fetchJWKS(h.httpClient, h.providerInfo.JwksURI)
		}
		entry.AccessTokenSigInfo = protocol.BuildJWTSignatureInfo(newToken.AccessToken, jwksRaw, true)
	}

	// Prepend new entry
	session.Results = append([]ResultEntry{entry}, session.Results...)

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

func formatTimestamp(t time.Time) string {
	if protocol.DisplayLocation != nil {
		t = t.In(protocol.DisplayLocation)
	}
	return t.Format("2006/01/02 15:04:05 MST")
}

func formatSidebarTimestamp(t time.Time) string {
	if protocol.DisplayLocation != nil {
		t = t.In(protocol.DisplayLocation)
	}
	return t.Format("01/02 15:04:05")
}
