package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	debugSessions *DebugSessionStore
	oauth2Config  *oauth2.Config
	provider      *gooidc.Provider
	verifier      *gooidc.IDTokenVerifier
	httpClient    *http.Client
	capTransport  *capturingTransport
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
	ct := newCapturingTransport(httpClient.Transport)
	capturedClient := &http.Client{
		Transport: ct,
		Timeout:   httpClient.Timeout,
	}
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
		debugSessions: NewDebugSessionStore(),
		oauth2Config:  oauth2Config,
		provider:      provider,
		verifier:      verifier,
		httpClient:    capturedClient,
		capTransport:  ct,
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
	mux.HandleFunc("/userinfo", h.handleUserInfo)
	mux.HandleFunc("/reauth", h.handleReauth)
	mux.HandleFunc("/clear", h.handleClear)
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
	debugSession := h.debugSessions.Get(r)

	// Build result entries from debug session
	var results []templates.OIDCResultEntryData
	if debugSession != nil {
		for i, entry := range debugSession.Results {
			results = append(results, h.buildResultEntryData(i, entry))
		}
	}

	data := templates.OIDCPageData{
		Name:            h.Config.Name,
		Results:         results,
		HasRefreshToken: session != nil && session.RefreshTokenRaw != "",
		CallbackPath:    h.Config.CallbackPath,
		JWKSJSON:        protocol.PrettyJSON(h.jwksRaw),
		DiscoveryJSON:   protocol.PrettyJSON(h.discoveryRaw),
		EndpointRows:    h.endpointRows,
		JWKSKeys:        h.jwksKeys,
	}

	page := templates.PageInfo{
		Tabs:         h.navTabs,
		ActiveTab:    h.activeTab(),
		DefaultTheme: h.defaultTheme,
		References: []templates.Section{
			{ID: "sec-flow", Label: "Flow Diagram"},
			{ID: "sec-provider", Label: "OpenID Provider"},
		},
	}

	if session != nil {
		// Logged in
		page.Status = "connected"
		page.StatusLabel = "Active Session"
		page.LogoutURL = "/logout"
		if h.providerInfo.UserinfoEndpoint != "" {
			page.UserInfoURL = "/userinfo"
		}
		if data.HasRefreshToken {
			page.RefreshURL = "/refresh"
		}
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
	} else {
		// Not logged in
		page.Status = "disconnected"
		page.StatusLabel = "No Session"
		page.LoginURL = "/login"
	}

	// Build sidebar sections from result entries
	for _, re := range results {
		page.Sections = append(page.Sections, templates.Section{
			ID:        re.ID,
			Label:     re.SidebarLabel,
			Timestamp: re.SidebarTimestamp,
			Dot:       re.SidebarDot,
			Children:  re.Children,
		})
	}

	templates.OIDCIndex(page, data).Render(r.Context(), w)
}

// buildResultEntryData converts a ResultEntry to template display data.
func (h *Handler) buildResultEntryData(index int, entry ResultEntry) templates.OIDCResultEntryData {
	id := fmt.Sprintf("result-%d", index)

	data := templates.OIDCResultEntryData{
		ID:               id,
		Type:             entry.Type,
		Timestamp:        formatTimestamp(entry.Timestamp),
		SidebarTimestamp: formatTimestamp(entry.Timestamp),
	}

	// Error entry
	if strings.HasPrefix(entry.Type, "Error") {
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
			data.AuthResponseHeader = "HTTP/1.1 302 Found\nLocation: " + entry.AuthResponseRedirectURI + "?" + entry.AuthResponseRaw
		}
		// Token Request (for "Error: Refresh", "Error: Login" etc.)
		if entry.TokenRequestURL != "" {
			orderedKeys := []string{"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token"}
			for _, k := range orderedKeys {
				if v, ok := entry.TokenRequestParams[k]; ok {
					data.TokenRequestParams = append(data.TokenRequestParams, components.ClaimRow{Key: k, Value: v})
				}
			}
			data.TokenRequestURL = entry.TokenRequestURL
			data.TokenRequestRaw = buildTokenRequestRaw("POST "+entry.TokenRequestURL, data.TokenRequestParams)
		}
		// Token Response (error path)
		if entry.TokenHTTPResponse != nil {
			data.ErrorStatus = strconv.Itoa(entry.TokenHTTPResponse.StatusCode)
			data.TokenResponseStatusLine, data.TokenResponseHeaders,
				data.TokenResponseBody, data.TokenResponseBodyLang = buildHTTPResponseDisplay(entry.TokenHTTPResponse)
		} else if entry.ErrorDetail != "" && entry.TokenRequestURL != "" {
			data.TokenResponseConnError = protocol.CleanGoErrorMessage(entry.ErrorDetail)
		}
		// UserInfo Error (for "Error: UserInfo")
		if entry.UserInfoError != nil {
			if entry.UserInfoError.StatusCode > 0 {
				data.ErrorStatus = strconv.Itoa(entry.UserInfoError.StatusCode)
			}
			if entry.UserInfoError.ErrorCode != "" && data.ErrorCode == "" {
				data.ErrorCode = entry.UserInfoError.ErrorCode
			}
			if entry.UserInfoError.Description != "" && data.ErrorDescription == "" {
				data.ErrorDescription = entry.UserInfoError.Description
			}
			if entry.UserInfoError.URI != "" && data.ErrorURI == "" {
				data.ErrorURI = entry.UserInfoError.URI
			}
			if entry.UserInfoError.Detail != "" && data.ErrorDetail == "" {
				data.ErrorDetail = entry.UserInfoError.Detail
			}
		}
		// UserInfo Response (error path)
		if entry.UserInfoHTTPResponse != nil {
			data.UserInfoResponseStatusLine, data.UserInfoResponseHeaders,
				data.UserInfoResponseBody, data.UserInfoResponseBodyLang = buildHTTPResponseDisplay(entry.UserInfoHTTPResponse)
		} else if entry.UserInfoError != nil && entry.UserInfoError.Detail != "" {
			data.UserInfoResponseConnError = protocol.CleanGoErrorMessage(entry.UserInfoError.Detail)
		}
		if entry.UserInfoRequestURL != "" {
			data.UserInfoRequestURL = entry.UserInfoRequestMethod + " " + entry.UserInfoRequestURL + "\nAuthorization: Bearer " + entry.AccessTokenRaw
		}
		data.SidebarLabel = strings.TrimPrefix(entry.Type, "Error: ")
		data.SidebarDot = "error"
		if data.ErrorCode != "" || data.ErrorStatus != "" {
			data.Children = append(data.Children, templates.Section{ID: id + "-error", Label: "Error Details"})
		}
		if entry.AuthRequestURL != "" || data.TokenRequestURL != "" || data.UserInfoRequestURL != "" {
			data.Children = append(data.Children, templates.Section{ID: id + "-protocol", Label: "Protocol Messages"})
		}
		return data
	}

	// Logout entry
	if strings.HasPrefix(entry.Type, "Logout") {
		data.SidebarLabel = entry.Type
		data.SidebarDot = "logout"
		if entry.LogoutRequestURL != "" {
			data.LogoutRequestURL = entry.LogoutRequestURL
			data.LogoutRequestParams = parseToClaimRows(protocol.ParseURLParams(entry.LogoutRequestURL))
		}
		// Logout Details: id_token_hint JWT decode
		if entry.LogoutIDTokenRaw != "" {
			data.LogoutIDTokenRaw = entry.LogoutIDTokenRaw
			data.LogoutIDTokenHeader, data.LogoutIDTokenPayload, data.LogoutIDTokenSignature = protocol.DecodeJWT(entry.LogoutIDTokenRaw)
			data.Children = append(data.Children, templates.Section{ID: id + "-details", Label: "Logout Details"})
		}
		if entry.LogoutRequestURL != "" {
			data.Children = append(data.Children, templates.Section{ID: id + "-protocol", Label: "Protocol Messages"})
		}
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

	// Access Token Claims (JWT only, not for UserInfo action entries)
	if entry.Type != "UserInfo" && protocol.IsJWT(entry.AccessTokenRaw) {
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

	// UserInfo Error
	if entry.UserInfoError != nil {
		var rows []components.ErrorRow
		if entry.UserInfoError.StatusCode > 0 {
			rows = append(rows, components.ErrorRow{Label: "status", Value: strconv.Itoa(entry.UserInfoError.StatusCode)})
		}
		if entry.UserInfoError.ErrorCode != "" {
			rows = append(rows, components.ErrorRow{Label: "error", Value: entry.UserInfoError.ErrorCode})
		}
		if entry.UserInfoError.Description != "" {
			rows = append(rows, components.ErrorRow{Label: "error_description", Value: entry.UserInfoError.Description})
		}
		if entry.UserInfoError.URI != "" {
			rows = append(rows, components.ErrorRow{Label: "error_uri", Value: entry.UserInfoError.URI})
		}
		if entry.UserInfoError.Detail != "" {
			rows = append(rows, components.ErrorRow{Label: "detail", Value: entry.UserInfoError.Detail})
		}
		data.UserInfoErrorRows = rows
	}

	// Protocol Messages
	data.AuthRequestURL = entry.AuthRequestURL
	data.AuthRequestParams = parseToClaimRows(protocol.ParseURLParams(entry.AuthRequestURL))
	if entry.AuthResponseRaw != "" {
		data.AuthResponseRaw = entry.AuthResponseRaw
		data.AuthResponseParams = parseToClaimRows(protocol.ParseURLParams(entry.AuthResponseRaw))
		data.AuthResponseHeader = "HTTP/1.1 302 Found\nLocation: " + entry.AuthResponseRedirectURI + "?" + entry.AuthResponseRaw
	}
	// Token Request
	if entry.TokenRequestURL != "" {
		orderedKeys := []string{"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token"}
		for _, k := range orderedKeys {
			if v, ok := entry.TokenRequestParams[k]; ok {
				data.TokenRequestParams = append(data.TokenRequestParams, components.ClaimRow{Key: k, Value: v})
			}
		}
		data.TokenRequestURL = entry.TokenRequestURL
		data.TokenRequestRaw = buildTokenRequestRaw("POST "+entry.TokenRequestURL, data.TokenRequestParams)
	}
	// Token Response
	if entry.TokenHTTPResponse != nil {
		data.TokenResponseStatusLine, data.TokenResponseHeaders,
			data.TokenResponseBody, data.TokenResponseBodyLang = buildHTTPResponseDisplay(entry.TokenHTTPResponse)
	}
	// UserInfo Request
	if entry.UserInfoRequestURL != "" {
		data.UserInfoRequestURL = entry.UserInfoRequestMethod + " " + entry.UserInfoRequestURL + "\nAuthorization: Bearer " + entry.AccessTokenRaw
	}
	// UserInfo Response
	if entry.UserInfoHTTPResponse != nil {
		data.UserInfoResponseStatusLine, data.UserInfoResponseHeaders,
			data.UserInfoResponseBody, data.UserInfoResponseBodyLang = buildHTTPResponseDisplay(entry.UserInfoHTTPResponse)
	} else if entry.UserInfoError != nil && entry.UserInfoError.Detail != "" {
		data.UserInfoResponseConnError = protocol.CleanGoErrorMessage(entry.UserInfoError.Detail)
	}

	// Raw Tokens
	if entry.IDTokenRaw != "" {
		data.IDTokenRaw = entry.IDTokenRaw
		data.IDTokenHeader, data.IDTokenPayload, data.IDTokenSignature = protocol.DecodeJWT(entry.IDTokenRaw)
	}
	if protocol.IsJWT(entry.AccessTokenRaw) {
		data.AccessTokenJWT = entry.AccessTokenRaw
		data.AccessTokenHeader, data.AccessTokenPayload, data.AccessTokenSignature = protocol.DecodeJWT(entry.AccessTokenRaw)
	} else if entry.AccessTokenRaw != "" {
		data.AccessTokenRaw = entry.AccessTokenRaw
	}
	if protocol.IsJWT(entry.RefreshTokenRaw) {
		data.RefreshTokenJWT = entry.RefreshTokenRaw
		data.RefreshTokenHeader, data.RefreshTokenPayload, data.RefreshTokenSignature = protocol.DecodeJWT(entry.RefreshTokenRaw)
	} else if entry.RefreshTokenRaw != "" {
		data.RefreshTokenRaw = entry.RefreshTokenRaw
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

	// Sidebar label and dot color (Logout handled above via early return)
	switch {
	case entry.Type == "Login":
		data.SidebarLabel = "Login"
		data.SidebarDot = "login"
	case entry.Type == "Refresh":
		data.SidebarLabel = "Refresh"
		data.SidebarDot = "refresh"
	case entry.Type == "UserInfo":
		data.SidebarLabel = "UserInfo"
		data.SidebarDot = "userinfo"
	default: // Re-auth: *
		data.SidebarLabel = entry.Type
		data.SidebarDot = "reauth"
	}

	// Build sidebar children (sub-sections)
	if len(data.IDTokenClaims) > 0 || len(data.UserInfoClaims) > 0 {
		data.Children = append(data.Children, templates.Section{ID: id + "-claims", Label: "Identity & Claims"})
	}
	if len(data.IDTokenSigRows) > 0 || len(data.AccessTokenSigRows) > 0 {
		data.Children = append(data.Children, templates.Section{ID: id + "-sigs", Label: "Signature Verification"})
	}
	if entry.AuthRequestURL != "" || entry.TokenRequestURL != "" || entry.UserInfoRequestURL != "" {
		data.Children = append(data.Children, templates.Section{ID: id + "-protocol", Label: "Protocol Messages"})
	}
	if entry.Type != "UserInfo" && (entry.IDTokenRaw != "" || entry.AccessTokenRaw != "" || entry.RefreshTokenRaw != "") {
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
		Secure:   isHTTPS(r),
		SameSite: sameSiteMode(r),
	})

	// Store reauth name in cookie if this is a re-auth flow
	if reauthName != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_reauth_name",
			Value:    reauthName,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			Secure:   isHTTPS(r),
		SameSite: sameSiteMode(r),
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
			Secure:   isHTTPS(r),
		SameSite: sameSiteMode(r),
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
		Secure:   isHTTPS(r),
		SameSite: sameSiteMode(r),
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
			Type:                    "Error: " + resultType,
			Timestamp:               time.Now(),
			AuthRequestURL:          authRequestURL,
			AuthResponseRaw:         authResponseRaw,
			AuthResponseRedirectURI: h.oauth2Config.RedirectURL,
			ErrorCode:               errCode,
			ErrorDescription:        errDesc,
			ErrorURI:                errURI,
		}

		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")

	// Build exchange options
	var exchangeOpts []oauth2.AuthCodeOption
	var pkceVerifier string

	// PKCE: include code_verifier
	if h.Config.PKCE {
		if c, err := r.Cookie("oidc_pkce_verifier"); err == nil {
			pkceVerifier = c.Value
			exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
		}
		http.SetCookie(w, &http.Cookie{
			Name: "oidc_pkce_verifier", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		})
	}

	// Build Token Request params for display (before exchange, so available on error)
	tokenRequestParams := map[string]string{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": h.oauth2Config.RedirectURL,
		"client_id":    h.oauth2Config.ClientID,
	}
	if h.oauth2Config.ClientSecret != "" {
		tokenRequestParams["client_secret"] = "*******"
	}
	if pkceVerifier != "" {
		tokenRequestParams["code_verifier"] = pkceVerifier
	}

	tokenCtx := context.WithValue(r.Context(), oauth2.HTTPClient, h.httpClient)
	token, err := h.oauth2Config.Exchange(tokenCtx, code, exchangeOpts...)
	if err != nil {
		log.Printf("Token exchange failed: %v", err)
		errCode, desc, uri, detail, respBody, sc, hdrs := extractOAuthError(err)
		if sc == 0 {
			errCode = "connection_failed"
		} else if errCode == "" {
			errCode = "token_exchange_failed"
		}
		var tokenHTTPResp *HTTPResponseInfo
		if sc > 0 {
			tokenHTTPResp = &HTTPResponseInfo{StatusCode: sc, Headers: hdrs, Body: respBody}
		}
		errorEntry := ResultEntry{
			Type:                    "Error: " + resultType,
			Timestamp:               time.Now(),
			AuthRequestURL:          authRequestURL,
			AuthResponseRaw:         authResponseRaw,
			AuthResponseRedirectURI: h.oauth2Config.RedirectURL,
			ErrorCode:               errCode,
			ErrorDescription:        desc,
			ErrorURI:                uri,
			ErrorDetail:             detail,
			TokenHTTPResponse:       tokenHTTPResp,
			TokenRequestURL:         h.oauth2Config.Endpoint.TokenURL,
			TokenRequestParams:      tokenRequestParams,
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Capture Token endpoint HTTP response
	tokenCapture := h.capTransport.LastCapture()
	var tokenHTTPResp *HTTPResponseInfo
	if tokenCapture != nil {
		tokenHTTPResp = &HTTPResponseInfo{
			StatusCode: tokenCapture.StatusCode,
			Headers:    tokenCapture.Headers,
			Body:       string(tokenCapture.Body),
		}
	}

	tokenResponseJSON := marshalTokenResponse(token)

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Println("No id_token in token response")
		errorEntry := ResultEntry{
			Type:                    "Error: " + resultType,
			Timestamp:               time.Now(),
			AuthRequestURL:          authRequestURL,
			AuthResponseRaw:         authResponseRaw,
			AuthResponseRedirectURI: h.oauth2Config.RedirectURL,
			TokenRequestURL:         h.oauth2Config.Endpoint.TokenURL,
			TokenRequestParams:      tokenRequestParams,
			TokenResponse:           tokenResponseJSON,
			ErrorCode:               "missing_id_token",
			ErrorDetail:             "No id_token in token response",
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	idToken, err := h.verifier.Verify(tokenCtx, rawIDToken)
	if err != nil {
		log.Printf("ID token verification failed: %v", err)
		errorEntry := ResultEntry{
			Type:                    "Error: " + resultType,
			Timestamp:               time.Now(),
			AuthRequestURL:          authRequestURL,
			AuthResponseRaw:         authResponseRaw,
			AuthResponseRedirectURI: h.oauth2Config.RedirectURL,
			TokenRequestURL:         h.oauth2Config.Endpoint.TokenURL,
			TokenRequestParams:      tokenRequestParams,
			TokenResponse:           tokenResponseJSON,
			IDTokenRaw:              rawIDToken,
			ErrorCode:               "id_token_verification_failed",
			ErrorDetail:             err.Error(),
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
	var userInfoErr *UserInfoError
	var userInfoHTTPResp *HTTPResponseInfo
	if h.providerInfo.UserinfoEndpoint != "" {
		userInfoResponse, userInfoErr, userInfoHTTPResp = fetchUserInfo(h.httpClient, h.providerInfo.UserinfoEndpoint, token.AccessToken)
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
		Type:                    resultType,
		Timestamp:               time.Now(),
		Claims:                  claims,
		AuthRequestURL:          authRequestURL,
		AuthResponseCode:        code,
		AuthResponseRaw:         authResponseRaw,
		AuthResponseRedirectURI: h.oauth2Config.RedirectURL,
		TokenRequestURL:         h.oauth2Config.Endpoint.TokenURL,
		TokenRequestParams:      tokenRequestParams,
		TokenResponse:      tokenResponseJSON,
		TokenHTTPResponse:    tokenHTTPResp,
		UserInfoHTTPResponse: userInfoHTTPResp,
		IDTokenRaw:           rawIDToken,
		AccessTokenRaw:       token.AccessToken,
		RefreshTokenRaw:      refreshTokenRaw,
		UserInfoResponse:     userInfoResponse,
		UserInfoError:        userInfoErr,
		IDTokenSigInfo:       idTokenSigInfo,
		AccessTokenSigInfo:   accessTokenSigInfo,
		JWKSResponse:         jwksRaw,
	}

	// Record UserInfo Request info
	if h.providerInfo.UserinfoEndpoint != "" {
		entry.UserInfoRequestURL = h.providerInfo.UserinfoEndpoint
		entry.UserInfoRequestMethod = "GET"
	}

	// Save entry to debug session
	h.saveDebugEntry(w, r, entry)

	// Update auth session (refresh token)
	if cookie, err := r.Cookie("session_id"); err == nil {
		if existing := h.sessions.GetByID(cookie.Value); existing != nil {
			existing.IDTokenRaw = rawIDToken
			existing.AccessTokenRaw = token.AccessToken
			if refreshTokenRaw != "" {
				existing.RefreshTokenRaw = refreshTokenRaw
			}
			h.sessions.Set(cookie.Value, existing)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	// New auth session
	sessionID, err := protocol.RandomHex(32)
	if err != nil {
		log.Printf("Failed to generate session ID: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.sessions.Set(sessionID, &Session{
		IDTokenRaw:      rawIDToken,
		AccessTokenRaw:  token.AccessToken,
		RefreshTokenRaw: refreshTokenRaw,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: sameSiteMode(r),
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// saveDebugEntry saves a result entry to the debug session.
func (h *Handler) saveDebugEntry(w http.ResponseWriter, r *http.Request, entry ResultEntry) {
	var debugSession *DebugSession
	var debugID string

	if c, err := r.Cookie("oidc_debug_id"); err == nil {
		debugSession = h.debugSessions.GetByID(c.Value)
		debugID = c.Value
	}

	if debugSession == nil {
		debugID, _ = protocol.RandomHex(32)
		debugSession = &DebugSession{}
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_debug_id",
			Value:    debugID,
			Path:     "/",
			HttpOnly: true,
			Secure:   isHTTPS(r),
		SameSite: sameSiteMode(r),
		})
	}

	debugSession.Results = append([]ResultEntry{entry}, debugSession.Results...)
	h.debugSessions.Set(debugID, debugSession)
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func sameSiteMode(r *http.Request) http.SameSite {
	if isHTTPS(r) {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

// saveErrorEntry saves an error result entry to the debug session.
func (h *Handler) saveErrorEntry(w http.ResponseWriter, r *http.Request, entry ResultEntry) {
	h.saveDebugEntry(w, r, entry)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Retrieve id_token_raw from session before deleting it
	var idTokenRaw string
	if cookie, err := r.Cookie("session_id"); err == nil {
		if session := h.sessions.GetByID(cookie.Value); session != nil {
			idTokenRaw = session.IDTokenRaw
		}
	}

	// Build Logout entry
	logoutEntry := ResultEntry{
		Type:      "Logout (RP)",
		Timestamp: time.Now(),
	}

	// Build end_session_endpoint URL
	if h.providerInfo.EndSessionEndpoint != "" {
		logoutURL := h.providerInfo.EndSessionEndpoint + "?post_logout_redirect_uri=" + url.QueryEscape(h.topPageURL) + "&client_id=" + url.QueryEscape(h.Config.ClientID)

		// Add id_token_hint if enabled (default: true)
		if h.Config.LogoutIDTokenHint == nil || *h.Config.LogoutIDTokenHint {
			if idTokenRaw != "" {
				logoutURL += "&id_token_hint=" + url.QueryEscape(idTokenRaw)
				logoutEntry.LogoutIDTokenRaw = idTokenRaw
			}
		}

		logoutEntry.LogoutRequestURL = logoutURL
	}

	// Save Logout entry to debug session (survives logout)
	h.saveDebugEntry(w, r, logoutEntry)

	// Destroy auth session only
	if cookie, err := r.Cookie("session_id"); err == nil {
		h.sessions.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "session_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})

	// Redirect to IdP end_session_endpoint or back to index
	if logoutEntry.LogoutRequestURL != "" {
		http.Redirect(w, r, logoutEntry.LogoutRequestURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// handleUserInfo fetches the latest UserInfo using the stored access token.
func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	session := h.sessions.GetByID(cookie.Value)
	if session == nil || session.AccessTokenRaw == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if h.providerInfo.UserinfoEndpoint == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	userInfoResponse, userInfoErr, uiHTTPResp := fetchUserInfo(h.httpClient, h.providerInfo.UserinfoEndpoint, session.AccessTokenRaw)

	entryType := "UserInfo"
	if userInfoErr != nil {
		entryType = "Error: UserInfo"
	}

	entry := ResultEntry{
		Type:                  entryType,
		Timestamp:             time.Now(),
		UserInfoRequestURL:    h.providerInfo.UserinfoEndpoint,
		UserInfoRequestMethod: "GET",
		UserInfoResponse:      userInfoResponse,
		UserInfoError:         userInfoErr,
		UserInfoHTTPResponse:  uiHTTPResp,
		AccessTokenRaw:        session.AccessTokenRaw,
	}

	h.saveDebugEntry(w, r, entry)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleClear clears all debug results.
func (h *Handler) handleClear(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("oidc_debug_id"); err == nil {
		h.debugSessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "oidc_debug_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleRefresh performs a token refresh using the stored refresh token.
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	session := h.sessions.GetByID(cookie.Value)
	if session == nil || session.RefreshTokenRaw == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tokenCtx := context.WithValue(r.Context(), oauth2.HTTPClient, h.httpClient)
	tokenSource := h.oauth2Config.TokenSource(tokenCtx, &oauth2.Token{
		RefreshToken: session.RefreshTokenRaw,
	})

	// Build Token Request params for display (before exchange, so available on error)
	refreshTokenRequestParams := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": session.RefreshTokenRaw,
		"client_id":     h.oauth2Config.ClientID,
	}
	if h.oauth2Config.ClientSecret != "" {
		refreshTokenRequestParams["client_secret"] = "*******"
	}

	newToken, err := tokenSource.Token()
	if err != nil {
		log.Printf("Token refresh failed: %v", err)
		code, desc, uri, detail, respBody, sc, hdrs := extractOAuthError(err)
		if sc == 0 {
			code = "connection_failed"
		} else if code == "" {
			code = "token_refresh_failed"
		}
		var tokenHTTPResp *HTTPResponseInfo
		if sc > 0 {
			tokenHTTPResp = &HTTPResponseInfo{StatusCode: sc, Headers: hdrs, Body: respBody}
		}
		errorEntry := ResultEntry{
			Type:               "Error: Refresh",
			Timestamp:          time.Now(),
			ErrorCode:          code,
			ErrorDescription:   desc,
			ErrorURI:           uri,
			ErrorDetail:        detail,
			TokenHTTPResponse:  tokenHTTPResp,
			TokenRequestURL:    h.oauth2Config.Endpoint.TokenURL,
			TokenRequestParams: refreshTokenRequestParams,
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Capture Token endpoint HTTP response for refresh
	refreshCapture := h.capTransport.LastCapture()
	var refreshHTTPResp *HTTPResponseInfo
	if refreshCapture != nil {
		refreshHTTPResp = &HTTPResponseInfo{
			StatusCode: refreshCapture.StatusCode,
			Headers:    refreshCapture.Headers,
			Body:       string(refreshCapture.Body),
		}
	}

	// Determine refresh token for display: new one if rotated, otherwise the original
	refreshTokenForDisplay := session.RefreshTokenRaw
	if newRT := newToken.Extra("refresh_token"); newRT != nil {
		if rt, ok := newRT.(string); ok {
			refreshTokenForDisplay = rt
		}
	}

	entry := ResultEntry{
		Type:               "Refresh",
		Timestamp:          time.Now(),
		TokenRequestURL:    h.oauth2Config.Endpoint.TokenURL,
		TokenRequestParams: refreshTokenRequestParams,
		TokenResponse:      marshalTokenResponse(newToken),
		TokenHTTPResponse:  refreshHTTPResp,
		AccessTokenRaw:     newToken.AccessToken,
		RefreshTokenRaw:    refreshTokenForDisplay,
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

	// Save entry to debug session
	h.saveDebugEntry(w, r, entry)

	// Update tokens in auth session for subsequent refreshes
	session.AccessTokenRaw = newToken.AccessToken
	if entry.IDTokenRaw != "" {
		session.IDTokenRaw = entry.IDTokenRaw
	}
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

// buildTokenRequestRaw builds a full HTTP request for display: request line + headers + body.
func buildTokenRequestRaw(requestLine string, params []components.ClaimRow) string {
	var b strings.Builder
	b.WriteString(requestLine)
	b.WriteString("\nContent-Type: application/x-www-form-urlencoded\n\n")
	for i, p := range params {
		if i > 0 {
			b.WriteString("&")
		}
		b.WriteString(p.Key)
		b.WriteString("=")
		b.WriteString(p.Value)
	}
	return b.String()
}

// buildHTTPResponseDisplay converts HTTPResponseInfo to display strings.
func buildHTTPResponseDisplay(resp *HTTPResponseInfo) (statusLine, headers, body, bodyLang string) {
	statusLine = protocol.FormatHTTPStatusLine(resp.StatusCode)
	headers = protocol.FormatHTTPHeaders(resp.Headers)
	body = resp.Body
	if ct := resp.Headers.Get("Content-Type"); ct != "" {
		bodyLang = protocol.DetectContentLanguage(ct)
		if bodyLang == "json" {
			if pretty := protocol.PrettyJSON(json.RawMessage(resp.Body)); pretty != "" {
				body = pretty
			}
		}
	}
	return
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

// extractOAuthError extracts RFC 6749 error fields from an oauth2.RetrieveError.
// Returns the error code, description, URI, detail message, HTTP response body,
// status code, and headers. For non-RetrieveError, statusCode is 0 and headers is nil.
func extractOAuthError(err error) (code, description, uri, detail, responseBody string, statusCode int, headers http.Header) {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		sc := 0
		var h http.Header
		if re.Response != nil {
			sc = re.Response.StatusCode
			h = re.Response.Header.Clone()
		}
		return re.ErrorCode, re.ErrorDescription, re.ErrorURI, "", string(re.Body), sc, h
	}
	return "", "", "", err.Error(), "", 0, nil
}

func fetchUserInfo(client *http.Client, userinfoURL, accessToken string) (json.RawMessage, *UserInfoError, *HTTPResponseInfo) {
	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		log.Printf("Failed to create userinfo request: %v", err)
		return nil, &UserInfoError{ErrorCode: "connection_failed", Detail: err.Error()}, nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch userinfo: %v", err)
		return nil, &UserInfoError{ErrorCode: "connection_failed", Detail: err.Error()}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read userinfo response: %v", err)
		return nil, &UserInfoError{ErrorCode: "connection_failed", Detail: err.Error()}, nil
	}

	httpResp := &HTTPResponseInfo{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       string(body),
	}

	if resp.StatusCode >= 300 {
		log.Printf("UserInfo endpoint returned status %d", resp.StatusCode)
		uiErr := &UserInfoError{
			StatusCode: resp.StatusCode,
			RawBody:    string(body),
		}
		// Attempt to parse RFC 6750 JSON error response
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
			URI         string `json:"error_uri"`
		}
		if json.Unmarshal(body, &errResp) == nil {
			uiErr.ErrorCode = errResp.Error
			uiErr.Description = errResp.Description
			uiErr.URI = errResp.URI
		}
		// Fallback: parse WWW-Authenticate header (RFC 6750 Section 3)
		if uiErr.ErrorCode == "" {
			if wwwAuth := resp.Header.Get("Www-Authenticate"); wwwAuth != "" {
				code, desc, uri := protocol.ParseWWWAuthenticate(wwwAuth)
				uiErr.ErrorCode = code
				uiErr.Description = desc
				uiErr.URI = uri
			}
		}
		return nil, uiErr, httpResp
	}

	var raw json.RawMessage
	if json.Unmarshal(body, &raw) != nil {
		log.Printf("Failed to decode userinfo response as JSON")
		return nil, &UserInfoError{
			StatusCode:  resp.StatusCode,
			ErrorCode:   "invalid_response",
			Description: "Response is not valid JSON",
			RawBody:     string(body),
		}, httpResp
	}
	return raw, nil, httpResp
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
