package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wadahiro/fedlens/internal/protocol"
)

// handleResource serves as a built-in resource server endpoint (OAuth2 only).
// It validates the Bearer token via Token Introspection and returns the result.
func (h *Handler) handleResource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")

	metadataURL := h.resourceMetadataURL()

	// 1. Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.Header().Set("WWW-Authenticate", buildWWWAuthenticate("", "", metadataURL))
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "missing_token",
			"error_description": "No Authorization header provided",
		})
		return
	}

	// 2. Validate Bearer format
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", buildWWWAuthenticate("invalid_request", "Authorization header must use Bearer scheme", metadataURL))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "Authorization header must use Bearer scheme",
		})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		w.Header().Set("WWW-Authenticate", buildWWWAuthenticate("invalid_request", "Bearer token is empty", metadataURL))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "Bearer token is empty",
		})
		return
	}

	// 3. Check Introspection endpoint configured
	if h.providerInfo.IntrospectionEndpoint == "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": "Token introspection endpoint is not configured",
		})
		return
	}

	// 4. Perform Token Introspection
	introResp, err := h.performIntrospection(token)
	if err != nil {
		log.Printf("Resource server introspection failed: %v", err)
		w.Header().Set("WWW-Authenticate", buildWWWAuthenticate("invalid_token", "Token introspection failed", metadataURL))
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "Token introspection failed",
		})
		return
	}

	// Check active status
	var introResult map[string]any
	if err := json.Unmarshal(introResp, &introResult); err != nil {
		w.Header().Set("WWW-Authenticate", buildWWWAuthenticate("invalid_token", "Invalid introspection response", metadataURL))
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "Invalid introspection response",
		})
		return
	}

	active, _ := introResult["active"].(bool)
	if !active {
		w.Header().Set("WWW-Authenticate", buildWWWAuthenticate("invalid_token", "Token is not active", metadataURL))
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "Token is not active",
		})
		return
	}

	// 5. Success
	resourceURL := h.Config.BaseURL + "/resource"
	authServer := h.deriveAuthorizationServer()

	result := map[string]any{
		"resource_server":      resourceURL,
		"authorization_server": authServer,
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
		"token_introspection":  introResult,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// performIntrospection calls the token introspection endpoint and returns the raw response.
func (h *Handler) performIntrospection(token string) (json.RawMessage, error) {
	params := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}

	req, err := http.NewRequest("POST", h.providerInfo.IntrospectionEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(h.oauth2Config.ClientID, h.oauth2Config.ClientSecret)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read introspection response: %w", err)
	}

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("introspection returned %d: %s", resp.StatusCode, string(body))
	}

	return json.RawMessage(body), nil
}

// handleResourceAccess is the client-side action handler: fetches a resource with the stored access token.
// If no session exists, sends the request without an Authorization header.
func (h *Handler) handleResourceAccess(w http.ResponseWriter, r *http.Request) {
	// Get access token from session if available
	var accessToken string
	if cookie, err := r.Cookie("session_id"); err == nil {
		if session := h.sessions.GetByID(cookie.Value); session != nil {
			accessToken = accessToken
		}
	}

	// Determine target URL
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		targetURL = h.Config.BaseURL + "/resource"
	}

	serverName := ""
	if targetURL == h.Config.BaseURL+"/resource" {
		serverName = "Built-in Resource"
	}

	// Make GET request (with Bearer token if available)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		log.Printf("Failed to create resource request: %v", err)
		errorEntry := ResultEntry{
			Type:                  "Error: Resource",
			Timestamp:             time.Now(),
			ResourceRequestURL:    targetURL,
			ResourceRequestMethod: "GET",
			ResourceServerName:    serverName,
			ResourceError: &ResourceError{
				ErrorCode: "connection_failed",
				Detail:    err.Error(),
			},
			ErrorCode:   "connection_failed",
			ErrorDetail: err.Error(),
			AccessTokenRaw: accessToken,
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, h.basePath+"/", http.StatusFound)
		return
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := h.httpClient.Do(req)

	// Capture HTTP response
	resourceCapture := h.capTransport.LastCapture()
	var resourceHTTPResp *HTTPResponseInfo
	if resourceCapture != nil {
		resourceHTTPResp = &HTTPResponseInfo{
			StatusCode: resourceCapture.StatusCode,
			Headers:    resourceCapture.Headers,
			Body:       string(resourceCapture.Body),
		}
	}

	if err != nil {
		log.Printf("Resource access request failed: %v", err)
		errorEntry := ResultEntry{
			Type:                  "Error: Resource",
			Timestamp:             time.Now(),
			ResourceRequestURL:    targetURL,
			ResourceRequestMethod: "GET",
			ResourceHTTPResponse:  resourceHTTPResp,
			ResourceServerName:    serverName,
			ResourceError: &ResourceError{
				ErrorCode: "connection_failed",
				Detail:    err.Error(),
			},
			ErrorCode:   "connection_failed",
			ErrorDetail: err.Error(),
			AccessTokenRaw: accessToken,
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, h.basePath+"/", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read resource response: %v", err)
		http.Redirect(w, r, h.basePath+"/", http.StatusFound)
		return
	}

	if resp.StatusCode >= 300 {
		// Error response
		resErr := &ResourceError{
			StatusCode: resp.StatusCode,
			RawBody:    string(body),
		}

		// Try to parse JSON error response
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
			URI         string `json:"error_uri"`
		}
		if json.Unmarshal(body, &errResp) == nil {
			resErr.ErrorCode = errResp.Error
			resErr.Description = errResp.Description
			resErr.URI = errResp.URI
		}

		// Fallback: parse WWW-Authenticate header (RFC 6750)
		if resErr.ErrorCode == "" {
			if wwwAuth := resp.Header.Get("Www-Authenticate"); wwwAuth != "" {
				code, desc, uri := protocol.ParseWWWAuthenticate(wwwAuth)
				resErr.ErrorCode = code
				resErr.Description = desc
				resErr.URI = uri
			}
		}

		errorEntry := ResultEntry{
			Type:                  "Error: Resource",
			Timestamp:             time.Now(),
			ResourceRequestURL:    targetURL,
			ResourceRequestMethod: "GET",
			ResourceHTTPResponse:  resourceHTTPResp,
			ResourceServerName:    serverName,
			ResourceError:         resErr,
			ErrorCode:             resErr.ErrorCode,
			ErrorDescription:      resErr.Description,
			ErrorURI:              resErr.URI,
			AccessTokenRaw:        accessToken,
		}
		if resErr.ErrorCode == "" {
			errorEntry.ErrorCode = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		h.saveErrorEntry(w, r, errorEntry)
		http.Redirect(w, r, h.basePath+"/", http.StatusFound)
		return
	}

	// Success
	var resourceResponse json.RawMessage
	if json.Unmarshal(body, &resourceResponse) != nil {
		// Not valid JSON, store raw body
		resourceResponse = nil
	}

	entry := ResultEntry{
		Type:                  "Resource",
		Timestamp:             time.Now(),
		ResourceRequestURL:    targetURL,
		ResourceRequestMethod: "GET",
		ResourceResponse:      resourceResponse,
		ResourceHTTPResponse:  resourceHTTPResp,
		ResourceServerName:    serverName,
		AccessTokenRaw:        accessToken,
	}

	h.saveDebugEntry(w, r, entry)
	http.Redirect(w, r, h.basePath+"/", http.StatusFound)
}

// buildWWWAuthenticate constructs an RFC 6750 WWW-Authenticate header value.
func buildWWWAuthenticate(errCode, errDesc, metadataURL string) string {
	var parts []string
	if errCode != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, errCode))
	}
	if errDesc != "" {
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, errDesc))
	}
	if metadataURL != "" {
		parts = append(parts, fmt.Sprintf(`resource_metadata="%s"`, metadataURL))
	}
	if len(parts) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(parts, ", ")
}

// ResourceMetadataJSON returns the RFC 9728 Protected Resource Metadata as JSON.
func (h *Handler) ResourceMetadataJSON() []byte {
	resourceURL := h.Config.BaseURL + "/resource"
	authServer := h.deriveAuthorizationServer()

	metadata := map[string]any{
		"resource":                 resourceURL,
		"authorization_servers":    []string{authServer},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "fedlens Built-in Resource Server (" + h.Config.Name + ")",
	}

	if h.oauth2Cfg != nil && len(h.oauth2Cfg.Scopes) > 0 {
		metadata["scopes_supported"] = h.oauth2Cfg.Scopes
	}

	data, _ := json.MarshalIndent(metadata, "", "  ")
	return data
}

// ResourceMetadataPath returns the RFC 8615-compliant well-known path for this resource.
func (h *Handler) ResourceMetadataPath() string {
	return "/.well-known/oauth-protected-resource" + h.basePath + "/resource"
}

// resourceMetadataURL returns the full URL for the RFC 9728 metadata endpoint.
func (h *Handler) resourceMetadataURL() string {
	// Derive scheme://host from BaseURL
	u, err := url.Parse(h.Config.BaseURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + h.ResourceMetadataPath()
}

// deriveAuthorizationServer returns the authorization server identifier.
func (h *Handler) deriveAuthorizationServer() string {
	if h.oauth2Cfg != nil && h.oauth2Cfg.Issuer != "" {
		return h.oauth2Cfg.Issuer
	}
	// Derive from token URL
	tokenURL := h.oauth2Config.Endpoint.TokenURL
	if tokenURL != "" {
		if u, err := url.Parse(tokenURL); err == nil {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}
