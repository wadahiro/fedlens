package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	xmlpkg "encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	samlpkg "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/wadahiro/fedlens/internal/config"
	"github.com/wadahiro/fedlens/internal/protocol"
	"github.com/wadahiro/fedlens/internal/ui/templates"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

// Handler is a per-SP SAML handler set.
type Handler struct {
	Config          config.SAMLConfig
	debugSessions   *DebugSessionStore
	sp              *samlsp.Middleware
	httpClient      *http.Client
	idpMetadataRaw  string
	rootURLStr      string
	navTabs         []templates.NavTab
	defaultTheme    string
	requestBinding  string // "redirect" or "post"
	responseBinding string // "redirect" or "post"
	endpointRows    []components.ClaimRow
	idpCertificates []templates.SAMLCertificateData
	idpSigningCerts []*x509.Certificate
}

// NewHandler creates and initializes a SAML handler for the given config.
func NewHandler(cfg config.SAMLConfig, httpClient *http.Client) (*Handler, error) {
	rootURL, err := url.Parse(cfg.RootURL)
	if err != nil {
		return nil, fmt.Errorf("parse root URL: %w", err)
	}

	var keyPair *KeyPair
	if cfg.CertPath != "" && cfg.KeyPath != "" {
		keyPair, err = LoadCertFromFiles(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load certificate files: %w", err)
		}
		log.Printf("SAML SP certificate loaded from files (%s)", cfg.Name)
	} else {
		keyPair, err = GenerateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		log.Printf("SAML SP self-signed certificate generated (%s)", cfg.Name)
	}

	idpMetadataURL, err := url.Parse(cfg.IDPMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("parse IdP metadata URL: %w", err)
	}

	var idpMetadata *samlpkg.EntityDescriptor
	for i := range 30 {
		idpMetadata, err = samlsp.FetchMetadata(context.Background(), httpClient, *idpMetadataURL)
		if err == nil {
			break
		}
		log.Printf("SAML IdP metadata fetch attempt %d/30 failed (%s): %v", i+1, cfg.Name, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("fetch SAML IdP metadata %s: %w", cfg.Name, err)
	}
	log.Printf("SAML IdP metadata fetched: %s (%s)", cfg.IDPMetadataURL, cfg.Name)

	// Fetch raw IdP Metadata XML
	var idpMetadataRaw string
	if resp, err := httpClient.Get(cfg.IDPMetadataURL); err == nil {
		defer resp.Body.Close()
		if body, err := io.ReadAll(resp.Body); err == nil {
			idpMetadataRaw = string(body)
		}
	}

	sp, err := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.Key,
		Certificate:    keyPair.Cert,
		IDPMetadata:    idpMetadata,
		EntityID:       cfg.EntityID,
		SignRequest:    false,
		LogoutBindings: []string{samlpkg.HTTPPostBinding, samlpkg.HTTPRedirectBinding},
	})
	if err != nil {
		return nil, fmt.Errorf("create SAML SP: %w", err)
	}

	// Override SP endpoint paths from config
	sp.ServiceProvider.AcsURL = *rootURL.ResolveReference(&url.URL{Path: cfg.ACSPath})
	sp.ServiceProvider.SloURL = *rootURL.ResolveReference(&url.URL{Path: cfg.SLOPath})
	sp.ServiceProvider.MetadataURL = *rootURL.ResolveReference(&url.URL{Path: cfg.MetadataPath})

	// Determine request binding (same logic as handleLogin)
	reqBinding := "redirect"
	if sp.ServiceProvider.GetSSOBindingLocation(samlpkg.HTTPRedirectBinding) == "" {
		reqBinding = "post"
	}

	h := &Handler{
		Config:          cfg,
		debugSessions:   NewDebugSessionStore(),
		sp:              sp,
		httpClient:      httpClient,
		idpMetadataRaw:  idpMetadataRaw,
		rootURLStr:      cfg.RootURL,
		requestBinding:  reqBinding,
		responseBinding: "post", // SAML Response is always HTTP-POST binding
	}

	// Build endpoint rows from IdP metadata
	h.endpointRows = buildSAMLEndpointRows(&sp.ServiceProvider)

	// Extract IdP certificates with metadata
	h.idpCertificates = extractIdPCertificateInfos(idpMetadata)

	// Extract IdP signing certificates for signature verification
	h.idpSigningCerts = extractIdPSigningCerts(idpMetadata)

	return h, nil
}

func buildSAMLEndpointRows(sp *samlpkg.ServiceProvider) []components.ClaimRow {
	var rows []components.ClaimRow
	endpoints := []struct{ key, value string }{
		{"SSO URL (Redirect)", sp.GetSSOBindingLocation(samlpkg.HTTPRedirectBinding)},
		{"SSO URL (POST)", sp.GetSSOBindingLocation(samlpkg.HTTPPostBinding)},
		{"SLO URL (Redirect)", sp.GetSLOBindingLocation(samlpkg.HTTPRedirectBinding)},
		{"SLO URL (POST)", sp.GetSLOBindingLocation(samlpkg.HTTPPostBinding)},
	}
	for _, ep := range endpoints {
		if ep.value != "" {
			rows = append(rows, components.ClaimRow{Key: ep.key, Value: ep.value})
		}
	}
	return rows
}

func extractIdPCertificateInfos(metadata *samlpkg.EntityDescriptor) []templates.SAMLCertificateData {
	var certs []templates.SAMLCertificateData
	for _, idpDesc := range metadata.IDPSSODescriptors {
		for _, kd := range idpDesc.KeyDescriptors {
			for _, certData := range kd.KeyInfo.X509Data.X509Certificates {
				derBytes, err := base64.StdEncoding.DecodeString(certData.Data)
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(derBytes)
				if err != nil {
					continue
				}
				pemBlock := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				certInfo := protocol.ParseCertificateInfo(cert)
				var rows []components.SignatureRow
				pairs := []struct{ label, value string }{
					{"Subject", certInfo.Subject},
					{"Issuer", certInfo.Issuer},
					{"Serial Number", certInfo.SerialNumber},
					{"Not Before", certInfo.NotBefore},
					{"Not After", certInfo.NotAfter},
					{"Fingerprint (SHA-256)", certInfo.Fingerprint},
				}
				for _, p := range pairs {
					if p.value != "" {
						rows = append(rows, components.SignatureRow{Label: p.label, Value: p.value})
					}
				}
				certs = append(certs, templates.SAMLCertificateData{
					Rows: rows,
					PEM:  string(pemBlock),
				})
			}
		}
	}
	return certs
}

// extractIdPSigningCerts extracts signing certificates from IdP metadata.
// Certificates with use="signing" or no use attribute are included.
func extractIdPSigningCerts(metadata *samlpkg.EntityDescriptor) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, idpDesc := range metadata.IDPSSODescriptors {
		for _, kd := range idpDesc.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, certData := range kd.KeyInfo.X509Data.X509Certificates {
				derBytes, err := base64.StdEncoding.DecodeString(certData.Data)
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(derBytes)
				if err != nil {
					continue
				}
				certs = append(certs, cert)
			}
		}
	}
	return certs
}

// SetNavTabs sets the navigation tabs for this handler.
func (h *Handler) SetNavTabs(tabs []templates.NavTab) {
	h.navTabs = tabs
}

// SetDefaultTheme sets the default theme for this handler.
func (h *Handler) SetDefaultTheme(theme string) {
	h.defaultTheme = theme
}

// RegisterRoutes registers SAML handlers on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc(h.Config.ACSPath, h.handleACS)
	mux.Handle(h.Config.MetadataPath, h.sp)
	mux.HandleFunc(h.Config.SLOPath, h.handleSLO)
	mux.HandleFunc("/logout", h.handleLogout)
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

	session, _ := h.sp.Session.GetSession(r)
	debugSession := h.debugSessions.Get(r)

	// Build timeline result entries from debug session
	var results []templates.SAMLResultEntryData
	if debugSession != nil {
		for i, entry := range debugSession.Results {
			results = append(results, buildSAMLResultEntryData(i, entry))
		}
	}

	// If logged in but no results from debug session, build a synthetic entry
	if session != nil && len(results) == 0 {
		sa, ok := session.(samlsp.SessionWithAttributes)
		if ok {
			attrs := sa.GetAttributes()
			var subject string
			if claims, ok := session.(samlsp.JWTSessionClaims); ok {
				subject = claims.Subject
			}
			now := time.Now()
			entryData := templates.SAMLResultEntryData{
				ID:               "result-0",
				Type:             "Login",
				Timestamp:        formatTimestamp(now),
				SidebarTimestamp: formatTimestamp(now),
				Subject:          subject,
				SidebarLabel:     "Login",
				SidebarDot:       "login",
			}
			attrKeys := protocol.SortedKeys(toStringMap(attrs))
			for _, k := range attrKeys {
				entryData.Attributes = append(entryData.Attributes, components.ClaimRow{
					Key:   k,
					Value: attrs.Get(k),
				})
			}
			results = []templates.SAMLResultEntryData{entryData}
		}
	}

	data := templates.SAMLPageData{
		Name:            h.Config.Name,
		Results:         results,
		IDPMetadataXML:  protocol.FormatXML(h.idpMetadataRaw),
		ACSPath:         h.Config.ACSPath,
		RequestBinding:  h.requestBinding,
		ResponseBinding: h.responseBinding,
		EndpointRows:    h.endpointRows,
		IDPCertificates: h.idpCertificates,
	}

	page := templates.PageInfo{
		Tabs:         h.navTabs,
		ActiveTab:    h.activeTab(),
		DefaultTheme: h.defaultTheme,
		References: []templates.Section{
			{ID: "sec-flow", Label: "Flow Diagram"},
			{ID: "sec-idp", Label: "Identity Provider"},
		},
	}

	if session != nil {
		// Logged in
		page.Status = "connected"
		page.StatusLabel = "Active Session"
		page.LogoutURL = "/logout"
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

	templates.SAMLIndex(page, data).Render(r.Context(), w)
}

// buildSAMLResultEntryData converts a SAMLResultEntry to template display data.
func buildSAMLResultEntryData(index int, entry SAMLResultEntry) templates.SAMLResultEntryData {
	id := fmt.Sprintf("result-%d", index)

	data := templates.SAMLResultEntryData{
		ID:               id,
		Type:             entry.Type,
		Timestamp:        formatTimestamp(entry.Timestamp),
		SidebarTimestamp: formatTimestamp(entry.Timestamp),
		Subject:          entry.Subject,
	}

	// Error entry
	if entry.Type == "Error" {
		data.ErrorCode = entry.ErrorCode
		data.ErrorDetail = entry.ErrorDetail
		data.AuthnRequestXML = protocol.FormatXML(entry.AuthnRequestXML)
		data.SAMLResponseXML = protocol.FormatXML(entry.SAMLResponseXML)
		data.SidebarLabel = "Error"
		data.SidebarDot = "error"
		return data
	}

	// Logout entry
	if strings.HasPrefix(entry.Type, "Logout") {
		data.SidebarLabel = entry.Type
		data.SidebarDot = "logout"

		// LogoutRequest details (IdP-initiated: incoming request)
		if entry.LogoutRequestXML != "" {
			data.LogoutRequestXML = protocol.FormatXML(entry.LogoutRequestXML)
			if requestInfo := protocol.ExtractSAMLResponseInfo(entry.LogoutRequestXML); requestInfo != nil {
				for _, group := range requestInfo.Groups {
					var rows []components.GroupedRow
					for _, row := range group.Rows {
						rows = append(rows, components.GroupedRow{Label: row.Label, Value: row.Value})
					}
					data.ResponseGroups = append(data.ResponseGroups, components.RowGroup{
						Name: "Logout Request",
						Rows: rows,
					})
				}
			}
		}

		// SP-initiated: LogoutRequestURL (outgoing)
		if entry.LogoutRequestURL != "" {
			data.LogoutRequestURL = entry.LogoutRequestURL
			data.LogoutRequestParams = parseToClaimRows(protocol.ParseURLParams(entry.LogoutRequestURL))
		}

		// LogoutResponse details
		if entry.LogoutResponseXML != "" {
			data.LogoutResponseXML = protocol.FormatXML(entry.LogoutResponseXML)
			if responseInfo := protocol.ExtractSAMLResponseInfo(entry.LogoutResponseXML); responseInfo != nil {
				for _, group := range responseInfo.Groups {
					var rows []components.GroupedRow
					for _, row := range group.Rows {
						rows = append(rows, components.GroupedRow{Label: row.Label, Value: row.Value})
					}
					data.ResponseGroups = append(data.ResponseGroups, components.RowGroup{
						Name: "Logout Response",
						Rows: rows,
					})
				}
			}
		}

		// IdP-initiated: outgoing LogoutResponse URL (Redirect binding)
		if entry.LogoutResponseURL != "" {
			data.LogoutResponseURL = entry.LogoutResponseURL
			data.LogoutResponseParams = parseToClaimRows(protocol.ParseURLParams(entry.LogoutResponseURL))
		}

		// Signatures (LogoutRequest from IdP)
		sigVerifiedAll := true
		for _, sigInfo := range entry.SignatureInfos {
			verifiedStr := "false"
			if sigInfo.Verified {
				verifiedStr = "true"
			} else {
				sigVerifiedAll = false
			}
			var rows []components.SignatureRow
			pairs := []struct{ label, value string }{
				{"Signature Algorithm", sigInfo.Algorithm},
				{"Signature Algorithm (short)", sigInfo.AlgorithmShort},
				{"Digest Algorithm", sigInfo.DigestAlgorithm},
				{"Digest Algorithm (short)", sigInfo.DigestAlgorithmShort},
				{"Key Name", sigInfo.KeyName},
				{"Certificate Subject", sigInfo.CertSubject},
				{"Certificate Issuer", sigInfo.CertIssuer},
				{"Certificate Serial Number", sigInfo.CertSerialNumber},
				{"Certificate Not Before", sigInfo.CertNotBefore},
				{"Certificate Not After", sigInfo.CertNotAfter},
				{"Certificate Fingerprint (SHA-256)", sigInfo.CertFingerprint},
				{"Verified", verifiedStr},
			}
			for _, p := range pairs {
				if p.value != "" {
					rows = append(rows, components.SignatureRow{Label: p.label, Value: p.value})
				}
			}
			data.Signatures = append(data.Signatures, templates.SAMLSignatureData{
				Title: sigInfo.Target + " Signature Verification",
				Rows:  rows,
			})
		}
		data.SigVerifiedAll = sigVerifiedAll

		// Sidebar children
		if len(data.ResponseGroups) > 0 {
			data.Children = append(data.Children, templates.Section{ID: id + "-details", Label: "Logout Details"})
		}
		if len(entry.SignatureInfos) > 0 {
			data.Children = append(data.Children, templates.Section{ID: id + "-sigs", Label: "Signature Verification"})
		}
		if data.LogoutRequestURL != "" || data.LogoutResponseXML != "" || data.LogoutRequestXML != "" || data.LogoutResponseURL != "" {
			data.Children = append(data.Children, templates.Section{ID: id + "-protocol", Label: "Protocol Messages"})
		}
		return data
	}

	// Attributes
	if entry.Attributes != nil {
		attrKeys := protocol.SortedKeys(toStringMapFromSlice(entry.Attributes))
		for _, k := range attrKeys {
			vals := entry.Attributes[k]
			if len(vals) > 0 {
				data.Attributes = append(data.Attributes, components.ClaimRow{
					Key:   k,
					Value: vals[0],
				})
			}
		}
	}

	// Signatures
	sigVerifiedAll := true
	for _, sigInfo := range entry.SignatureInfos {
		verifiedStr := "false"
		if sigInfo.Verified {
			verifiedStr = "true"
		} else {
			sigVerifiedAll = false
		}
		var rows []components.SignatureRow
		pairs := []struct{ label, value string }{
			{"Signature Algorithm", sigInfo.Algorithm},
			{"Signature Algorithm (short)", sigInfo.AlgorithmShort},
			{"Digest Algorithm", sigInfo.DigestAlgorithm},
			{"Digest Algorithm (short)", sigInfo.DigestAlgorithmShort},
			{"Key Name", sigInfo.KeyName},
			{"Certificate Subject", sigInfo.CertSubject},
			{"Certificate Issuer", sigInfo.CertIssuer},
			{"Certificate Serial Number", sigInfo.CertSerialNumber},
			{"Certificate Not Before", sigInfo.CertNotBefore},
			{"Certificate Not After", sigInfo.CertNotAfter},
			{"Certificate Fingerprint (SHA-256)", sigInfo.CertFingerprint},
			{"Verified", verifiedStr},
		}
		for _, p := range pairs {
			if p.value != "" {
				rows = append(rows, components.SignatureRow{Label: p.label, Value: p.value})
			}
		}
		data.Signatures = append(data.Signatures, templates.SAMLSignatureData{
			Title: sigInfo.Target + " Signature Verification",
			Rows:  rows,
		})
	}
	data.SigVerifiedAll = sigVerifiedAll

	// Response details
	if entry.ResponseInfo != nil {
		for _, group := range entry.ResponseInfo.Groups {
			var rows []components.GroupedRow
			for _, row := range group.Rows {
				rows = append(rows, components.GroupedRow{Label: row.Label, Value: row.Value})
			}
			data.ResponseGroups = append(data.ResponseGroups, components.RowGroup{
				Name: group.Name,
				Rows: rows,
			})
		}
	}

	// Protocol messages
	data.AuthnRequestXML = protocol.FormatXML(entry.AuthnRequestXML)
	data.SAMLResponseXML = protocol.FormatXML(entry.SAMLResponseXML)

	// Sidebar label and dot
	switch {
	case entry.Type == "Login":
		data.SidebarLabel = "Login"
		data.SidebarDot = "login"
	default: // Re-auth: *
		data.SidebarLabel = entry.Type
		data.SidebarDot = "reauth"
	}

	// Build sidebar children (sub-sections)
	if len(entry.Attributes) > 0 || entry.Subject != "" {
		data.Children = append(data.Children, templates.Section{ID: id + "-claims", Label: "Identity & Claims"})
	}
	if entry.ResponseInfo != nil && len(entry.ResponseInfo.Groups) > 0 {
		data.Children = append(data.Children, templates.Section{ID: id + "-response", Label: "Response Details"})
	}
	if len(entry.SignatureInfos) > 0 {
		data.Children = append(data.Children, templates.Section{ID: id + "-sigs", Label: "Signature Verification"})
	}
	if entry.AuthnRequestXML != "" || entry.SAMLResponseXML != "" {
		data.Children = append(data.Children, templates.Section{ID: id + "-protocol", Label: "Protocol Messages"})
	}

	return data
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	h.startAuthFlow(w, r, "", "", false)
}

func (h *Handler) handleReauth(w http.ResponseWriter, r *http.Request) {
	// Verify session exists
	session, err := h.sp.Session.GetSession(r)
	if err != nil || session == nil {
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
		h.startAuthFlow(w, r, "__default__", "", false)
		return
	}

	if step < 0 || step >= len(h.Config.Reauth) {
		http.Error(w, "Invalid reauth step", http.StatusBadRequest)
		return
	}

	rc := h.Config.Reauth[step]
	h.startAuthFlow(w, r, rc.Name, rc.AuthnContextClassRef, rc.ForceAuthn)
}

// startAuthFlow initiates a SAML AuthnRequest with optional RequestedAuthnContext and ForceAuthn.
func (h *Handler) startAuthFlow(w http.ResponseWriter, r *http.Request, reauthName string, authnContextClassRef string, forceAuthn bool) {
	// Determine binding
	binding := samlpkg.HTTPRedirectBinding
	bindingLocation := h.sp.ServiceProvider.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = samlpkg.HTTPPostBinding
		bindingLocation = h.sp.ServiceProvider.GetSSOBindingLocation(binding)
	}

	// Generate AuthnRequest
	authReq, err := h.sp.ServiceProvider.MakeAuthenticationRequest(
		bindingLocation, binding, samlpkg.HTTPPostBinding,
	)
	if err != nil {
		log.Printf("Failed to make AuthnRequest: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Apply RequestedAuthnContext if specified
	if authnContextClassRef != "" {
		authReq.RequestedAuthnContext = &samlpkg.RequestedAuthnContext{
			Comparison:           "exact",
			AuthnContextClassRef: authnContextClassRef,
		}
	}

	// Apply ForceAuthn if specified
	if forceAuthn {
		forceAuthnVal := true
		authReq.ForceAuthn = &forceAuthnVal
	}

	// Store reauth name in cookie
	if reauthName != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "saml_reauth_name",
			Value:    reauthName,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: sameSiteMode(r),
		})
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

	pendingEntry := SAMLResultEntry{
		Type:            "pending",
		Timestamp:       time.Now(),
		AuthnRequestXML: string(xmlBytes),
	}

	// Reuse existing debug session if available (preserves timeline on re-auth)
	var debugID string
	if c, err := r.Cookie("saml_debug_id"); err == nil {
		if existing := h.debugSessions.GetByID(c.Value); existing != nil {
			existing.Results = append([]SAMLResultEntry{pendingEntry}, existing.Results...)
			debugID = c.Value
		}
	}

	// Create new debug session if none exists
	if debugID == "" {
		debugID, err = protocol.RandomHex(16)
		if err != nil {
			log.Printf("Failed to generate debug ID: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		h.debugSessions.Set(debugID, &DebugSession{
			Results: []SAMLResultEntry{pendingEntry},
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "saml_debug_id",
			Value:    debugID,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: sameSiteMode(r),
		})
	}

	// Track request
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/"
	r2.RequestURI = "/"
	relayState, err := h.sp.RequestTracker.TrackRequest(w, r2, authReq.ID)
	if err != nil {
		log.Printf("Failed to track request: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect to IdP
	if binding == samlpkg.HTTPRedirectBinding {
		redirectURL, err := authReq.Redirect(relayState, &h.sp.ServiceProvider)
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
}

func (h *Handler) handleACS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Failed to parse ACS form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Decode SAMLResponse from Base64 and store in debug session
	if samlResponseB64 := r.PostForm.Get("SAMLResponse"); samlResponseB64 != "" {
		if samlResponseXMLBytes, err := base64.StdEncoding.DecodeString(samlResponseB64); err == nil {
			samlResponseXML := string(samlResponseXMLBytes)
			signatureInfos := protocol.ExtractSAMLSignatureInfos(samlResponseXML)
			responseInfo := protocol.ExtractSAMLResponseInfo(samlResponseXML)

			// Retrieve reauth name from cookie
			var reauthName string
			if c, err := r.Cookie("saml_reauth_name"); err == nil {
				reauthName = c.Value
				http.SetCookie(w, &http.Cookie{
					Name: "saml_reauth_name", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
				})
			}

			resultType := "Login"
			if reauthName == "__default__" {
				resultType = "Re-auth"
			} else if reauthName != "" {
				resultType = "Re-auth: " + reauthName
			}

			c, cookieErr := r.Cookie("saml_debug_id")
			if cookieErr == nil {
				if ds := h.debugSessions.GetByID(c.Value); ds != nil {
					// Retrieve the AuthnRequest XML from the pending entry
					var authnRequestXML string
					if len(ds.Results) > 0 && ds.Results[0].Type == "pending" {
						authnRequestXML = ds.Results[0].AuthnRequestXML
						// Remove the pending entry
						ds.Results = ds.Results[1:]
					}
					// Prepend the completed result entry
					// Extract Subject and Attributes from SAML Response XML
					subject, attributes := protocol.ExtractSAMLSubjectAndAttributes(samlResponseXML)

					entry := SAMLResultEntry{
						Type:            resultType,
						Timestamp:       time.Now(),
						Subject:         subject,
						Attributes:      attributes,
						AuthnRequestXML: authnRequestXML,
						SAMLResponseXML: samlResponseXML,
						SignatureInfos:  signatureInfos,
						ResponseInfo:    responseInfo,
					}
					ds.Results = append([]SAMLResultEntry{entry}, ds.Results...)
				}
			} else {
				// IdP-initiated: no existing debug session, create one
				debugID, err := protocol.RandomHex(16)
				if err == nil {
					subject, attributes := protocol.ExtractSAMLSubjectAndAttributes(samlResponseXML)

					entry := SAMLResultEntry{
						Type:            resultType,
						Timestamp:       time.Now(),
						Subject:         subject,
						Attributes:      attributes,
						SAMLResponseXML: samlResponseXML,
						SignatureInfos:  signatureInfos,
						ResponseInfo:    responseInfo,
					}
					h.debugSessions.Set(debugID, &DebugSession{
						Results: []SAMLResultEntry{entry},
					})
					http.SetCookie(w, &http.Cookie{
						Name:     "saml_debug_id",
						Value:    debugID,
						Path:     "/",
						MaxAge:   600,
						HttpOnly: true,
						Secure:   isHTTPS(r),
						SameSite: sameSiteMode(r),
					})
				}
			}
		}
	}

	// Delegate to samlsp's standard ACS processing
	h.sp.ServeACS(w, r)
}

func (h *Handler) handleSLO(w http.ResponseWriter, r *http.Request) {
	// Determine binding and extract SAMLResponse/SAMLRequest
	var samlResponseB64, samlRequestB64, relayState string
	isPostBinding := false

	if r.Method == http.MethodPost {
		isPostBinding = true
		r.ParseForm()
		samlResponseB64 = r.PostForm.Get("SAMLResponse")
		samlRequestB64 = r.PostForm.Get("SAMLRequest")
		relayState = r.PostForm.Get("RelayState")
	} else {
		samlResponseB64 = r.URL.Query().Get("SAMLResponse")
		samlRequestB64 = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	}

	// Pattern 1: SAMLResponse — SP-initiated Logout return from IdP
	if samlResponseB64 != "" {
		xmlBytes := decodeSAMLMessage(samlResponseB64, isPostBinding)
		if xmlBytes != nil {
			logoutResponseXML := string(xmlBytes)
			if c, err := r.Cookie("saml_debug_id"); err == nil {
				if ds := h.debugSessions.GetByID(c.Value); ds != nil {
					// Find the most recent Logout entry and attach the response
					for i := range ds.Results {
						if strings.HasPrefix(ds.Results[i].Type, "Logout") && ds.Results[i].LogoutResponseXML == "" {
							ds.Results[i].LogoutResponseXML = logoutResponseXML
							break
						}
					}
					h.debugSessions.Set(c.Value, ds)
				}
			}
		}

		h.sp.Session.DeleteSession(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Pattern 2: SAMLRequest — IdP-initiated LogoutRequest
	if samlRequestB64 != "" {
		xmlBytes := decodeSAMLMessage(samlRequestB64, isPostBinding)
		if xmlBytes == nil {
			log.Printf("Failed to decode IdP-initiated LogoutRequest")
			h.sp.Session.DeleteSession(w, r)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Parse LogoutRequest to get the request ID
		var logoutRequest samlpkg.LogoutRequest
		if err := xmlpkg.Unmarshal(xmlBytes, &logoutRequest); err != nil {
			log.Printf("Failed to parse IdP-initiated LogoutRequest: %v", err)
			h.sp.Session.DeleteSession(w, r)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Build Logout entry for debug display
		logoutRequestXML := string(xmlBytes)
		sigInfos := protocol.ExtractSAMLLogoutRequestSignatureInfos(logoutRequestXML)
		if protocol.VerifyXMLSignature(logoutRequestXML, h.idpSigningCerts) {
			for i := range sigInfos {
				sigInfos[i].Verified = true
			}
		}
		logoutEntry := SAMLResultEntry{
			Type:             "Logout (IdP)",
			Timestamp:        time.Now(),
			LogoutRequestXML: logoutRequestXML,
			SignatureInfos:   sigInfos,
		}

		// Generate LogoutResponse to IdP (match the binding we received)
		if isPostBinding {
			postHTML, err := h.sp.ServiceProvider.MakePostLogoutResponse(logoutRequest.ID, relayState)
			if err != nil {
				log.Printf("Failed to create POST LogoutResponse for IdP-initiated SLO: %v", err)
			} else {
				// Serialize LogoutResponse XML for debug display
				sloURL := h.sp.ServiceProvider.GetSLOBindingLocation(samlpkg.HTTPPostBinding)
				if resp, err := h.sp.ServiceProvider.MakeLogoutResponse(sloURL, logoutRequest.ID); err == nil {
					doc := etree.NewDocument()
					doc.SetRoot(resp.Element())
					if xmlBytes, err := doc.WriteToBytes(); err == nil {
						logoutEntry.LogoutResponseXML = string(xmlBytes)
					}
				}

				// Save entry to debug session before sending response
				h.saveLogoutEntry(w, r, logoutEntry)

				// Delete SP session
				h.sp.Session.DeleteSession(w, r)

				// Send POST form to IdP
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(`<!DOCTYPE html><html><body>`))
				w.Write(postHTML)
				w.Write([]byte(`</body></html>`))
				return
			}
		} else {
			redirectURL, err := h.sp.ServiceProvider.MakeRedirectLogoutResponse(logoutRequest.ID, relayState)
			if err != nil {
				log.Printf("Failed to create Redirect LogoutResponse for IdP-initiated SLO: %v", err)
			} else {
				logoutEntry.LogoutResponseURL = redirectURL.String()
			}
		}

		// Save entry to debug session
		h.saveLogoutEntry(w, r, logoutEntry)

		// Delete SP session
		h.sp.Session.DeleteSession(w, r)

		// Redirect to IdP with LogoutResponse
		if logoutEntry.LogoutResponseURL != "" && !isPostBinding {
			http.Redirect(w, r, logoutEntry.LogoutResponseURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Neither SAMLResponse nor SAMLRequest — just delete session
	h.sp.Session.DeleteSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

// decodeSAMLMessage decodes a Base64-encoded SAML message.
// POST binding uses plain Base64; Redirect binding uses Base64 + DEFLATE.
func decodeSAMLMessage(b64 string, isPostBinding bool) []byte {
	if isPostBinding {
		xmlBytes, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			log.Printf("Failed to base64-decode SAML POST message: %v", err)
			return nil
		}
		return xmlBytes
	}
	xmlBytes, err := protocol.DecodeSAMLRedirectBinding(b64)
	if err != nil {
		log.Printf("Failed to decode SAML Redirect message: %v", err)
		return nil
	}
	return xmlBytes
}

// saveLogoutEntry saves a logout entry to the debug session.
func (h *Handler) saveLogoutEntry(w http.ResponseWriter, r *http.Request, entry SAMLResultEntry) {
	if c, err := r.Cookie("saml_debug_id"); err == nil {
		if ds := h.debugSessions.GetByID(c.Value); ds != nil {
			ds.Results = append([]SAMLResultEntry{entry}, ds.Results...)
			h.debugSessions.Set(c.Value, ds)
			return
		}
	}
	// No existing debug session — create one
	debugID, err := protocol.RandomHex(16)
	if err != nil {
		return
	}
	h.debugSessions.Set(debugID, &DebugSession{
		Results: []SAMLResultEntry{entry},
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "saml_debug_id",
		Value:    debugID,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: sameSiteMode(r),
	})
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

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Get NameID from current session before deleting it
	var nameID string
	if session, err := h.sp.Session.GetSession(r); err == nil && session != nil {
		if claims, ok := session.(samlsp.JWTSessionClaims); ok {
			nameID = claims.Subject
		}
	}

	// Build Logout entry
	logoutEntry := SAMLResultEntry{
		Type:      "Logout (SP)",
		Timestamp: time.Now(),
	}

	// Build SLO redirect URL
	if nameID != "" {
		if sloURL := h.sp.ServiceProvider.GetSLOBindingLocation(samlpkg.HTTPRedirectBinding); sloURL != "" {
			redirectURL, err := h.sp.ServiceProvider.MakeRedirectLogoutRequest(nameID, h.rootURLStr+"/")
			if err == nil {
				logoutEntry.LogoutRequestURL = redirectURL.String()
			} else {
				log.Printf("Failed to create SAML logout request: %v", err)
			}
		}
	}

	// Save Logout entry to debug session (preserved across logout)
	if c, err := r.Cookie("saml_debug_id"); err == nil {
		if ds := h.debugSessions.GetByID(c.Value); ds != nil {
			ds.Results = append([]SAMLResultEntry{logoutEntry}, ds.Results...)
			h.debugSessions.Set(c.Value, ds)
		}
	}

	// Delete SP auth session only
	h.sp.Session.DeleteSession(w, r)

	// Redirect to IdP SLO endpoint or back to index
	if logoutEntry.LogoutRequestURL != "" {
		http.Redirect(w, r, logoutEntry.LogoutRequestURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// handleClear clears all debug results.
func (h *Handler) handleClear(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("saml_debug_id"); err == nil {
		h.debugSessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "saml_debug_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
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

func toStringMapFromSlice(attrs map[string][]string) map[string]string {
	m := make(map[string]string, len(attrs))
	for k, v := range attrs {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
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
