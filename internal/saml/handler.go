package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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

	return &Handler{
		Config:          cfg,
		debugSessions:   NewDebugSessionStore(),
		sp:              sp,
		httpClient:      httpClient,
		idpMetadataRaw:  idpMetadataRaw,
		rootURLStr:      cfg.RootURL,
		requestBinding:  reqBinding,
		responseBinding: "post", // SAML Response is always HTTP-POST binding
	}, nil
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

	session, err := h.sp.Session.GetSession(r)
	if err != nil || session == nil {
		idpMetadataXML := protocol.FormatXML(h.idpMetadataRaw)
		page := templates.PageInfo{
			Tabs:         h.navTabs,
			ActiveTab:    h.activeTab(),
			Status:       "disconnected",
			StatusLabel:  "No Session",
			LoginURL:     "/login",
			DefaultTheme: h.defaultTheme,
			References: []templates.Section{
				{ID: "sec-flow", Label: "Flow Diagram"},
				{ID: "sec-config", Label: "IdP Metadata"},
			},
		}
		templates.SAMLIndex(page, h.Config.Name, idpMetadataXML, h.Config.ACSPath, h.requestBinding, h.responseBinding).Render(r.Context(), w)
		return
	}

	sa, ok := session.(samlsp.SessionWithAttributes)
	if !ok {
		http.Error(w, "Invalid session", http.StatusInternalServerError)
		return
	}
	attrs := sa.GetAttributes()
	debugSession := h.debugSessions.Get(r)

	// Extract NameID from session
	var subject string
	if claims, ok := session.(samlsp.JWTSessionClaims); ok {
		subject = claims.Subject
	}

	// Build template data
	data := templates.SAMLDebugData{
		Name:            h.Config.Name,
		Subject:         subject,
		IDPMetadataXML:  protocol.FormatXML(h.idpMetadataRaw),
		ACSPath:         h.Config.ACSPath,
		RequestBinding:  h.requestBinding,
		ResponseBinding: h.responseBinding,
	}

	// Attributes
	attrKeys := protocol.SortedKeys(toStringMap(attrs))
	for _, k := range attrKeys {
		data.Attributes = append(data.Attributes, components.ClaimRow{
			Key:   k,
			Value: attrs.Get(k),
		})
	}

	// Signature info
	sigVerifiedAll := true
	if debugSession != nil && len(debugSession.SignatureInfos) > 0 {
		for _, sigInfo := range debugSession.SignatureInfos {
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
	}
	data.SigVerifiedAll = sigVerifiedAll

	if debugSession != nil {
		data.AuthnRequestXML = protocol.FormatXML(debugSession.AuthnRequestXML)
		data.SAMLResponseXML = protocol.FormatXML(debugSession.SAMLResponseXML)

		// Extract SAML Response details
		if debugSession.ResponseInfo != nil {
			for _, group := range debugSession.ResponseInfo.Groups {
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
			{ID: "sec-idp", Label: "IdP Info"},
		},
		Sections: []templates.Section{
			{ID: "sec-claims", Label: "Identity & Claims"},
			{ID: "sec-response", Label: "SAML Response Details"},
			{ID: "sec-sigs", Label: "Signature Verification"},
			{ID: "sec-protocol", Label: "Protocol Messages"},
		},
	}

	templates.SAMLDebug(page, data).Render(r.Context(), w)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	debugID, err := protocol.RandomHex(16)
	if err != nil {
		log.Printf("Failed to generate debug ID: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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

	// Serialize AuthnRequest to XML for debug display
	xmlDoc := etree.NewDocument()
	xmlDoc.SetRoot(authReq.Element())
	xmlBytes, err := xmlDoc.WriteToBytes()
	if err != nil {
		log.Printf("Failed to serialize AuthnRequest XML: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.debugSessions.Set(debugID, &DebugSession{
		AuthnRequestXML: string(xmlBytes),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "saml_debug_id",
		Value:    debugID,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

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

			c, cookieErr := r.Cookie("saml_debug_id")
			if cookieErr == nil {
				// SP-initiated: update existing debug session
				if ds := h.debugSessions.GetByID(c.Value); ds != nil {
					ds.SAMLResponseXML = samlResponseXML
					ds.SignatureInfos = signatureInfos
					ds.ResponseInfo = responseInfo
				}
			} else {
				// IdP-initiated: no existing debug session, create one
				debugID, err := protocol.RandomHex(16)
				if err == nil {
					h.debugSessions.Set(debugID, &DebugSession{
						SAMLResponseXML: samlResponseXML,
						SignatureInfos:  signatureInfos,
						ResponseInfo:    responseInfo,
					})
					http.SetCookie(w, &http.Cookie{
						Name:     "saml_debug_id",
						Value:    debugID,
						Path:     "/",
						MaxAge:   600,
						HttpOnly: true,
						SameSite: http.SameSiteLaxMode,
					})
				}
			}
		}
	}

	// Delegate to samlsp's standard ACS processing
	h.sp.ServeACS(w, r)
}

func (h *Handler) handleSLO(w http.ResponseWriter, r *http.Request) {
	h.sp.Session.DeleteSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Get NameID from current session before deleting it
	var nameID string
	if session, err := h.sp.Session.GetSession(r); err == nil && session != nil {
		if claims, ok := session.(samlsp.JWTSessionClaims); ok {
			nameID = claims.Subject
		}
	}

	// Delete SP session cookie
	h.sp.Session.DeleteSession(w, r)

	if c, err := r.Cookie("saml_debug_id"); err == nil {
		h.debugSessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "saml_debug_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})

	// Send SAML LogoutRequest to IdP
	if nameID != "" {
		if sloURL := h.sp.ServiceProvider.GetSLOBindingLocation(samlpkg.HTTPRedirectBinding); sloURL != "" {
			redirectURL, err := h.sp.ServiceProvider.MakeRedirectLogoutRequest(nameID, h.rootURLStr+"/")
			if err == nil {
				http.Redirect(w, r, redirectURL.String(), http.StatusFound)
				return
			}
			log.Printf("Failed to create SAML logout request: %v", err)
		}
	}

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
