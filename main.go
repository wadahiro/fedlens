package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/wadahiro/fedlens/internal/config"
	fedoidc "github.com/wadahiro/fedlens/internal/oidc"
	"github.com/wadahiro/fedlens/internal/protocol"
	fedsaml "github.com/wadahiro/fedlens/internal/saml"
	"github.com/wadahiro/fedlens/internal/ui"
	"github.com/wadahiro/fedlens/internal/ui/templates"
)

type routeEntry struct {
	host     string
	basePath string
	baseURL  string
	handler  http.Handler
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		healthURL := os.Getenv("HEALTHCHECK_URL")
		if healthURL == "" {
			healthURL = "http://localhost:3000/healthz"
		}
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
		resp, err := client.Get(healthURL)
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Load configuration from TOML file
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		slog.Error("CONFIG_FILE environment variable is required")
		os.Exit(1)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}
	if len(cfg.OIDC) == 0 && len(cfg.SAML) == 0 && len(cfg.OAuth2) == 0 {
		slog.Error("No [[oidc]], [[saml]], or [[oauth2]] entries defined in config file")
		os.Exit(1)
	}

	// Setup structured logging
	setupLogger(cfg.LogLevel)

	// Setup display timezone
	if cfg.Timezone != "" && cfg.Timezone != "UTC" {
		loc, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			slog.Error("Invalid timezone", "timezone", cfg.Timezone, "error", err)
			os.Exit(1)
		}
		protocol.DisplayLocation = loc
		slog.Info("Display timezone configured", "timezone", cfg.Timezone)
	}

	httpClient := &http.Client{}
	if cfg.InsecureSkipVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		slog.Warn("TLS certificate verification is disabled")
	}

	// Build nav tabs for all SP/RPs (sorted by TOML definition order)
	type tabInfo struct {
		order    int
		routeKey string
		tab      templates.NavTab
	}
	var tabInfos []tabInfo
	for _, c := range cfg.OIDC {
		routeKey := c.ParsedHost + c.BasePath
		tabInfos = append(tabInfos, tabInfo{order: c.Order, routeKey: routeKey,
			tab: templates.NavTab{Label: c.Name, BaseURL: c.BaseURL, Protocol: "oidc"}})
	}
	for _, c := range cfg.SAML {
		routeKey := c.ParsedHost + c.BasePath
		tabInfos = append(tabInfos, tabInfo{order: c.Order, routeKey: routeKey,
			tab: templates.NavTab{Label: c.Name, BaseURL: c.BaseURL, Protocol: "saml"}})
	}
	for _, c := range cfg.OAuth2 {
		routeKey := c.ParsedHost + c.BasePath
		tabInfos = append(tabInfos, tabInfo{order: c.Order, routeKey: routeKey,
			tab: templates.NavTab{Label: c.Name, BaseURL: c.BaseURL, Protocol: "oauth2"}})
	}
	slices.SortStableFunc(tabInfos, func(a, b tabInfo) int { return a.order - b.order })

	var allTabs []templates.NavTab
	tabIndex := make(map[string]int) // routeKey -> tab index
	for i, ti := range tabInfos {
		tabIndex[ti.routeKey] = i
		allTabs = append(allTabs, ti.tab)
	}

	// Static file server for embedded assets
	staticFS, err := fs.Sub(ui.StaticFiles, "static")
	if err != nil {
		slog.Error("Failed to create static file sub", "error", err)
		os.Exit(1)
	}
	staticHandler := http.FileServer(http.FS(staticFS))

	// Route entries for host+path based routing
	var routes []routeEntry

	// Initialize OIDC handlers
	for _, oidcCfg := range cfg.OIDC {
		handler, err := fedoidc.NewHandler(oidcCfg, httpClient)
		if err != nil {
			slog.Error("Failed to initialize OIDC handler", "name", oidcCfg.Name, "error", err)
			os.Exit(1)
		}
		routeKey := oidcCfg.ParsedHost + oidcCfg.BasePath
		handler.SetNavTabs(makeTabsWithActive(allTabs, tabIndex[routeKey]))
		handler.SetDefaultTheme(cfg.Theme)

		mux := http.NewServeMux()
		handler.RegisterRoutes(mux)

		var h http.Handler = mux
		if oidcCfg.BasePath != "" {
			h = http.StripPrefix(oidcCfg.BasePath, mux)
		}

		routes = append(routes, routeEntry{
			host:     oidcCfg.ParsedHost,
			basePath: oidcCfg.BasePath,
			baseURL:  oidcCfg.BaseURL,
			handler:  h,
		})
		slog.Info("OIDC RP registered", "name", oidcCfg.Name, "base_url", oidcCfg.BaseURL)
	}

	// Initialize SAML handlers
	for _, samlCfg := range cfg.SAML {
		handler, err := fedsaml.NewHandler(samlCfg, httpClient)
		if err != nil {
			slog.Error("Failed to initialize SAML handler", "name", samlCfg.Name, "error", err)
			os.Exit(1)
		}
		routeKey := samlCfg.ParsedHost + samlCfg.BasePath
		handler.SetNavTabs(makeTabsWithActive(allTabs, tabIndex[routeKey]))
		handler.SetDefaultTheme(cfg.Theme)

		mux := http.NewServeMux()
		handler.RegisterRoutes(mux)

		var h http.Handler = mux
		if samlCfg.BasePath != "" {
			h = http.StripPrefix(samlCfg.BasePath, mux)
		}

		routes = append(routes, routeEntry{
			host:     samlCfg.ParsedHost,
			basePath: samlCfg.BasePath,
			baseURL:  samlCfg.BaseURL,
			handler:  h,
		})
		slog.Info("SAML SP registered", "name", samlCfg.Name, "base_url", samlCfg.BaseURL)
	}

	// Initialize OAuth2 handlers
	for _, oauth2Cfg := range cfg.OAuth2 {
		handler, err := fedoidc.NewOAuth2Handler(oauth2Cfg, httpClient)
		if err != nil {
			slog.Error("Failed to initialize OAuth2 handler", "name", oauth2Cfg.Name, "error", err)
			os.Exit(1)
		}
		routeKey := oauth2Cfg.ParsedHost + oauth2Cfg.BasePath
		handler.SetNavTabs(makeTabsWithActive(allTabs, tabIndex[routeKey]))
		handler.SetDefaultTheme(cfg.Theme)

		mux := http.NewServeMux()
		handler.RegisterRoutes(mux)

		var h http.Handler = mux
		if oauth2Cfg.BasePath != "" {
			h = http.StripPrefix(oauth2Cfg.BasePath, mux)
		}

		routes = append(routes, routeEntry{
			host:     oauth2Cfg.ParsedHost,
			basePath: oauth2Cfg.BasePath,
			baseURL:  oauth2Cfg.BaseURL,
			handler:  h,
		})
		slog.Info("OAuth2 Client registered", "name", oauth2Cfg.Name, "base_url", oauth2Cfg.BaseURL)
	}

	// Root mux with health check, static files, and host+path-based routing
	rootMux := http.NewServeMux()

	// RFC 9728: Register Protected Resource Metadata well-known endpoints for OAuth2 handlers
	for _, oauth2Cfg := range cfg.OAuth2 {
		// Re-derive metadata path and JSON from config (no handler state needed)
		basePath := oauth2Cfg.BasePath
		metadataPath := "/.well-known/oauth-protected-resource" + basePath + "/resource"
		resourceURL := oauth2Cfg.BaseURL + "/resource"
		authServer := oauth2Cfg.Issuer
		if authServer == "" && oauth2Cfg.TokenURL != "" {
			if u, err := url.Parse(oauth2Cfg.TokenURL); err == nil {
				authServer = u.Scheme + "://" + u.Host
			}
		}
		metadata := map[string]any{
			"resource":                 resourceURL,
			"authorization_servers":    []string{authServer},
			"bearer_methods_supported": []string{"header"},
			"resource_name":            "fedlens Built-in Resource Server (" + oauth2Cfg.Name + ")",
		}
		if len(oauth2Cfg.Scopes) > 0 {
			metadata["scopes_supported"] = oauth2Cfg.Scopes
		}
		metadataJSON, _ := json.MarshalIndent(metadata, "", "  ")
		rootMux.HandleFunc(metadataPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(metadataJSON)
		})
		slog.Info("RFC 9728 metadata registered", "path", metadataPath)
	}
	rootMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	rootMux.Handle("/static/", http.StripPrefix("/static/", staticHandler))
	rootMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		// 1. Path-based routes first (host + path prefix match)
		for _, route := range routes {
			if route.basePath != "" && host == route.host {
				if strings.HasPrefix(r.URL.Path, route.basePath+"/") || r.URL.Path == route.basePath {
					route.handler.ServeHTTP(w, r)
					return
				}
			}
		}

		// 2. Host-based routes (host only match, no basePath)
		for _, route := range routes {
			if route.basePath == "" && host == route.host {
				route.handler.ServeHTTP(w, r)
				return
			}
		}

		// 3. Root "/" → redirect to first app (when path-based apps are configured)
		if r.URL.Path == "/" && len(routes) > 0 {
			http.Redirect(w, r, routes[0].baseURL+"/", http.StatusFound)
			return
		}

		http.Error(w, "Not found", http.StatusNotFound)
	})

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      rootMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		var err error
		if cfg.TLSSelfSigned {
			tlsCert, certErr := generateSelfSignedTLSCert()
			if certErr != nil {
				slog.Error("Failed to generate self-signed TLS certificate", "error", certErr)
				os.Exit(1)
			}
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
			slog.Info("Listening (TLS, self-signed)", "addr", cfg.ListenAddr)
			err = server.ListenAndServeTLS("", "")
		} else if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
			slog.Info("Listening (TLS)", "addr", cfg.ListenAddr)
			err = server.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
		} else {
			slog.Info("Listening", "addr", cfg.ListenAddr)
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-shutdown
	slog.Info("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Shutdown failed", "error", err)
		os.Exit(1)
	}
	slog.Info("Server stopped")
}

func setupLogger(level string) {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))
}

func makeTabsWithActive(allTabs []templates.NavTab, activeIdx int) []templates.NavTab {
	tabs := make([]templates.NavTab, len(allTabs))
	copy(tabs, allTabs)
	if activeIdx >= 0 && activeIdx < len(tabs) {
		tabs[activeIdx].Active = true
	}
	return tabs
}

func generateSelfSignedTLSCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate RSA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}
