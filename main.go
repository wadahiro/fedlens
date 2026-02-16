package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
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
	if len(cfg.OIDC) == 0 && len(cfg.SAML) == 0 {
		slog.Error("No [[oidc]] or [[saml]] entries defined in config file")
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

	// Build nav tabs for all SP/RPs
	var allTabs []templates.NavTab
	hostTabIndex := make(map[string]int)

	for _, oidcCfg := range cfg.OIDC {
		hostTabIndex[oidcCfg.Host] = len(allTabs)
		allTabs = append(allTabs, templates.NavTab{
			Label:    oidcCfg.Name,
			BaseURL:  extractBaseURL(oidcCfg.RedirectURI),
			Protocol: "oidc",
		})
	}
	for _, samlCfg := range cfg.SAML {
		hostTabIndex[samlCfg.Host] = len(allTabs)
		allTabs = append(allTabs, templates.NavTab{
			Label:    samlCfg.Name,
			BaseURL:  extractBaseURL(samlCfg.RootURL),
			Protocol: "saml",
		})
	}

	// Static file server for embedded assets
	staticFS, err := fs.Sub(ui.StaticFiles, "static")
	if err != nil {
		slog.Error("Failed to create static file sub", "error", err)
		os.Exit(1)
	}
	staticHandler := http.FileServer(http.FS(staticFS))

	// Host-based router
	hostRouters := make(map[string]http.Handler)

	// Initialize OIDC handlers
	for _, oidcCfg := range cfg.OIDC {
		handler, err := fedoidc.NewHandler(oidcCfg, httpClient)
		if err != nil {
			slog.Error("Failed to initialize OIDC handler", "name", oidcCfg.Name, "error", err)
			os.Exit(1)
		}
		handler.SetNavTabs(makeTabsWithActive(allTabs, hostTabIndex[oidcCfg.Host]))
		handler.SetDefaultTheme(cfg.Theme)

		mux := http.NewServeMux()
		mux.Handle("/static/", http.StripPrefix("/static/", staticHandler))
		handler.RegisterRoutes(mux)
		hostRouters[oidcCfg.Host] = mux
		slog.Info("OIDC RP registered", "name", oidcCfg.Name, "host", oidcCfg.Host)
	}

	// Initialize SAML handlers
	for _, samlCfg := range cfg.SAML {
		handler, err := fedsaml.NewHandler(samlCfg, httpClient)
		if err != nil {
			slog.Error("Failed to initialize SAML handler", "name", samlCfg.Name, "error", err)
			os.Exit(1)
		}
		handler.SetNavTabs(makeTabsWithActive(allTabs, hostTabIndex[samlCfg.Host]))
		handler.SetDefaultTheme(cfg.Theme)

		mux := http.NewServeMux()
		mux.Handle("/static/", http.StripPrefix("/static/", staticHandler))
		handler.RegisterRoutes(mux)
		hostRouters[samlCfg.Host] = mux
		slog.Info("SAML SP registered", "name", samlCfg.Name, "host", samlCfg.Host)
	}

	// Root mux with health check and host-based routing
	rootMux := http.NewServeMux()
	rootMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	rootMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if handler, ok := hostRouters[r.Host]; ok {
			handler.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Unknown host", http.StatusNotFound)
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

func extractBaseURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
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
