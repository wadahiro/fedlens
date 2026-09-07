package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration.
type Config struct {
	ListenAddr         string         `toml:"listen_addr"`
	InsecureSkipVerify bool           `toml:"insecure_skip_verify"`
	LogLevel           string         `toml:"log_level"`
	Theme              string         `toml:"theme"`
	Timezone           string         `toml:"timezone"`
	TLSCertPath        string         `toml:"tls_cert_path"`
	TLSKeyPath         string         `toml:"tls_key_path"`
	TLSSelfSigned      bool           `toml:"tls_self_signed"`
	OIDC               []OIDCConfig   `toml:"oidc"`
	SAML               []SAMLConfig   `toml:"saml"`
	OAuth2             []OAuth2Config `toml:"oauth2"`
}

// OIDCConfig defines a single OIDC RP instance.
type OIDCConfig struct {
	Name              string            `toml:"name"`
	BaseURL           string            `toml:"base_url"`
	Issuer            string            `toml:"issuer"`
	ClientID          string            `toml:"client_id"`
	ClientSecret      string            `toml:"client_secret"`
	RedirectURI       string            `toml:"redirect_uri"`
	CallbackPath      string            `toml:"callback_path"`
	Scopes            []string          `toml:"scopes"`
	PKCE              bool              `toml:"pkce"`
	PKCEMethod        string            `toml:"pkce_method"`
	ResponseType      string            `toml:"response_type"`
	ResponseMode      string            `toml:"response_mode"`
	ExtraAuthParams   map[string]string `toml:"extra_auth_params"`
	IntrospectionURL  string            `toml:"introspection_url"` // Token Introspection endpoint (optional, Discovery takes precedence)
	RevocationURL     string            `toml:"revocation_url"`    // Token Revocation endpoint (optional, Discovery takes precedence)
	Reauth            []ReauthConfig    `toml:"reauth"`
	LogoutIDTokenHint *bool             `toml:"logout_id_token_hint"` // default: true

	// AuthRequestMaxAge is how long a sent authorization request stays valid,
	// i.e. how long the user may spend on the IdP login screen before the state
	// and PKCE verifier cookies expire. Accepts a duration string such as "30m".
	AuthRequestMaxAge time.Duration `toml:"auth_request_max_age"`

	// Computed fields (not from TOML)
	ParsedHost string // host:port extracted from base_url
	BasePath   string // path prefix extracted from base_url (empty for host-based routing)
	Order      int    // definition order in TOML file (computed)
}

// OAuth2Config defines a single OAuth2 Client instance.
type OAuth2Config struct {
	Name                       string            `toml:"name"`
	BaseURL                    string            `toml:"base_url"`
	Issuer                     string            `toml:"issuer"`            // RFC 8414 Discovery (optional)
	AuthorizationURL           string            `toml:"authorization_url"` // Manual (required if no issuer)
	TokenURL                   string            `toml:"token_url"`         // Manual (required if no issuer)
	IntrospectionURL           string            `toml:"introspection_url"` // Token Introspection endpoint (optional)
	RevocationURL              string            `toml:"revocation_url"`    // Token Revocation endpoint (optional)
	ClientID                   string            `toml:"client_id"`
	ClientSecret               string            `toml:"client_secret"`
	RedirectURI                string            `toml:"redirect_uri"`
	CallbackPath               string            `toml:"callback_path"`
	Scopes                     []string          `toml:"scopes"`
	PKCE                       bool              `toml:"pkce"`
	PKCEMethod                 string            `toml:"pkce_method"`
	ResponseMode               string            `toml:"response_mode"`
	ExtraAuthParams            map[string]string `toml:"extra_auth_params"`
	Reauth                     []ReauthConfig    `toml:"reauth"`
	ResourceURLs               []string          `toml:"resource_urls"`                 // Custom resource server URLs to test
	ResourceServerClientID     string            `toml:"resource_server_client_id"`     // Client ID for built-in Resource Server (Token Introspection)
	ResourceServerClientSecret string            `toml:"resource_server_client_secret"` // Client Secret for built-in Resource Server (Token Introspection)

	// AuthRequestMaxAge is how long a sent authorization request stays valid,
	// i.e. how long the user may spend on the AS login screen before the state
	// and PKCE verifier cookies expire. Accepts a duration string such as "30m".
	AuthRequestMaxAge time.Duration `toml:"auth_request_max_age"`

	// Computed fields (not from TOML)
	ParsedHost string
	BasePath   string
	Order      int // definition order in TOML file (computed)
}

// ReauthConfig defines a re-authentication profile with extra auth params.
type ReauthConfig struct {
	Name            string            `toml:"name"`
	ExtraAuthParams map[string]string `toml:"extra_auth_params"`
}

// SAMLConfig defines a single SAML SP instance.
type SAMLConfig struct {
	Name              string             `toml:"name"`
	BaseURL           string             `toml:"base_url"`
	IDPMetadataURL    string             `toml:"idp_metadata_url"`
	EntityID          string             `toml:"entity_id"`
	RootURL           string             `toml:"root_url"`
	ACSPath           string             `toml:"acs_path"`
	SLOPath           string             `toml:"slo_path"`
	MetadataPath      string             `toml:"metadata_path"`
	CertPath          string             `toml:"cert_path"`
	KeyPath           string             `toml:"key_path"`
	AllowIDPInitiated bool               `toml:"allow_idp_initiated"`
	Reauth            []SAMLReauthConfig `toml:"reauth"`

	// AuthnRequestMaxAge is how long a sent AuthnRequest stays valid for
	// InResponseTo validation, i.e. how long the user may spend on the IdP login
	// screen. Accepts a duration string such as "30m".
	AuthnRequestMaxAge time.Duration `toml:"authn_request_max_age"`

	// Computed fields (not from TOML)
	ParsedHost string // host:port extracted from base_url
	BasePath   string // path prefix extracted from base_url (empty for host-based routing)
	Order      int    // definition order in TOML file (computed)
}

// SAMLReauthConfig defines a SAML re-authentication profile.
type SAMLReauthConfig struct {
	Name                 string `toml:"name"`
	AuthnContextClassRef string `toml:"authn_context_class_ref"`
	ForceAuthn           bool   `toml:"force_authn"`
}

// Load reads the configuration from a TOML file.
func Load(path string) (*Config, error) {
	cfg := &Config{
		ListenAddr: ":3000",
		LogLevel:   "info",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	// Assign definition order based on TOML section header positions
	assignDefinitionOrder(data, cfg)

	// Apply defaults
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":3000"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.Theme == "" {
		cfg.Theme = "auto"
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "UTC"
	}

	// Validate TLS settings
	if cfg.TLSSelfSigned && (cfg.TLSCertPath != "" || cfg.TLSKeyPath != "") {
		return nil, fmt.Errorf("tls_self_signed and tls_cert_path/tls_key_path are mutually exclusive")
	}
	if (cfg.TLSCertPath != "") != (cfg.TLSKeyPath != "") {
		return nil, fmt.Errorf("both tls_cert_path and tls_key_path must be specified together")
	}

	for i := range cfg.OIDC {
		applyOIDCDefaults(&cfg.OIDC[i])
	}
	for i := range cfg.SAML {
		applySAMLDefaults(&cfg.SAML[i])
	}
	for i := range cfg.OAuth2 {
		applyOAuth2Defaults(&cfg.OAuth2[i])
	}

	// Validate OAuth2 entries
	for i, oa := range cfg.OAuth2 {
		if oa.Issuer == "" && (oa.AuthorizationURL == "" || oa.TokenURL == "") {
			return nil, fmt.Errorf("oauth2[%d] (%s): either issuer or both authorization_url and token_url are required", i, oa.Name)
		}
	}

	// Parse and validate base_url for all entries
	seen := make(map[string]string) // routeKey -> name for duplicate detection
	for i := range cfg.OIDC {
		if err := parseBaseURL(&cfg.OIDC[i].BaseURL, &cfg.OIDC[i].ParsedHost, &cfg.OIDC[i].BasePath); err != nil {
			return nil, fmt.Errorf("oidc[%d] (%s): %w", i, cfg.OIDC[i].Name, err)
		}
		routeKey := cfg.OIDC[i].ParsedHost + cfg.OIDC[i].BasePath
		if existing, ok := seen[routeKey]; ok {
			return nil, fmt.Errorf("duplicate base_url route %q: %s and %s", routeKey, existing, cfg.OIDC[i].Name)
		}
		seen[routeKey] = cfg.OIDC[i].Name
	}
	for i := range cfg.SAML {
		if err := parseBaseURL(&cfg.SAML[i].BaseURL, &cfg.SAML[i].ParsedHost, &cfg.SAML[i].BasePath); err != nil {
			return nil, fmt.Errorf("saml[%d] (%s): %w", i, cfg.SAML[i].Name, err)
		}
		routeKey := cfg.SAML[i].ParsedHost + cfg.SAML[i].BasePath
		if existing, ok := seen[routeKey]; ok {
			return nil, fmt.Errorf("duplicate base_url route %q: %s and %s", routeKey, existing, cfg.SAML[i].Name)
		}
		seen[routeKey] = cfg.SAML[i].Name
	}
	for i := range cfg.OAuth2 {
		if err := parseBaseURL(&cfg.OAuth2[i].BaseURL, &cfg.OAuth2[i].ParsedHost, &cfg.OAuth2[i].BasePath); err != nil {
			return nil, fmt.Errorf("oauth2[%d] (%s): %w", i, cfg.OAuth2[i].Name, err)
		}
		routeKey := cfg.OAuth2[i].ParsedHost + cfg.OAuth2[i].BasePath
		if existing, ok := seen[routeKey]; ok {
			return nil, fmt.Errorf("duplicate base_url route %q: %s and %s", routeKey, existing, cfg.OAuth2[i].Name)
		}
		seen[routeKey] = cfg.OAuth2[i].Name
	}

	return cfg, nil
}

// parseBaseURL validates and parses a base_url, setting the computed host and basePath fields.
func parseBaseURL(baseURL *string, parsedHost *string, basePath *string) error {
	if *baseURL == "" {
		return fmt.Errorf("base_url is required")
	}

	u, err := url.Parse(*baseURL)
	if err != nil {
		return fmt.Errorf("invalid base_url %q: %w", *baseURL, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("base_url %q: scheme must be http or https", *baseURL)
	}
	if u.Host == "" {
		return fmt.Errorf("base_url %q: host is required", *baseURL)
	}

	*parsedHost = u.Host

	// Normalize path: strip trailing slash
	p := strings.TrimRight(u.Path, "/")
	*basePath = p

	// Normalize base_url: remove trailing slash
	*baseURL = u.Scheme + "://" + u.Host + p

	return nil
}

func applyOIDCDefaults(c *OIDCConfig) {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
	if c.PKCEMethod == "" {
		c.PKCEMethod = "S256"
	}
	if c.ResponseType == "" {
		c.ResponseType = "code"
	}
	if c.CallbackPath == "" {
		c.CallbackPath = "/callback"
	}
	// A non-positive value would expire the state and PKCE verifier cookies
	// immediately, so treat it the same as unset.
	if c.AuthRequestMaxAge <= 0 {
		c.AuthRequestMaxAge = DefaultAuthRequestMaxAge
	}
}

// TLSEnabled returns true if TLS is configured (self-signed or cert files).
func (c *Config) TLSEnabled() bool {
	return c.TLSSelfSigned || (c.TLSCertPath != "" && c.TLSKeyPath != "")
}

func applyOAuth2Defaults(c *OAuth2Config) {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"profile", "email"}
	}
	if c.PKCEMethod == "" {
		c.PKCEMethod = "S256"
	}
	if c.CallbackPath == "" {
		c.CallbackPath = "/callback"
	}
	// A non-positive value would expire the state and PKCE verifier cookies
	// immediately, so treat it the same as unset.
	if c.AuthRequestMaxAge <= 0 {
		c.AuthRequestMaxAge = DefaultAuthRequestMaxAge
	}
}

// assignDefinitionOrder sets the Order field based on TOML section header positions.
func assignDefinitionOrder(data []byte, cfg *Config) {
	re := regexp.MustCompile(`(?m)^\s*\[\[(oidc|oauth2|saml)\]\]`)
	matches := re.FindAllSubmatchIndex(data, -1)

	counters := map[string]int{"oidc": 0, "oauth2": 0, "saml": 0}
	for order, match := range matches {
		protocol := string(data[match[2]:match[3]])
		idx := counters[protocol]
		counters[protocol]++
		switch protocol {
		case "oidc":
			if idx < len(cfg.OIDC) {
				cfg.OIDC[idx].Order = order
			}
		case "oauth2":
			if idx < len(cfg.OAuth2) {
				cfg.OAuth2[idx].Order = order
			}
		case "saml":
			if idx < len(cfg.SAML) {
				cfg.SAML[idx].Order = order
			}
		}
	}
}

// IsSecureBaseURL reports whether an externally visible base URL is served over
// TLS. Cookie Secure and SameSite flags derive from this rather than from the
// incoming request: base_url is the authoritative statement of how browsers
// reach fedlens, and deciding per-request would let a misconfigured base_url
// half-work — some cookies adapting to X-Forwarded-Proto while the ones handed
// to samlsp at startup cannot.
func IsSecureBaseURL(baseURL string) bool {
	return strings.HasPrefix(strings.ToLower(baseURL), "https://")
}

// DefaultAuthRequestMaxAge is the default lifetime of a pending OIDC/OAuth2
// authorization request. The cookies holding the state and the PKCE verifier
// must outlive the time the user spends on the IdP login screen.
const DefaultAuthRequestMaxAge = 30 * time.Minute

// DefaultAuthnRequestMaxAge is the default lifetime of a pending AuthnRequest.
// samlsp defaults to saml.MaxIssueDelay (90s), which expires while the user is
// still on the IdP login screen; 30 minutes is in the same range as a typical
// IdP login timeout.
const DefaultAuthnRequestMaxAge = 30 * time.Minute

func applySAMLDefaults(c *SAMLConfig) {
	if c.ACSPath == "" {
		c.ACSPath = "/saml/acs"
	}
	if c.SLOPath == "" {
		c.SLOPath = "/saml/slo"
	}
	if c.MetadataPath == "" {
		c.MetadataPath = "/saml/metadata"
	}
	// A non-positive value would make every AuthnRequest expire immediately, so
	// treat it the same as unset.
	if c.AuthnRequestMaxAge <= 0 {
		c.AuthnRequestMaxAge = DefaultAuthnRequestMaxAge
	}
}
