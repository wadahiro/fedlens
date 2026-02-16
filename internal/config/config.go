package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration.
type Config struct {
	ListenAddr         string       `toml:"listen_addr"`
	InsecureSkipVerify bool         `toml:"insecure_skip_verify"`
	LogLevel           string       `toml:"log_level"`
	Theme              string       `toml:"theme"`
	Timezone           string       `toml:"timezone"`
	TLSCertPath        string       `toml:"tls_cert_path"`
	TLSKeyPath         string       `toml:"tls_key_path"`
	TLSSelfSigned      bool         `toml:"tls_self_signed"`
	OIDC               []OIDCConfig `toml:"oidc"`
	SAML               []SAMLConfig `toml:"saml"`
}

// OIDCConfig defines a single OIDC RP instance.
type OIDCConfig struct {
	Name            string            `toml:"name"`
	Host            string            `toml:"host"`
	Issuer          string            `toml:"issuer"`
	ClientID        string            `toml:"client_id"`
	ClientSecret    string            `toml:"client_secret"`
	RedirectURI     string            `toml:"redirect_uri"`
	CallbackPath    string            `toml:"callback_path"`
	Scopes          []string          `toml:"scopes"`
	PKCE            bool              `toml:"pkce"`
	PKCEMethod      string            `toml:"pkce_method"`
	ResponseType    string            `toml:"response_type"`
	ResponseMode    string            `toml:"response_mode"`
	ExtraAuthParams map[string]string `toml:"extra_auth_params"`
	Reauth            []ReauthConfig    `toml:"reauth"`
	LogoutIDTokenHint *bool             `toml:"logout_id_token_hint"` // default: true
}

// ReauthConfig defines a re-authentication profile with extra auth params.
type ReauthConfig struct {
	Name            string            `toml:"name"`
	ExtraAuthParams map[string]string `toml:"extra_auth_params"`
}

// SAMLConfig defines a single SAML SP instance.
type SAMLConfig struct {
	Name              string             `toml:"name"`
	Host              string             `toml:"host"`
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
}

// SAMLReauthConfig defines a SAML re-authentication profile.
type SAMLReauthConfig struct {
	Name                  string `toml:"name"`
	AuthnContextClassRef  string `toml:"authn_context_class_ref"`
	ForceAuthn            bool   `toml:"force_authn"`
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

	return cfg, nil
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
}

// TLSEnabled returns true if TLS is configured (self-signed or cert files).
func (c *Config) TLSEnabled() bool {
	return c.TLSSelfSigned || (c.TLSCertPath != "" && c.TLSKeyPath != "")
}


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
}
