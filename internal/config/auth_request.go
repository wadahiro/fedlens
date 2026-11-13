package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
)

// OIDCAuthRequestConfig groups the settings that shape an OIDC authentication
// request. Fields are pointers so that "not set" stays distinguishable from a
// zero value, which the conflict check against the legacy flat keys relies on.
//
// max_age is deliberately not a typed field: it belongs in extra_auth_params,
// otherwise it reads as a sibling of the top-level auth_request_max_age, which
// is an unrelated cookie lifetime.
type OIDCAuthRequestConfig struct {
	Scopes          *[]string          `toml:"scopes"`
	PKCE            *bool              `toml:"pkce"`
	PKCEMethod      *string            `toml:"pkce_method"`
	ResponseType    *string            `toml:"response_type"`
	ResponseMode    *string            `toml:"response_mode"`
	ExtraAuthParams *map[string]string `toml:"extra_auth_params"`
}

// OAuth2AuthRequestConfig is the OAuth2 counterpart. It has no response_type:
// the authorization code flow is the only one the OAuth2 client speaks, and
// leaving the key out lets an accidental response_type be reported as unknown.
type OAuth2AuthRequestConfig struct {
	Scopes          *[]string          `toml:"scopes"`
	PKCE            *bool              `toml:"pkce"`
	PKCEMethod      *string            `toml:"pkce_method"`
	ResponseMode    *string            `toml:"response_mode"`
	ExtraAuthParams *map[string]string `toml:"extra_auth_params"`
}

// SAMLAuthRequestConfig groups the settings that shape a SAML AuthnRequest.
// The same keys are accepted in a [[saml.reauth]] profile, where they override
// the top-level [saml.auth_request] values. Booleans are tri-state so a profile
// can turn off something the default turned on, and so an attribute can be
// omitted from the request entirely rather than sent as false.
//
// Unset NameIDPolicy values keep the library default (Format transient,
// AllowCreate true) so existing setups send the same request as before.
// OmitNameIDPolicy drops the whole element, which is how to see what an IdP does
// when the SP states no preference.
type SAMLAuthRequestConfig struct {
	NameIDFormat         string `toml:"name_id_format"`
	AllowCreate          *bool  `toml:"allow_create"`
	SPNameQualifier      string `toml:"sp_name_qualifier"`
	OmitNameIDPolicy     *bool  `toml:"omit_name_id_policy"`
	ForceAuthn           *bool  `toml:"force_authn"`
	IsPassive            *bool  `toml:"is_passive"`
	AuthnContextClassRef string `toml:"authn_context_class_ref"`

	// SubjectNameID adds a Subject/NameID to the request as a hint about who is
	// logging in (the SAML counterpart of OIDC login_hint).
	SubjectNameID       string `toml:"subject_name_id"`
	SubjectNameIDFormat string `toml:"subject_name_id_format"`
}

// Overlay returns a copy of c in which every value set in o replaces the one in c.
func (c SAMLAuthRequestConfig) Overlay(o SAMLAuthRequestConfig) SAMLAuthRequestConfig {
	if o.NameIDFormat != "" {
		c.NameIDFormat = o.NameIDFormat
	}
	if o.AllowCreate != nil {
		c.AllowCreate = o.AllowCreate
	}
	if o.SPNameQualifier != "" {
		c.SPNameQualifier = o.SPNameQualifier
	}
	if o.OmitNameIDPolicy != nil {
		c.OmitNameIDPolicy = o.OmitNameIDPolicy
	}
	if o.SubjectNameID != "" {
		c.SubjectNameID = o.SubjectNameID
	}
	if o.SubjectNameIDFormat != "" {
		c.SubjectNameIDFormat = o.SubjectNameIDFormat
	}
	if o.ForceAuthn != nil {
		c.ForceAuthn = o.ForceAuthn
	}
	if o.IsPassive != nil {
		c.IsPassive = o.IsPassive
	}
	if o.AuthnContextClassRef != "" {
		c.AuthnContextClassRef = o.AuthnContextClassRef
	}
	return c
}

// legacyAuthRequestProbe re-reads the flat keys that predate [x.auth_request].
// The effective fields on OIDCConfig/OAuth2Config cannot say whether a key was
// present, and MetaData.IsDefined cannot say which [[oidc]] element defined it.
type legacyAuthRequestProbe struct {
	OIDC   []legacyAuthRequestKeys `toml:"oidc"`
	OAuth2 []legacyAuthRequestKeys `toml:"oauth2"`
}

type legacyAuthRequestKeys struct {
	Scopes          *[]string          `toml:"scopes"`
	PKCE            *bool              `toml:"pkce"`
	PKCEMethod      *string            `toml:"pkce_method"`
	ResponseType    *string            `toml:"response_type"`
	ResponseMode    *string            `toml:"response_mode"`
	ExtraAuthParams *map[string]string `toml:"extra_auth_params"`
}

// resolveAuthRequests folds the [x.auth_request] tables and the legacy flat keys
// into the effective fields the handlers read. It must run before the defaults
// are applied, otherwise a default would be indistinguishable from a user value.
func resolveAuthRequests(data []byte, cfg *Config) error {
	var probe legacyAuthRequestProbe
	if _, err := toml.Decode(string(data), &probe); err != nil {
		return fmt.Errorf("parse legacy auth request keys: %w", err)
	}

	for i := range cfg.OIDC {
		c := &cfg.OIDC[i]
		where := fmt.Sprintf("oidc[%d] (%s)", i, c.Name)
		var legacy legacyAuthRequestKeys
		if i < len(probe.OIDC) {
			legacy = probe.OIDC[i]
		}
		m := merger{where: where, warnings: &cfg.Warnings}
		ar := c.AuthRequest
		scopes := mergeKey(&m, "scopes", legacy.Scopes, ar.Scopes)
		pkce := mergeKey(&m, "pkce", legacy.PKCE, ar.PKCE)
		pkceMethod := mergeKey(&m, "pkce_method", legacy.PKCEMethod, ar.PKCEMethod)
		responseType := mergeKey(&m, "response_type", legacy.ResponseType, ar.ResponseType)
		responseMode := mergeKey(&m, "response_mode", legacy.ResponseMode, ar.ResponseMode)
		extra := mergeKey(&m, "extra_auth_params", legacy.ExtraAuthParams, ar.ExtraAuthParams)
		if m.err != nil {
			return m.err
		}
		assign(&c.Scopes, scopes)
		assign(&c.PKCE, pkce)
		assign(&c.PKCEMethod, pkceMethod)
		assign(&c.ResponseType, responseType)
		assign(&c.ResponseMode, responseMode)
		assign(&c.ExtraAuthParams, extra)
	}

	for i := range cfg.OAuth2 {
		c := &cfg.OAuth2[i]
		where := fmt.Sprintf("oauth2[%d] (%s)", i, c.Name)
		var legacy legacyAuthRequestKeys
		if i < len(probe.OAuth2) {
			legacy = probe.OAuth2[i]
		}
		m := merger{where: where, warnings: &cfg.Warnings}
		ar := c.AuthRequest
		scopes := mergeKey(&m, "scopes", legacy.Scopes, ar.Scopes)
		pkce := mergeKey(&m, "pkce", legacy.PKCE, ar.PKCE)
		pkceMethod := mergeKey(&m, "pkce_method", legacy.PKCEMethod, ar.PKCEMethod)
		responseMode := mergeKey(&m, "response_mode", legacy.ResponseMode, ar.ResponseMode)
		extra := mergeKey(&m, "extra_auth_params", legacy.ExtraAuthParams, ar.ExtraAuthParams)
		if m.err != nil {
			return m.err
		}
		assign(&c.Scopes, scopes)
		assign(&c.PKCE, pkce)
		assign(&c.PKCEMethod, pkceMethod)
		assign(&c.ResponseMode, responseMode)
		assign(&c.ExtraAuthParams, extra)
	}
	return nil
}

// merger carries the entry being resolved so mergeKey can phrase its messages
// and remember the first error without every call site checking it.
type merger struct {
	where    string
	warnings *[]string
	err      error
}

// mergeKey picks the value for one key. The new-format value wins; the legacy
// one is used when it is the only one present. Two different values are an
// error: silently preferring either would change what the user's request sends.
func mergeKey[T any](m *merger, key string, legacy, modern *T) *T {
	switch {
	case legacy != nil && modern != nil:
		if !reflect.DeepEqual(*legacy, *modern) && m.err == nil {
			m.err = fmt.Errorf("%s: %q is set both directly and in auth_request with different values; remove the direct key", m.where, key)
		}
		m.warnDeprecated(key)
		return modern
	case legacy != nil:
		m.warnDeprecated(key)
		return legacy
	default:
		return modern
	}
}

func (m *merger) warnDeprecated(key string) {
	*m.warnings = append(*m.warnings, fmt.Sprintf("%s: %q is deprecated as a direct key; move it under auth_request", m.where, key))
}

// assign overwrites dst only when the key was present in the config.
func assign[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

// undecodedWarnings reports keys that no struct field consumed. A key written
// below an [x.auth_request] header belongs to that table, so a connection
// setting placed there would otherwise be dropped without a trace.
func undecodedWarnings(md toml.MetaData) []string {
	var out []string
	for _, key := range md.Undecoded() {
		msg := fmt.Sprintf("unknown config key %q is ignored", key.String())
		if strings.Contains(key.String(), "auth_request.") {
			msg += "; keys below an auth_request header belong to that table, so move connection settings above it"
		}
		out = append(out, msg)
	}
	return out
}
