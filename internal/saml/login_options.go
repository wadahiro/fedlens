package saml

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/wadahiro/fedlens/internal/config"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

// nameIDFormatSuggestions are the identifier formats of SAML 2.0 Core §8.3 plus
// the SAML 1.1 ones that IdPs commonly still accept. They are suggestions only:
// the field stays free text so a vendor-specific or invalid URI can be tried.
func nameIDFormatSuggestions() []components.RequestOption {
	return []components.RequestOption{
		{Value: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", Label: "unspecified"},
		{Value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", Label: "emailAddress"},
		{Value: "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName", Label: "X509SubjectName"},
		{Value: "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", Label: "WindowsDomainQualifiedName"},
		{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos", Label: "kerberos"},
		{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Label: "entity"},
		{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", Label: "persistent"},
		{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", Label: "transient"},
	}
}

// Form field names. They match the TOML keys of [saml.auth_request] so the form
// and the config read the same way.
const (
	fieldNameIDFormat         = "name_id_format"
	fieldAllowCreate          = "allow_create"
	fieldSPNameQualifier      = "sp_name_qualifier"
	fieldOmitNameIDPolicy     = "omit_name_id_policy"
	fieldSubjectNameID        = "subject_name_id"
	fieldSubjectNameIDFormat  = "subject_name_id_format"
	fieldForceAuthn           = "force_authn"
	fieldIsPassive            = "is_passive"
	fieldAuthnContextClassRef = "authn_context_class_ref"
)

// loginOptions builds the options shown next to the Login button.
func (h *Handler) loginOptions() *components.RequestOptions {
	return h.authnRequestOptions("login", "Login", "", "/login")
}

// reauthOptions builds the options of the default Re-authenticate button. When
// reauth profiles are configured they are offered as a choice in the form, and
// the other fields override what the chosen profile sets.
func (h *Handler) reauthOptions() *components.RequestOptions {
	o := h.authnRequestOptions("reauth", "Re-authenticate", "outline", "/reauth")
	if len(h.Config.Reauth) > 0 {
		preset := h.reauthProfileField()
		o.Preset = &preset
	}
	return o
}

func (h *Handler) reauthProfileField() components.RequestField {
	opts := []components.RequestOption{{Value: "", Label: "(none)"}}
	for i, rc := range h.Config.Reauth {
		opts = append(opts, components.RequestOption{
			Value:  strconv.Itoa(i),
			Label:  describeReauthProfile(rc),
			Short:  rc.Name,
			Values: profileValues(rc),
		})
	}
	return components.RequestField{
		Name: "profile", Label: "Profile", Kind: "select", Options: opts,
		Help: "Applied first. Any parameter you fill in below overrides the profile's value for it.",
	}
}

// profileFieldOrder is the order a profile's settings are listed in, which is
// also the order of the form's fields.
var profileFieldOrder = []string{
	fieldNameIDFormat, fieldAllowCreate, fieldSPNameQualifier, fieldOmitNameIDPolicy,
	fieldSubjectNameID, fieldSubjectNameIDFormat, fieldForceAuthn, fieldIsPassive, fieldAuthnContextClassRef,
}

// profileValues returns what a profile sets, keyed by form field name, so the
// form can show those values as the placeholders of the fields it would override.
func profileValues(rc config.SAMLReauthConfig) map[string]string {
	values := map[string]string{}
	set := func(name, value string) {
		if value != "" {
			values[name] = value
		}
	}
	setBool := func(name string, value *bool) {
		if value != nil {
			values[name] = strconv.FormatBool(*value)
		}
	}
	set(fieldNameIDFormat, rc.NameIDFormat)
	setBool(fieldAllowCreate, rc.AllowCreate)
	set(fieldSPNameQualifier, rc.SPNameQualifier)
	setBool(fieldOmitNameIDPolicy, rc.OmitNameIDPolicy)
	set(fieldSubjectNameID, rc.SubjectNameID)
	set(fieldSubjectNameIDFormat, rc.SubjectNameIDFormat)
	setBool(fieldForceAuthn, rc.ForceAuthn)
	setBool(fieldIsPassive, rc.IsPassive)
	set(fieldAuthnContextClassRef, rc.AuthnContextClassRef)
	return values
}

// describeReauthProfile names a profile together with what it sets, so the choice
// can be made without looking the profile up in the config.
func describeReauthProfile(rc config.SAMLReauthConfig) string {
	values := profileValues(rc)
	var set []string
	for _, name := range profileFieldOrder {
		if v, ok := values[name]; ok {
			set = append(set, name+"="+v)
		}
	}
	if len(set) == 0 {
		return rc.Name
	}
	return rc.Name + " (" + strings.Join(set, ", ") + ")"
}

// authnRequestOptions builds the options of a button that sends an AuthnRequest.
// Login and Re-authenticate send the same one, so they share it.
func (h *Handler) authnRequestOptions(id, label, style, action string) *components.RequestOptions {
	def := h.Config.AuthRequest
	return &components.RequestOptions{
		ID:     id,
		Label:  label,
		Style:  style,
		Action: h.basePath + action,
		Fields: []components.RequestField{
			{
				Name: fieldNameIDFormat, Label: "NameIDPolicy Format", Kind: "text",
				Placeholder: configuredOr(shortNameIDFormat(def.NameIDFormat), "transient"),
				Options:     nameIDFormatSuggestions(),
			},
			{Name: fieldAllowCreate, Label: "NameIDPolicy AllowCreate", Kind: "select", Options: components.TriStateOptions(boolChoice(def.AllowCreate, "true"))},
			{Name: fieldSPNameQualifier, Label: "NameIDPolicy SPNameQualifier", Kind: "text", Placeholder: components.Fallback(def.SPNameQualifier)},
			{
				Name: fieldOmitNameIDPolicy, Label: "Omit NameIDPolicy", Kind: "select", Options: components.TriStateOptions(boolChoice(def.OmitNameIDPolicy, "false")),
				Help: "true sends no NameIDPolicy element, leaving the choice to the IdP.",
			},
			{
				Name: fieldSubjectNameID, Label: "Subject NameID", Kind: "text", Placeholder: components.Fallback(def.SubjectNameID),
				Help: "Hints which user is logging in, e.g. user@example.com",
			},
			{
				Name: fieldSubjectNameIDFormat, Label: "Subject NameID Format", Kind: "text",
				Placeholder: components.Fallback(shortNameIDFormat(def.SubjectNameIDFormat)),
				Options:     nameIDFormatSuggestions(),
			},
			{Name: fieldForceAuthn, Label: "ForceAuthn", Kind: "select", Options: components.TriStateOptions(boolChoice(def.ForceAuthn, ""))},
			{Name: fieldIsPassive, Label: "IsPassive", Kind: "select", Options: components.TriStateOptions(boolChoice(def.IsPassive, ""))},
			{
				Name: fieldAuthnContextClassRef, Label: "AuthnContextClassRef", Kind: "text",
				Placeholder: components.Fallback(def.AuthnContextClassRef),
				Help:        "e.g. urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
	}
}

// configuredOr is the placeholder of a field with a built-in fallback: the config
// file's value when there is one, else the value fedlens' SAML library sends.
func configuredOr(configured, libraryDefault string) string {
	if configured != "" {
		return components.Fallback(configured)
	}
	return components.Fallback(libraryDefault)
}

// boolChoice labels the empty choice of a tri-state select: the config file's
// value when it sets one, else the value sent when nothing sets it ("" = nothing).
func boolChoice(configured *bool, valueWhenUnset string) string {
	if configured != nil {
		return components.DefaultChoice(strconv.FormatBool(*configured))
	}
	return components.DefaultChoice(valueWhenUnset)
}

// parseLoginOptions reads the submitted form. Blank fields stay unset so that
// Overlay keeps the configured value for them.
func parseLoginOptions(q url.Values) config.SAMLAuthRequestConfig {
	text := func(name string) string { return strings.TrimSpace(q.Get(name)) }
	return config.SAMLAuthRequestConfig{
		NameIDFormat:         text(fieldNameIDFormat),
		AllowCreate:          triState(q.Get(fieldAllowCreate)),
		SPNameQualifier:      text(fieldSPNameQualifier),
		OmitNameIDPolicy:     triState(q.Get(fieldOmitNameIDPolicy)),
		SubjectNameID:        text(fieldSubjectNameID),
		SubjectNameIDFormat:  text(fieldSubjectNameIDFormat),
		ForceAuthn:           triState(q.Get(fieldForceAuthn)),
		IsPassive:            triState(q.Get(fieldIsPassive)),
		AuthnContextClassRef: text(fieldAuthnContextClassRef),
	}
}

// triState maps the select values "true" and "false" to a pointer; anything
// else, including the "(default)" choice, is unset.
func triState(value string) *bool {
	switch value {
	case "true":
		t := true
		return &t
	case "false":
		f := false
		return &f
	default:
		return nil
	}
}

// shortNameIDFormat names a standard NameID format by its short name
// ("emailAddress"), so that the marker after it in a placeholder stays in view;
// any other value is kept as it is.
func shortNameIDFormat(format string) string {
	for _, s := range nameIDFormatSuggestions() {
		if s.Value == format {
			return s.Label
		}
	}
	return format
}
