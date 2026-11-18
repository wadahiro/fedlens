package saml

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	samlpkg "github.com/crewjam/saml"

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
	fieldACSURL               = "assertion_consumer_service_url"
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
	fieldACSURL,
}

// authRequestValues returns the settings of an auth_request config, keyed by form
// field name: what a profile sets, and what the config file starts the form with.
// A setting that is not set is absent.
func authRequestValues(c config.SAMLAuthRequestConfig) map[string]string {
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
	set(fieldNameIDFormat, c.NameIDFormat)
	setBool(fieldAllowCreate, c.AllowCreate)
	set(fieldSPNameQualifier, c.SPNameQualifier)
	setBool(fieldOmitNameIDPolicy, c.OmitNameIDPolicy)
	set(fieldSubjectNameID, c.SubjectNameID)
	set(fieldSubjectNameIDFormat, c.SubjectNameIDFormat)
	setBool(fieldForceAuthn, c.ForceAuthn)
	setBool(fieldIsPassive, c.IsPassive)
	set(fieldAuthnContextClassRef, c.AuthnContextClassRef)
	set(fieldACSURL, c.AssertionConsumerServiceURL)
	return values
}

// profileValues returns what a profile sets, keyed by form field name, so the
// form can show those values as the placeholders of the fields it would override.
func profileValues(rc config.SAMLReauthConfig) map[string]string {
	return authRequestValues(rc.SAMLAuthRequestConfig)
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
	start := h.formStart()
	return &components.RequestOptions{
		ID:     id,
		Label:  label,
		Style:  style,
		Action: h.basePath + action,
		Fields: []components.RequestField{
			{
				Name: fieldNameIDFormat, Label: "NameIDPolicy Format", Kind: "text",
				Value:   start[fieldNameIDFormat],
				Options: nameIDFormatSuggestions(),
				Help:    "Empty leaves the Format out of the NameIDPolicy.",
			},
			{Name: fieldAllowCreate, Label: "NameIDPolicy AllowCreate", Kind: "select", Value: start[fieldAllowCreate], Options: components.TriStateOptions(components.DefaultChoice(""))},
			{Name: fieldSPNameQualifier, Label: "NameIDPolicy SPNameQualifier", Kind: "text", Value: start[fieldSPNameQualifier]},
			{
				Name: fieldOmitNameIDPolicy, Label: "Omit NameIDPolicy", Kind: "select", Value: start[fieldOmitNameIDPolicy], Options: components.TriStateOptions(components.DefaultChoice("false")),
				Help: "true sends no NameIDPolicy element, leaving the choice to the IdP.",
			},
			{
				Name: fieldSubjectNameID, Label: "Subject NameID", Kind: "text", Value: start[fieldSubjectNameID],
				Help: "Hints which user is logging in, e.g. user@example.com",
			},
			{
				Name: fieldSubjectNameIDFormat, Label: "Subject NameID Format", Kind: "text", Value: start[fieldSubjectNameIDFormat],
				Options: nameIDFormatSuggestions(),
			},
			{Name: fieldForceAuthn, Label: "ForceAuthn", Kind: "select", Value: start[fieldForceAuthn], Options: components.TriStateOptions(components.DefaultChoice(""))},
			{Name: fieldIsPassive, Label: "IsPassive", Kind: "select", Value: start[fieldIsPassive], Options: components.TriStateOptions(components.DefaultChoice(""))},
			{
				Name: fieldAuthnContextClassRef, Label: "AuthnContextClassRef", Kind: "text", Value: start[fieldAuthnContextClassRef],
				Help: "e.g. urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
			{
				Name: fieldACSURL, Label: "AssertionConsumerServiceURL", Kind: "text",
				Value: start[fieldACSURL],
				Help:  "Where the request asks the IdP to post the response. A URL other than the SP's tests how the IdP checks it against the metadata. Empty leaves it out.",
			},
		},
	}
}

// formStart is what the form's fields start with: the config's values, and for
// the three settings the SAML library fills in when they are unset (the NameIDPolicy's
// Format and AllowCreate, and the AssertionConsumerServiceURL) the value it would
// send. They are real values rather than faint hints so that the form shows the
// request as it will be sent, and emptying one takes it out of the request.
func (h *Handler) formStart() map[string]string {
	start := authRequestValues(h.Config.AuthRequest)
	fill := func(name, value string) {
		if _, set := start[name]; !set && value != "" {
			start[name] = value
		}
	}
	if o := h.Config.AuthRequest.OmitNameIDFormat; o == nil || !*o {
		fill(fieldNameIDFormat, string(samlpkg.TransientNameIDFormat))
	}
	fill(fieldAllowCreate, "true")
	fill(fieldACSURL, h.acsURL())
	return start
}

// parseLoginOptions reads the submitted form against what it started with
// (formStart). A field still holding its starting value overrides nothing, which keeps the
// layering (config, then profile, then form): a profile is not undone by a field the
// user never touched. A changed field becomes an override; a field the config had
// filled and the user emptied is returned by name, meaning the setting is dropped.
func parseLoginOptions(q url.Values, start map[string]string) (config.SAMLAuthRequestConfig, []string) {
	var override config.SAMLAuthRequestConfig
	var cleared []string
	for _, name := range profileFieldOrder {
		if !q.Has(name) { // the form was not submitted (a plain link): nothing to override
			continue
		}
		v := strings.TrimSpace(q.Get(name))
		if v == start[name] {
			continue
		}
		if v == "" {
			cleared = append(cleared, name)
			continue
		}
		switch name {
		case fieldNameIDFormat:
			override.NameIDFormat = v
		case fieldAllowCreate:
			override.AllowCreate = triState(v)
		case fieldSPNameQualifier:
			override.SPNameQualifier = v
		case fieldOmitNameIDPolicy:
			override.OmitNameIDPolicy = triState(v)
		case fieldSubjectNameID:
			override.SubjectNameID = v
		case fieldSubjectNameIDFormat:
			override.SubjectNameIDFormat = v
		case fieldForceAuthn:
			override.ForceAuthn = triState(v)
		case fieldIsPassive:
			override.IsPassive = triState(v)
		case fieldAuthnContextClassRef:
			override.AuthnContextClassRef = v
		case fieldACSURL:
			override.AssertionConsumerServiceURL = v
		}
	}
	return override, cleared
}

// authnRequestPlan is what one AuthnRequest is built from: the settings to apply
// and the settings the user emptied, which must not appear in the request at all
// (not even as the SAML library's own default).
type authnRequestPlan struct {
	opts config.SAMLAuthRequestConfig
	omit []string
}

// dropSettings unsets the named settings.
func dropSettings(c config.SAMLAuthRequestConfig, names []string) config.SAMLAuthRequestConfig {
	for _, name := range names {
		switch name {
		case fieldNameIDFormat:
			c.NameIDFormat = ""
		case fieldAllowCreate:
			c.AllowCreate = nil
		case fieldSPNameQualifier:
			c.SPNameQualifier = ""
		case fieldOmitNameIDPolicy:
			c.OmitNameIDPolicy = nil
		case fieldSubjectNameID:
			c.SubjectNameID = ""
		case fieldSubjectNameIDFormat:
			c.SubjectNameIDFormat = ""
		case fieldForceAuthn:
			c.ForceAuthn = nil
		case fieldIsPassive:
			c.IsPassive = nil
		case fieldAuthnContextClassRef:
			c.AuthnContextClassRef = ""
		case fieldACSURL:
			c.AssertionConsumerServiceURL = ""
		}
	}
	return c
}

// requestPlanFor resolves one AuthnRequest: the config's settings, then a reauth
// profile's if one was chosen, then what the form overrides or removes.
func (h *Handler) requestPlanFor(profile *config.SAMLReauthConfig, q url.Values) authnRequestPlan {
	effective := h.Config.AuthRequest
	if profile != nil {
		effective = effective.Overlay(profile.SAMLAuthRequestConfig)
	}
	override, cleared := parseLoginOptions(q, h.formStart())
	effective = effective.Overlay(override)
	omit := cleared
	// The library adds a Format when none is set, so leaving it out has to be explicit.
	if o := effective.OmitNameIDFormat; o != nil && *o && effective.NameIDFormat == "" && !slices.Contains(omit, fieldNameIDFormat) {
		omit = append(slices.Clone(omit), fieldNameIDFormat)
	}
	return authnRequestPlan{opts: dropSettings(effective, cleared), omit: omit}
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

// acsURL is the AssertionConsumerServiceURL the library puts in a request.
func (h *Handler) acsURL() string {
	if h.sp == nil {
		return ""
	}
	return h.sp.ServiceProvider.AcsURL.String()
}
