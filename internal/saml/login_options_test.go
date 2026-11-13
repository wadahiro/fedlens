package saml

import (
	"net/url"
	"testing"

	"github.com/wadahiro/fedlens/internal/config"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

func TestParseLoginOptionsBlankFormChangesNothing(t *testing.T) {
	got := parseLoginOptions(url.Values{"name_id_format": {""}, "allow_create": {""}, "force_authn": {""}})

	if got.NameIDFormat != "" || got.AllowCreate != nil || got.ForceAuthn != nil || got.IsPassive != nil || got.OmitNameIDPolicy != nil {
		t.Errorf("blank form must leave every option unset: %+v", got)
	}
}

func TestParseLoginOptionsTriState(t *testing.T) {
	got := parseLoginOptions(url.Values{
		"allow_create": {"false"},
		"force_authn":  {"true"},
		"is_passive":   {"(default)"},
	})

	if got.AllowCreate == nil || *got.AllowCreate {
		t.Errorf("AllowCreate = %v, want explicit false", got.AllowCreate)
	}
	if got.ForceAuthn == nil || !*got.ForceAuthn {
		t.Errorf("ForceAuthn = %v, want true", got.ForceAuthn)
	}
	if got.IsPassive != nil {
		t.Errorf("IsPassive = %v, want unset for an unknown value", got.IsPassive)
	}
}

func TestParseLoginOptionsTextFieldsAreTrimmed(t *testing.T) {
	got := parseLoginOptions(url.Values{
		"name_id_format":    {"  urn:oasis:names:tc:SAML:2.0:nameid-format:persistent "},
		"subject_name_id":   {" alice@example.com "},
		"sp_name_qualifier": {"https://sp.example.com"},
	})

	if got.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		t.Errorf("NameIDFormat = %q", got.NameIDFormat)
	}
	if got.SubjectNameID != "alice@example.com" || got.SPNameQualifier != "https://sp.example.com" {
		t.Errorf("text fields wrong: %+v", got)
	}
}

func TestFormOverridesConfiguredDefaultsPerField(t *testing.T) {
	yes := true
	h := &Handler{}
	h.Config.AuthRequest.ForceAuthn = &yes
	h.Config.AuthRequest.NameIDFormat = "urn:configured"

	got := h.Config.AuthRequest.Overlay(parseLoginOptions(url.Values{"force_authn": {"false"}}))

	if got.ForceAuthn == nil || *got.ForceAuthn {
		t.Errorf("ForceAuthn = %v, want the form's explicit false", got.ForceAuthn)
	}
	if got.NameIDFormat != "urn:configured" {
		t.Errorf("NameIDFormat = %q, want the configured value kept", got.NameIDFormat)
	}
}

func TestDescribeReauthProfileListsWhatItSets(t *testing.T) {
	yes := true
	rc := config.SAMLReauthConfig{Name: "Step-up"}
	rc.ForceAuthn = &yes
	rc.AuthnContextClassRef = "urn:acr:mfa"

	if got, want := describeReauthProfile(rc), "Step-up (force_authn=true, authn_context_class_ref=urn:acr:mfa)"; got != want {
		t.Errorf("describeReauthProfile = %q, want %q", got, want)
	}
	if got := describeReauthProfile(config.SAMLReauthConfig{Name: "Plain"}); got != "Plain" {
		t.Errorf("got %q, want the bare name", got)
	}
}

func TestSAMLReauthProfileThenFormOverlay(t *testing.T) {
	yes, no := true, false
	h := &Handler{}
	h.Config.AuthRequest.ForceAuthn = &no
	h.Config.AuthRequest.NameIDFormat = "urn:default"
	rc := config.SAMLReauthConfig{Name: "p"}
	rc.ForceAuthn = &yes
	rc.AuthnContextClassRef = "urn:acr:profile"

	got := h.Config.AuthRequest.Overlay(rc.SAMLAuthRequestConfig).Overlay(parseLoginOptions(url.Values{"authn_context_class_ref": {"urn:acr:form"}}))

	if got.ForceAuthn == nil || !*got.ForceAuthn {
		t.Errorf("ForceAuthn = %v, want the profile's true over the default false", got.ForceAuthn)
	}
	if got.AuthnContextClassRef != "urn:acr:form" {
		t.Errorf("AuthnContextClassRef = %q, want the form to win over the profile", got.AuthnContextClassRef)
	}
	if got.NameIDFormat != "urn:default" {
		t.Errorf("NameIDFormat = %q, want the default kept", got.NameIDFormat)
	}
}

func TestSAMLReauthOptionsOfferProfilesOnlyWhenConfigured(t *testing.T) {
	h := &Handler{basePath: "/saml-sp"}
	if h.reauthOptions().Preset != nil {
		t.Fatal("no preset expected without configured profiles")
	}

	yes := true
	rc := config.SAMLReauthConfig{Name: "p"}
	rc.ForceAuthn = &yes
	rc.AuthnContextClassRef = "urn:acr:mfa"
	h.Config.Reauth = []config.SAMLReauthConfig{rc}

	got := h.reauthOptions()
	if got.Preset == nil {
		t.Fatal("the profile choice should be offered, apart from the fields")
	}
	values := got.Preset.Options[1].Values
	if values["force_authn"] != "true" || values["authn_context_class_ref"] != "urn:acr:mfa" || len(values) != 2 {
		t.Errorf("profile values = %v, want only what the profile sets, keyed by form field name", values)
	}
}

func samlField(t *testing.T, o *components.RequestOptions, name string) components.RequestField {
	t.Helper()
	for _, f := range o.Fields {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no field %q", name)
	return components.RequestField{}
}

func TestSAMLBlankFieldsShowWhatIsSent(t *testing.T) {
	yes := true
	h := &Handler{basePath: "/saml-sp"}
	h.Config.AuthRequest.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	h.Config.AuthRequest.ForceAuthn = &yes
	o := h.loginOptions()

	if got := samlField(t, o, "name_id_format").Placeholder; got != "emailAddress" {
		t.Errorf("name_id_format placeholder = %q", got)
	}
	if got := samlField(t, o, "force_authn").Options[0].Label; got != "(true)" {
		t.Errorf("force_authn first choice = %q", got)
	}
	// nothing configured: what the library sends, or nothing at all
	if got := samlField(t, o, "allow_create").Options[0].Label; got != "(true)" {
		t.Errorf("allow_create first choice = %q, want the library's own default named as such", got)
	}
	if got := samlField(t, o, "is_passive").Options[0].Label; got != "(not sent)" {
		t.Errorf("is_passive first choice = %q", got)
	}
	if got := samlField(t, o, "authn_context_class_ref").Placeholder; got != "" {
		t.Errorf("authn_context_class_ref placeholder = %q: an example must not look like a sent value", got)
	}
}

func TestSAMLNameIDFormatFallsBackToTheLibraryDefault(t *testing.T) {
	h := &Handler{basePath: "/saml-sp"}
	if got := samlField(t, h.loginOptions(), "name_id_format").Placeholder; got != "transient" {
		t.Errorf("name_id_format placeholder = %q", got)
	}
}

func TestShortNameIDFormat(t *testing.T) {
	if got := shortNameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"); got != "persistent" {
		t.Errorf("got %q, want the short name of a standard format", got)
	}
	if got := shortNameIDFormat("urn:vendor:custom"); got != "urn:vendor:custom" {
		t.Errorf("got %q, want an unknown format kept as it is", got)
	}
}
