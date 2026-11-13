package saml

import (
	"net/url"
	"testing"

	samlpkg "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/wadahiro/fedlens/internal/config"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

func TestParseLoginOptionsAFormLeftAsTheConfigGaveItOverridesNothing(t *testing.T) {
	base := config.SAMLAuthRequestConfig{NameIDFormat: "urn:base", ForceAuthn: boolPtr(true)}
	// what the browser submits when nothing was touched: every field with its initial value
	q := url.Values{"name_id_format": {"urn:base"}, "force_authn": {"true"}, "allow_create": {""}, "is_passive": {""}, "authn_context_class_ref": {""}}

	override, cleared := parseLoginOptions(q, authRequestValues(base))

	if override != (config.SAMLAuthRequestConfig{}) || len(cleared) != 0 {
		t.Errorf("override %+v, cleared %v: an untouched form must not undo a reauth profile", override, cleared)
	}
}

func TestParseLoginOptionsChangedFieldsOverrideAndEmptiedOnesAreDropped(t *testing.T) {
	base := config.SAMLAuthRequestConfig{NameIDFormat: "urn:base", ForceAuthn: boolPtr(true), AllowCreate: boolPtr(true)}
	q := url.Values{
		"name_id_format":  {"  urn:oasis:names:tc:SAML:2.0:nameid-format:persistent "}, // changed
		"force_authn":     {""},                                                        // the config set it; emptied
		"allow_create":    {"false"},                                                   // changed to explicit false
		"subject_name_id": {" alice@example.com "},                                     // new
		"is_passive":      {"(default)"},                                               // an unknown value is not a setting
	}

	override, cleared := parseLoginOptions(q, authRequestValues(base))

	if override.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" || override.SubjectNameID != "alice@example.com" {
		t.Errorf("text overrides wrong (trimmed?): %+v", override)
	}
	if override.AllowCreate == nil || *override.AllowCreate {
		t.Errorf("AllowCreate = %v, want an explicit false", override.AllowCreate)
	}
	if override.IsPassive != nil {
		t.Errorf("IsPassive = %v, want unset", override.IsPassive)
	}
	if len(cleared) != 1 || cleared[0] != "force_authn" {
		t.Errorf("cleared = %v, want only force_authn", cleared)
	}
}

func TestParseLoginOptionsAPlainLinkWithoutTheFormOverridesNothing(t *testing.T) {
	base := config.SAMLAuthRequestConfig{ForceAuthn: boolPtr(true)}

	override, cleared := parseLoginOptions(url.Values{}, authRequestValues(base))

	if override != (config.SAMLAuthRequestConfig{}) || len(cleared) != 0 {
		t.Errorf("override %+v, cleared %v: with no form submitted the configured request goes out as it is", override, cleared)
	}
}

func TestRequestPlanForLayersConfigProfileAndForm(t *testing.T) {
	yes, no := true, false
	h := &Handler{}
	h.Config.AuthRequest = config.SAMLAuthRequestConfig{NameIDFormat: "urn:default", ForceAuthn: &no, AuthnContextClassRef: "urn:acr:config"}
	profile := config.SAMLReauthConfig{Name: "p"}
	profile.ForceAuthn = &yes
	profile.AuthnContextClassRef = "urn:acr:profile"
	q := url.Values{
		"name_id_format":          {"urn:default"},  // untouched
		"force_authn":             {"false"},        // untouched
		"authn_context_class_ref": {"urn:acr:form"}, // changed
	}

	got := h.requestPlanFor(&profile, q).opts

	if got.ForceAuthn == nil || !*got.ForceAuthn {
		t.Errorf("ForceAuthn = %v, want the profile's true: the field is untouched, so it must not undo the profile", got.ForceAuthn)
	}
	if got.AuthnContextClassRef != "urn:acr:form" {
		t.Errorf("AuthnContextClassRef = %q, want the form to win over the profile", got.AuthnContextClassRef)
	}
	if got.NameIDFormat != "urn:default" {
		t.Errorf("NameIDFormat = %q, want the config's kept", got.NameIDFormat)
	}
}

func TestRequestPlanForDropsASettingTheUserEmptied(t *testing.T) {
	h := &Handler{}
	h.Config.AuthRequest = config.SAMLAuthRequestConfig{ForceAuthn: boolPtr(true), SubjectNameID: "a@b.test"}

	plan := h.requestPlanFor(nil, url.Values{"force_authn": {""}, "subject_name_id": {"a@b.test"}})
	got := plan.opts

	if got.ForceAuthn != nil {
		t.Errorf("ForceAuthn = %v, want it dropped: the user emptied a field the config had set", got.ForceAuthn)
	}
	if got.SubjectNameID != "a@b.test" {
		t.Errorf("SubjectNameID = %q, want the untouched setting kept", got.SubjectNameID)
	}
	if len(plan.omit) != 1 || plan.omit[0] != "force_authn" {
		t.Errorf("omit = %v, want the emptied setting listed so it is kept out of the request", plan.omit)
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

func TestSAMLFieldsStartWithTheConfigsValues(t *testing.T) {
	h := &Handler{basePath: "/saml-sp"}
	h.Config.AuthRequest.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	h.Config.AuthRequest.ForceAuthn = boolPtr(true)
	o := h.loginOptions()

	if got := samlField(t, o, "name_id_format").Value; got != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" {
		t.Errorf("name_id_format starts with %q", got)
	}
	if got := samlField(t, o, "force_authn").Value; got != "true" {
		t.Errorf("force_authn starts on %q", got)
	}
	// a setting that neither the config nor the library sets starts empty
	for _, name := range []string{"is_passive", "sp_name_qualifier", "subject_name_id", "authn_context_class_ref"} {
		if got := samlField(t, o, name).Value; got != "" {
			t.Errorf("%s starts with %q, want empty", name, got)
		}
	}
}

func TestSAMLBlankChoicesSendNothing(t *testing.T) {
	o := (&Handler{basePath: "/saml-sp"}).loginOptions()

	for _, name := range []string{"allow_create", "is_passive", "force_authn"} {
		if got := samlField(t, o, name).Options[0].Label; got != "(not sent)" {
			t.Errorf("%s first choice = %q: blank must mean not sent, since the library's default is a real value", name, got)
		}
	}
	if got := samlField(t, o, "allow_create").Value; got != "true" {
		t.Errorf("allow_create starts on %q, want the library's true", got)
	}
}

func TestRequestPlanForACSURLFormOverridesConfigAndEmptyingDropsIt(t *testing.T) {
	h := &Handler{}
	h.Config.AuthRequest = config.SAMLAuthRequestConfig{AssertionConsumerServiceURL: "https://config.example/acs"}

	untouched := h.requestPlanFor(nil, url.Values{"assertion_consumer_service_url": {"https://config.example/acs"}})
	if untouched.opts.AssertionConsumerServiceURL != "https://config.example/acs" || len(untouched.omit) != 0 {
		t.Errorf("untouched = %+v", untouched)
	}
	changed := h.requestPlanFor(nil, url.Values{"assertion_consumer_service_url": {"https://form.example/acs"}})
	if changed.opts.AssertionConsumerServiceURL != "https://form.example/acs" {
		t.Errorf("changed = %+v", changed)
	}
	emptied := h.requestPlanFor(nil, url.Values{"assertion_consumer_service_url": {""}})
	if emptied.opts.AssertionConsumerServiceURL != "" || len(emptied.omit) != 1 || emptied.omit[0] != "assertion_consumer_service_url" {
		t.Errorf("emptied = %+v", emptied)
	}
}

func TestACSURLFieldStartsWithTheSPsURLUnlessConfigured(t *testing.T) {
	h := &Handler{sp: testMiddleware("http://localhost:3000/saml/acs")}
	field := func() components.RequestField {
		for _, f := range h.authnRequestOptions("login", "Login", "", "/login").Fields {
			if f.Name == "assertion_consumer_service_url" {
				return f
			}
		}
		t.Fatal("no assertion_consumer_service_url field")
		return components.RequestField{}
	}
	if f := field(); f.Value != "http://localhost:3000/saml/acs" {
		t.Errorf("Value = %q, want the SP's own ACS URL", f.Value)
	}
	h.Config.AuthRequest.AssertionConsumerServiceURL = "https://config.example/acs"
	if f := field(); f.Value != "https://config.example/acs" {
		t.Errorf("Value = %q, want the configured URL", f.Value)
	}
}

func TestFormStartCarriesTheLibraryDefaultsAsRealValues(t *testing.T) {
	h := &Handler{}
	start := h.formStart()
	if start["name_id_format"] != "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" || start["allow_create"] != "true" {
		t.Errorf("start = %v, want the library's Format and AllowCreate", start)
	}

	h.Config.AuthRequest = config.SAMLAuthRequestConfig{NameIDFormat: "urn:cfg", AllowCreate: boolPtr(false)}
	start = h.formStart()
	if start["name_id_format"] != "urn:cfg" || start["allow_create"] != "false" {
		t.Errorf("start = %v, want the config's values to win over the library's", start)
	}
}

func TestEmptyingALibraryDefaultTakesItOutOfTheRequest(t *testing.T) {
	h := &Handler{}
	// An untouched form submits the starting values: nothing is overridden.
	q := url.Values{"name_id_format": {"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}, "allow_create": {"true"}}
	if plan := h.requestPlanFor(nil, q); len(plan.omit) != 0 {
		t.Errorf("untouched form omits %v", plan.omit)
	}
	// Emptied with no config at all: the library default must not come back.
	plan := h.requestPlanFor(nil, url.Values{"name_id_format": {""}, "allow_create": {""}})
	if len(plan.omit) != 2 {
		t.Fatalf("omit = %v, want both emptied settings", plan.omit)
	}
	req := newRequest()
	applyAuthRequest(req, plan.opts)
	omitSettings(req, plan.omit)
	if req.NameIDPolicy.Format != nil || req.NameIDPolicy.AllowCreate != nil {
		t.Errorf("NameIDPolicy = %+v, want Format and AllowCreate removed", req.NameIDPolicy)
	}
}

func TestLoginFormShowsLibraryDefaultsAsValuesNotPlaceholders(t *testing.T) {
	h := &Handler{}
	for _, f := range h.authnRequestOptions("login", "Login", "", "/login").Fields {
		if f.Placeholder != "" {
			t.Errorf("%s has the faint placeholder %q: what is sent must be a real value", f.Name, f.Placeholder)
		}
		if f.Name == "name_id_format" && f.Value == "" {
			t.Error("name_id_format must start with the library's Format")
		}
	}
}

// testMiddleware is the minimum of an SP the form reads: its ACS URL.
func testMiddleware(acs string) *samlsp.Middleware {
	u, _ := url.Parse(acs)
	return &samlsp.Middleware{ServiceProvider: samlpkg.ServiceProvider{AcsURL: *u}}
}
