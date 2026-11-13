package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/wadahiro/fedlens/internal/config"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

func TestParseLoginParamsKeepsOnlyFilledFields(t *testing.T) {
	q := url.Values{
		"scope":      {" openid email "},
		"prompt":     {"login"},
		"login_hint": {""},
		"max_age":    {"0"},
	}
	got := parseLoginParams(q, false)

	want := map[string]string{"scope": "openid email", "prompt": "login", "max_age": "0"}
	if len(got) != len(want) {
		t.Fatalf("params = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseLoginParamsEmptyFormMeansNoOverrides(t *testing.T) {
	if got := parseLoginParams(url.Values{"prompt": {""}}, false); got != nil {
		t.Errorf("params = %v, want nil so the configured request is untouched", got)
	}
}

func TestParseLoginParamsExtraLinesOverrideFields(t *testing.T) {
	q := url.Values{
		"prompt": {"login"},
		"extra":  {"prompt=consent\nclaims={\"a\":\"b=c\"}\n# note\n\nbad line"},
	}
	got := parseLoginParams(q, false)

	if got["prompt"] != "consent" {
		t.Errorf("prompt = %q, want the extra line to win", got["prompt"])
	}
	if got["claims"] != `{"a":"b=c"}` {
		t.Errorf("claims = %q, want the value split only on the first '='", got["claims"])
	}
	if len(got) != 2 {
		t.Errorf("params = %v, want comments and malformed lines skipped", got)
	}
}

func TestParseLoginParamsOAuth2IgnoresOIDCFields(t *testing.T) {
	got := parseLoginParams(url.Values{"scope": {"read"}, "prompt": {"login"}}, true)
	if got["scope"] != "read" {
		t.Errorf("scope = %q", got["scope"])
	}
	if _, ok := got["prompt"]; ok {
		t.Error("prompt is an OpenID Connect parameter and must not be taken for OAuth2")
	}
}

func newLoginTestHandler() *Handler {
	return &Handler{
		Config: config.OIDCConfig{
			ResponseMode:      "query",
			ExtraAuthParams:   map[string]string{"prompt": "consent", "ui_locales": "ja"},
			AuthRequestMaxAge: config.DefaultAuthRequestMaxAge,
		},
		oauth2Config: &oauth2.Config{
			ClientID: "client",
			Scopes:   []string{"openid", "profile"},
			Endpoint: oauth2.Endpoint{AuthURL: "https://idp.test/auth"},
		},
	}
}

func authorizationQuery(t *testing.T, h *Handler, target string) url.Values {
	t.Helper()
	rec := httptest.NewRecorder()
	h.handleLogin(rec, httptest.NewRequest(http.MethodGet, target, nil))

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusFound {
		t.Fatalf("status %d, location %q, err %v", rec.Code, rec.Header().Get("Location"), err)
	}
	return loc.Query()
}

func TestLoginFormValuesReachTheAuthorizationRequest(t *testing.T) {
	q := authorizationQuery(t, newLoginTestHandler(),
		"/login?scope=openid+email&prompt=login&response_mode=form_post&extra=acr_values%3Durn%3Amfa")

	want := map[string]string{
		"scope":         "openid email",
		"prompt":        "login",     // form beats configured extra_auth_params
		"response_mode": "form_post", // form beats configured response_mode
		"ui_locales":    "ja",        // untouched configured extra
		"acr_values":    "urn:mfa",   // from the extra lines
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q (query %v)", k, q.Get(k), v, q)
		}
	}
}

func TestPlainLoginKeepsConfiguredRequest(t *testing.T) {
	q := authorizationQuery(t, newLoginTestHandler(), "/login")

	want := map[string]string{
		"scope":         "openid profile",
		"prompt":        "consent",
		"response_mode": "query",
		"ui_locales":    "ja",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
}

func logoutQuery(t *testing.T, endpoint string, q url.Values, sendByDefault bool) (url.Values, bool) {
	t.Helper()
	raw, sent := buildLogoutURL(endpoint, "client", "http://app/oidc/", "ID.TOKEN", sendByDefault, q)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query(), sent
}

func TestBuildLogoutURLDefaults(t *testing.T) {
	got, sent := logoutQuery(t, "https://idp.test/logout", url.Values{}, true)

	want := map[string]string{
		"post_logout_redirect_uri": "http://app/oidc/",
		"client_id":                "client",
		"id_token_hint":            "ID.TOKEN",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}
	if !sent {
		t.Error("the session ID Token is sent by default")
	}
}

func TestBuildLogoutURLFormOverridesAndExtraWins(t *testing.T) {
	got, _ := logoutQuery(t, "https://idp.test/logout", url.Values{
		"post_logout_redirect_uri": {"http://elsewhere/"},
		"logout_hint":              {"a@b.test"},
		"state":                    {"from-form"},
		"extra":                    {"state=from-extra\nclient_id=other"},
	}, true)

	want := map[string]string{
		"post_logout_redirect_uri": "http://elsewhere/",
		"logout_hint":              "a@b.test",
		"state":                    "from-extra",
		"client_id":                "other",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}
}

func TestBuildLogoutURLIDTokenHintChoice(t *testing.T) {
	cases := []struct {
		name          string
		choice        string
		sendByDefault bool
		wantSent      bool
	}{
		{"default on", "", true, true},
		{"default off", "", false, false},
		{"omit beats default on", idTokenHintOmit, true, false},
		{"send beats default off", idTokenHintSend, false, true},
	}
	for _, c := range cases {
		got, sent := logoutQuery(t, "https://idp.test/logout", url.Values{"id_token_hint": {c.choice}}, c.sendByDefault)
		if sent != c.wantSent || (got.Get("id_token_hint") != "") != c.wantSent {
			t.Errorf("%s: sent=%v hint=%q, want sent=%v", c.name, sent, got.Get("id_token_hint"), c.wantSent)
		}
	}
}

func TestBuildLogoutURLKeepsAnExistingQuery(t *testing.T) {
	raw, _ := buildLogoutURL("https://idp.test/logout?tenant=x", "client", "http://app/", "", true, url.Values{})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("tenant") != "x" || u.Query().Get("client_id") != "client" {
		t.Errorf("url = %s, want the endpoint's own query kept and ours appended", raw)
	}
}

func TestBuildLogoutURLWithoutSessionTokenSendsNone(t *testing.T) {
	raw, sent := buildLogoutURL("https://idp.test/logout", "client", "http://app/", "", true, url.Values{"id_token_hint": {idTokenHintSend}})
	if sent || strings.Contains(raw, "id_token_hint") {
		t.Errorf("url = %s, want no id_token_hint when the session has no ID Token", raw)
	}
}

func TestDescribeReauthProfileListsItsParameters(t *testing.T) {
	rc := config.ReauthConfig{Name: "Step-up", ExtraAuthParams: map[string]string{"prompt": "login", "acr_values": "2"}}

	if got, want := describeReauthProfile(rc), "Step-up (acr_values=2, prompt=login)"; got != want {
		t.Errorf("describeReauthProfile = %q, want %q (sorted, so the label is stable)", got, want)
	}
	if got := describeReauthProfile(config.ReauthConfig{Name: "Plain"}); got != "Plain" {
		t.Errorf("a profile with no parameters should be shown by name only, got %q", got)
	}
}

func TestMergeParamsLetsTheFormOverrideTheProfile(t *testing.T) {
	got := mergeParams(
		map[string]string{"prompt": "none", "acr_values": "2"},
		map[string]string{"prompt": "login"},
	)

	if got["prompt"] != "login" || got["acr_values"] != "2" {
		t.Errorf("merged = %v, want the form's prompt over the profile's and the profile's acr_values kept", got)
	}
	if mergeParams(nil, nil) != nil {
		t.Error("merging nothing should stay nil so the request is untouched")
	}
}

func TestReauthOptionsOfferProfilesOnlyWhenConfigured(t *testing.T) {
	h := newLoginTestHandler()
	h.basePath = "/oidc"

	if h.reauthOptions().Preset != nil {
		t.Fatal("no preset expected without configured profiles")
	}

	h.Config.Reauth = []config.ReauthConfig{{Name: "Step-up", ExtraAuthParams: map[string]string{"acr_values": "2"}}}
	with := h.reauthOptions()
	if with.Preset == nil || with.Preset.Name != "profile" {
		t.Fatalf("preset = %+v, want the profile choice kept apart from the fields", with.Preset)
	}
	for _, f := range with.Fields {
		if f.Name == "profile" {
			t.Error("the profile must not also appear among the parameter fields")
		}
	}
	opts := with.Preset.Options
	if len(opts) != 2 || opts[0].Value != "" || opts[1].Value != "0" || opts[1].Short != "Step-up" {
		t.Errorf("profile options = %+v, want (none) plus the profile by index with its name as the short label", opts)
	}
	if opts[1].Values["acr_values"] != "2" {
		t.Errorf("the option must carry the profile's parameters for the form placeholders, got %v", opts[1].Values)
	}
	if with.Action != "/oidc/reauth" {
		t.Errorf("Action = %q", with.Action)
	}
}

func fieldNamed(t *testing.T, fields []components.RequestField, name string) components.RequestField {
	t.Helper()
	for _, f := range fields {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no field %q", name)
	return components.RequestField{}
}

func TestBlankFieldsShowWhatTheConfigSends(t *testing.T) {
	fields := loginOptionFields(false, authorizationDefaults{
		Scopes:       []string{"openid", "profile"},
		ResponseMode: "query",
		Extra:        map[string]string{"ui_locales": "ja", "prompt": "consent"},
	})

	if got := fieldNamed(t, fields, "scope").Placeholder; got != "openid profile" {
		t.Errorf("scope placeholder = %q", got)
	}
	if got := fieldNamed(t, fields, "ui_locales").Placeholder; got != "ja" {
		t.Errorf("ui_locales placeholder = %q, want the value extra_auth_params sends", got)
	}
	if got := fieldNamed(t, fields, "response_mode").Options[0].Label; got != "(query)" {
		t.Errorf("response_mode first choice = %q", got)
	}
	if got := fieldNamed(t, fields, "prompt").Options[0].Label; got != "(consent)" {
		t.Errorf("prompt first choice = %q", got)
	}
}

func TestFieldsTheConfigDoesNotSetShowNoPlaceholder(t *testing.T) {
	fields := loginOptionFields(false, authorizationDefaults{Scopes: []string{"openid"}})

	for _, name := range []string{"login_hint", "max_age", "acr_values", "ui_locales", "id_token_hint", "claims"} {
		f := fieldNamed(t, fields, name)
		if f.Placeholder != "" {
			t.Errorf("%s placeholder = %q: a blank field sends nothing, so nothing may look like a value", name, f.Placeholder)
		}
	}
	if got := fieldNamed(t, fields, "prompt").Options[0].Label; got != "(not sent)" {
		t.Errorf("prompt first choice = %q, want (not sent)", got)
	}
	if fieldNamed(t, fields, "login_hint").Help == "" {
		t.Error("the example moves to the note shown on focus")
	}
}

func TestLogoutDefaultsShowWhatIsSent(t *testing.T) {
	h := newLoginTestHandler()
	h.topPageURL = "http://app/oidc/"

	if got := h.idTokenHintDefault(); got != "(send)" {
		t.Errorf("unset logout_id_token_hint = %q", got)
	}
	off := false
	h.Config.LogoutIDTokenHint = &off
	if got := h.idTokenHintDefault(); got != "(omit)" {
		t.Errorf("logout_id_token_hint=false = %q", got)
	}
	redirect := fieldNamed(t, h.logoutOptions().Fields, "post_logout_redirect_uri")
	if redirect.Placeholder != "http://app/oidc/" {
		t.Errorf("post_logout_redirect_uri placeholder = %q", redirect.Placeholder)
	}
}
