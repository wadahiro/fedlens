package components

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var sb strings.Builder
	if err := c.Render(context.Background(), &sb); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

func loginOptions() RequestOptions {
	return RequestOptions{ID: "login", Label: "Login", Action: "/app/login"}
}

func area(t *testing.T, sets ...RequestOptions) string {
	t.Helper()
	return render(t, RequestOptionsArea(sets))
}

func TestRequestOptionsAreaRendersEachFieldKind(t *testing.T) {
	o := loginOptions()
	o.Fields = []RequestField{
		{Name: "prompt", Label: "prompt", Kind: "select", Options: TriStateOptions("(default)")},
		{Name: "name_id_format", Label: "Format", Kind: "text", Options: []RequestOption{{Value: "urn:x", Label: "x"}}},
		{Name: "login_hint", Label: "login_hint", Kind: "text", Placeholder: "user@example.com"},
		{Name: "claims", Label: "claims", Kind: "textarea"},
	}
	o.ExtraName = "extra"
	o.ExtraHelp = "one per line"
	html := area(t, o)

	for _, want := range []string{
		`action="/app/login"`, `method="get"`,
		`<select name="prompt"`, `<datalist id="ro-list-login-name_id_format"`, `list="ro-list-login-name_id_format"`,
		`placeholder="user@example.com"`, `<textarea name="claims"`, `<textarea name="extra"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s in:\n%s", want, html)
		}
	}
	if strings.Contains(html, `list="ro-list-login-login_hint"`) {
		t.Error("a text field without suggestions must not reference a datalist")
	}
}

func TestRequestOptionsAreaOmitsExtraWhenUnnamed(t *testing.T) {
	if strings.Contains(area(t, loginOptions()), `name="extra"`) {
		t.Error("textarea rendered without ExtraName")
	}
}

func TestSelectOptionsCarryTheirShortLabel(t *testing.T) {
	o := loginOptions()
	o.Fields = []RequestField{{Name: "profile", Label: "profile", Kind: "select", Options: []RequestOption{
		{Value: "0", Label: "Step-up (acr_values=2)", Short: "Step-up"},
	}}}

	if html := area(t, o); !strings.Contains(html, `data-short="Step-up"`) {
		t.Errorf("the summary reads data-short, so a long label can be abbreviated there:\n%s", html)
	}
}

func TestSplitButtonTiesButtonCaretAndFormTogether(t *testing.T) {
	html := render(t, SplitButton(loginOptions()))

	for _, want := range []string{
		`form="ro-form-login"`,           // the button submits the form
		`aria-controls="ro-panel-login"`, // the caret refers to its form
		`data-ro-id="login"`,             // the delegated handler finds the button's parts by this
		`data-testid="login-btn"`, `data-testid="login-options-toggle"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s in:\n%s", want, html)
		}
	}
}

func TestRequestOptionsCardIsOneCardWithAFormPerButton(t *testing.T) {
	reauth := RequestOptions{ID: "reauth", Label: "Re-authenticate", Action: "/app/reauth"}
	logout := RequestOptions{ID: "logout", Label: "Logout", Style: "danger", Action: "/app/logout"}
	html := area(t, loginOptions(), reauth, logout)

	for _, want := range []string{
		`class="ro-card" hidden`, // nothing shows until it is opened or modified
		`data-testid="options-card"`, `data-testid="options-title"`, `data-testid="options-collapse"`,
		`data-testid="reauth-options-panel"`, `data-testid="logout-options-summary"`, `data-testid="logout-options-reset"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s in:\n%s", want, html)
		}
	}
	if n := strings.Count(html, `data-testid="options-card"`); n != 1 {
		t.Errorf("%d cards rendered, want a single card for all buttons", n)
	}
	if n := strings.Count(html, `class="ro-body"`); n != 3 {
		t.Errorf("%d forms rendered, want one per button", n)
	}
	if strings.Contains(html, "ro-tab") {
		t.Error("the caret is the only way in; there must be no second set of tabs to choose from")
	}
	if strings.Contains(html, "ro-overview") {
		t.Error("a closed card shows nothing: the count on each caret says what is modified")
	}
}

func TestSplitButtonCaretCarriesTheModifiedCount(t *testing.T) {
	html := render(t, SplitButton(loginOptions()))

	if !strings.Contains(html, `class="ro-count" hidden`) {
		t.Errorf("the caret needs a count of modified values, hidden until there are some:\n%s", html)
	}
}

func TestDangerButtonsMarkTheirForm(t *testing.T) {
	logout := RequestOptions{ID: "logout", Label: "Logout", Style: "danger", Action: "/logout"}
	html := area(t, loginOptions(), logout)

	if n := strings.Count(html, `data-danger="true"`); n != 1 {
		t.Errorf("%d forms marked data-danger=true, want only the danger button's, so the card can take its colour", n)
	}
	if !strings.Contains(render(t, SplitButton(logout)), "action-btn-danger") {
		t.Error("a danger button must keep its danger look")
	}
}

func TestPresetIsSeparatedFromTheParameters(t *testing.T) {
	o := RequestOptions{ID: "reauth", Label: "Re-authenticate", Action: "/reauth",
		Preset: &RequestField{Name: "profile", Label: "Profile", Kind: "select", Options: []RequestOption{
			{Value: "", Label: "(none)"},
			{Value: "0", Label: "Step-up", Short: "Step-up", Values: map[string]string{"acr_values": "2"}},
		}},
		Fields: []RequestField{{Name: "acr_values", Label: "acr_values", Kind: "text"}},
	}
	html := area(t, o)

	preset := strings.Index(html, `class="ro-preset"`)
	section := strings.Index(html, `class="ro-section"`)
	field := strings.Index(html, `name="acr_values"`)
	if preset < 0 || section < 0 || field < 0 || !(preset < section && section < field) {
		t.Errorf("want the preset band, then the Parameters heading, then the fields (got %d, %d, %d):\n%s", preset, section, field, html)
	}
	if !strings.Contains(html, `data-values="{&#34;acr_values&#34;:&#34;2&#34;}"`) && !strings.Contains(html, `data-values='{"acr_values":"2"}'`) && !strings.Contains(html, `data-values="{"acr_values":"2"}"`) {
		t.Errorf("the option must carry what the profile sets, for the placeholders:\n%s", html)
	}
	if !strings.Contains(html, `data-testid="reauth-opt-profile"`) {
		t.Error("the preset keeps the field test id so tests can select a profile")
	}
	if strings.Contains(area(t, loginOptions()), "ro-preset") || strings.Contains(area(t, loginOptions()), "Parameters") {
		t.Error("a button without a preset gets neither the band nor the Parameters heading")
	}
}

func TestOptionsOfDifferentButtonsDoNotCollide(t *testing.T) {
	login := loginOptions()
	login.Fields = []RequestField{{Name: "scope", Label: "scope", Kind: "text"}}
	reauth := RequestOptions{ID: "reauth", Label: "Re-authenticate", Action: "/app/reauth", Fields: login.Fields}

	html := area(t, login, reauth)

	for _, id := range []string{`id="ro-form-login"`, `id="ro-form-reauth"`, `id="ro-panel-login"`, `id="ro-panel-reauth"`} {
		if strings.Count(html, id) != 1 {
			t.Errorf("%s should appear exactly once, so two buttons can carry options:\n%s", id, html)
		}
	}
	if !strings.Contains(html, `data-testid="login-opt-scope"`) || !strings.Contains(html, `data-testid="reauth-opt-scope"`) {
		t.Error("field test ids must be scoped by button")
	}
}

func TestParseKeyValueLines(t *testing.T) {
	got := ParseKeyValueLines("a=1\n  b = two words \n#c=3\n\n=nokey\nnoequals\nurl=http://x/?q=1")

	want := map[string]string{"a": "1", "b": "two words", "url": "http://x/?q=1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestPrimarySplitButtonIsMarkedFilled(t *testing.T) {
	if !strings.Contains(render(t, SplitButton(loginOptions())), `split-btn split-filled`) {
		t.Error("the primary button is filled, so its count must be drawn inverted")
	}
	outline := RequestOptions{ID: "reauth", Label: "Re-authenticate", Style: "outline", Action: "/reauth"}
	if strings.Contains(render(t, SplitButton(outline)), "split-filled") {
		t.Error("an outline button is not filled while closed")
	}
}

func TestFallbackAndDefaultChoiceShowOnlyWhatIsSent(t *testing.T) {
	cases := []struct{ got, want string }{
		{Fallback("ja"), "ja"},
		{Fallback(""), ""}, // a blank field that sends nothing shows nothing
		{DefaultChoice("form_post"), "(form_post)"},
		{DefaultChoice("true"), "(true)"},
		{DefaultChoice(""), "(not sent)"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if got := TriStateOptions("(true)")[0]; got.Value != "" || got.Label != "(true)" {
		t.Errorf("first tri-state choice = %+v, want the unset value with the given label", got)
	}
}

func TestExtraParametersHasNoPlaceholder(t *testing.T) {
	o := loginOptions()
	o.ExtraName = "extra"
	o.ExtraHelp = "One key=value per line."

	html := area(t, o)
	if !strings.Contains(html, `<textarea name="extra"`) || strings.Contains(html, `placeholder="key=value"`) {
		t.Errorf("a blank extra field sends nothing, so it must show no placeholder; the format belongs in the note:\n%s", html)
	}
	if !strings.Contains(html, "One key=value per line.") {
		t.Error("the format is explained in the field's note")
	}
}

func TestFieldsRenderTheirInitialValue(t *testing.T) {
	o := loginOptions()
	o.Fields = []RequestField{
		{Name: "ui_locales", Label: "ui_locales", Kind: "text", Value: "ja"},
		{Name: "claims", Label: "claims", Kind: "textarea", Value: `{"a":1}`},
		{Name: "prompt", Label: "prompt", Kind: "select", Value: "consent", Options: []RequestOption{
			{Value: "", Label: "(not sent)"}, {Value: "login", Label: "login"}, {Value: "consent", Label: "consent"},
		}},
		{Name: "login_hint", Label: "login_hint", Kind: "text"},
	}
	html := area(t, o)

	if !strings.Contains(html, `name="ui_locales" value="ja"`) {
		t.Errorf("a text field starts with the config's value:\n%s", html)
	}
	if !strings.Contains(html, `>{&#34;a&#34;:1}</textarea>`) {
		t.Errorf("a textarea starts with the config's value:\n%s", html)
	}
	if !strings.Contains(html, `value="consent"`) || strings.Count(html, " selected") != 1 {
		t.Errorf("exactly the config's choice starts selected:\n%s", html)
	}
	if strings.Contains(html, `name="login_hint" value="`) && !strings.Contains(html, `name="login_hint" value=""`) {
		t.Errorf("a field the config does not set starts empty:\n%s", html)
	}
}

func TestEachFieldCarriesTheFlagsThatSayWhatItOverrides(t *testing.T) {
	o := loginOptions()
	o.Fields = []RequestField{{Name: "ui_locales", Label: "ui_locales", Kind: "text"}}
	html := area(t, o)

	if !strings.Contains(html, `ro-flag ro-flag-config" hidden`) || !strings.Contains(html, `ro-flag ro-flag-profile" hidden`) {
		t.Errorf("a field needs a hidden flag for the config and one for the profile, which the script fills in:\n%s", html)
	}
}
