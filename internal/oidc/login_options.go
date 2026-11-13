package oidc

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/wadahiro/fedlens/internal/config"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

const (
	loginParamScope = "scope"
	loginParamExtra = "extra"
)

// authorizationDefaults is what the config file contributes to every
// authorization request. The form shows it as the faint placeholder of a blank
// field, so what is sent when a field is left alone can be read from the form.
type authorizationDefaults struct {
	Scopes       []string
	ResponseMode string
	Extra        map[string]string // extra_auth_params
}

// loginOptionFields lists the inputs of the form of a button that starts an
// authorization request. OAuth2 gets only scope and response_mode: prompt,
// login_hint and the rest are OpenID Connect parameters. A faint placeholder is
// only ever a value that is sent when the field is left blank; examples of what to
// type are in the note shown on focus.
func loginOptionFields(isOAuth2 bool, d authorizationDefaults) []components.RequestField {
	configured := func(name string) string { return components.Fallback(d.Extra[name]) }
	choiceOf := func(configuredValue string) string {
		return components.DefaultChoice(configuredValue)
	}
	scope := components.RequestField{
		Name:        loginParamScope,
		Label:       "scope",
		Kind:        "text",
		Placeholder: components.Fallback(strings.Join(d.Scopes, " ")),
		Help:        "Space-separated. Replaces the configured scopes for this request.",
	}
	responseMode := components.RequestField{
		Name:  "response_mode",
		Label: "response_mode",
		Kind:  "select",
		Options: []components.RequestOption{
			{Value: "", Label: choiceOf(d.ResponseMode)},
			{Value: "query", Label: "query"},
			{Value: "fragment", Label: "fragment"},
			{Value: "form_post", Label: "form_post"},
		},
	}
	if isOAuth2 {
		return []components.RequestField{scope, responseMode}
	}
	return []components.RequestField{
		scope,
		responseMode,
		{
			Name:  "prompt",
			Label: "prompt",
			Kind:  "select",
			Options: []components.RequestOption{
				{Value: "", Label: choiceOf(d.Extra["prompt"])},
				{Value: "none", Label: "none"},
				{Value: "login", Label: "login"},
				{Value: "consent", Label: "consent"},
				{Value: "select_account", Label: "select_account"},
			},
		},
		{Name: "login_hint", Label: "login_hint", Kind: "text", Placeholder: configured("login_hint"), Help: "e.g. user@example.com"},
		{Name: "max_age", Label: "max_age", Kind: "text", Placeholder: configured("max_age"), Help: "Seconds. Maximum authentication age. Unrelated to auth_request_max_age in the config."},
		{Name: "acr_values", Label: "acr_values", Kind: "text", Placeholder: configured("acr_values"), Help: "Space-separated, in order of preference."},
		{Name: "ui_locales", Label: "ui_locales", Kind: "text", Placeholder: configured("ui_locales"), Help: "e.g. ja en"},
		{Name: "id_token_hint", Label: "id_token_hint", Kind: "textarea", Placeholder: configured("id_token_hint"), Help: "A previously issued ID Token (JWT)."},
		{Name: "claims", Label: "claims", Kind: "textarea", Placeholder: configured("claims"), Help: `JSON claims request parameter, e.g. {"id_token":{"email":null}}`},
	}
}

func (h *Handler) authorizationDefaults() authorizationDefaults {
	return authorizationDefaults{
		Scopes:       h.oauth2Config.Scopes,
		ResponseMode: h.Config.ResponseMode,
		Extra:        h.Config.ExtraAuthParams,
	}
}

// authorizationOptions builds the options of a button that starts an authorization
// request. Login and Re-authenticate send the same parameters, so they share it.
func (h *Handler) authorizationOptions(id, label, style, action string) *components.RequestOptions {
	return &components.RequestOptions{
		ID:        id,
		Label:     label,
		Style:     style,
		Action:    h.basePath + action,
		Fields:    loginOptionFields(h.isOAuth2, h.authorizationDefaults()),
		ExtraName: loginParamExtra,
		ExtraHelp: "One key=value per line, for parameters the form has no field for. Applied after the configured extra_auth_params.",
	}
}

// loginOptions builds the options shown next to the Login button.
func (h *Handler) loginOptions() *components.RequestOptions {
	return h.authorizationOptions("login", "Login", "", "/login")
}

// reauthOptions builds the options of the default Re-authenticate button. When
// reauth profiles are configured they are offered as a choice in the form, and
// the other fields override what the chosen profile sets.
func (h *Handler) reauthOptions() *components.RequestOptions {
	o := h.authorizationOptions("reauth", "Re-authenticate", "outline", "/reauth")
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
			Values: rc.ExtraAuthParams,
		})
	}
	return components.RequestField{
		Name: "profile", Label: "Profile", Kind: "select", Options: opts,
		Help: "Applied first. Any parameter you fill in below overrides the profile's value for it.",
	}
}

// describeReauthProfile names a profile together with the parameters it adds, so
// the choice can be made without looking the profile up in the config.
func describeReauthProfile(rc config.ReauthConfig) string {
	if len(rc.ExtraAuthParams) == 0 {
		return rc.Name
	}
	keys := make([]string, 0, len(rc.ExtraAuthParams))
	for k := range rc.ExtraAuthParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, len(keys))
	for i, k := range keys {
		pairs[i] = k + "=" + rc.ExtraAuthParams[k]
	}
	return rc.Name + " (" + strings.Join(pairs, ", ") + ")"
}

// mergeParams returns base with every entry of override applied on top.
func mergeParams(base, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

const (
	logoutParamIDTokenHint = "id_token_hint"
	idTokenHintSend        = "send"
	idTokenHintOmit        = "omit"
)

// logoutOptions builds the options of the Logout button (RP-Initiated Logout).
func (h *Handler) logoutOptions() *components.RequestOptions {
	return &components.RequestOptions{
		ID:     "logout",
		Label:  "Logout",
		Style:  "danger",
		Action: h.basePath + "/logout",
		Fields: []components.RequestField{
			{Name: "post_logout_redirect_uri", Label: "post_logout_redirect_uri", Kind: "text", Placeholder: components.Fallback(h.topPageURL)},
			{Name: "logout_hint", Label: "logout_hint", Kind: "text", Help: "e.g. user@example.com"},
			{Name: "ui_locales", Label: "ui_locales", Kind: "text", Help: "e.g. ja en"},
			{Name: "state", Label: "state", Kind: "text", Help: "An opaque value the IdP returns to post_logout_redirect_uri."},
			{
				Name: logoutParamIDTokenHint, Label: "id_token_hint", Kind: "select",
				Options: []components.RequestOption{
					{Value: "", Label: h.idTokenHintDefault()},
					{Value: idTokenHintSend, Label: "send the session ID Token"},
					{Value: idTokenHintOmit, Label: "omit"},
				},
				Help: "Whether to send the session's ID Token. logout_id_token_hint in the config sets the default.",
			},
		},
		ExtraName: loginParamExtra,
		ExtraHelp: "One key=value per line, for parameters the form has no field for.",
	}
}

// buildLogoutURL assembles the end_session_endpoint request. The form values win
// over the defaults, and the extra lines win over the form. It reports whether
// the session's ID Token was sent as id_token_hint.
func buildLogoutURL(endpoint, clientID, topPageURL, idToken string, sendByDefault bool, q url.Values) (string, bool) {
	values := url.Values{}
	values.Set("post_logout_redirect_uri", topPageURL)
	values.Set("client_id", clientID)
	for _, name := range []string{"post_logout_redirect_uri", "logout_hint", "ui_locales", "state"} {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			values.Set(name, v)
		}
	}
	for k, v := range components.ParseKeyValueLines(q.Get(loginParamExtra)) {
		values.Set(k, v)
	}

	send := sendByDefault
	switch strings.TrimSpace(q.Get(logoutParamIDTokenHint)) {
	case idTokenHintSend:
		send = true
	case idTokenHintOmit:
		send = false
	}
	sent := send && idToken != ""
	if sent {
		values.Set("id_token_hint", idToken)
	}

	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	return endpoint + separator + values.Encode(), sent
}

// parseLoginParams turns the submitted form into authorization request
// parameters. Blank fields are dropped so they keep the configured behaviour,
// and the extra lines are applied last so they can override a field.
func parseLoginParams(q url.Values, isOAuth2 bool) map[string]string {
	params := map[string]string{}
	for _, f := range loginOptionFields(isOAuth2, authorizationDefaults{}) {
		if v := strings.TrimSpace(q.Get(f.Name)); v != "" {
			params[f.Name] = v
		}
	}
	for k, v := range components.ParseKeyValueLines(q.Get(loginParamExtra)) {
		params[k] = v
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

// idTokenHintDefault says what a Logout that leaves id_token_hint alone does:
// logout_id_token_hint from the config, or sending it when the config says nothing.
func (h *Handler) idTokenHintDefault() string {
	if h.Config.LogoutIDTokenHint != nil && !*h.Config.LogoutIDTokenHint {
		return components.DefaultChoice(idTokenHintOmit)
	}
	return components.DefaultChoice(idTokenHintSend)
}
