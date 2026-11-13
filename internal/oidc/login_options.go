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
// login_hint and the rest are OpenID Connect parameters. Each field starts with the
// config file's value, so the form shows the request as it will be sent.
func loginOptionFields(isOAuth2 bool, d authorizationDefaults) []components.RequestField {
	text := func(name, help string, kind string) components.RequestField {
		return components.RequestField{Name: name, Label: name, Kind: kind, Value: d.Extra[name], Help: help}
	}
	scope := components.RequestField{
		Name:  loginParamScope,
		Label: "scope",
		Kind:  "text",
		Value: strings.Join(d.Scopes, " "),
		Help:  "Space-separated. Replaces the configured scopes for this request.",
	}
	responseMode := components.RequestField{
		Name:    "response_mode",
		Label:   "response_mode",
		Kind:    "select",
		Value:   d.ResponseMode,
		Options: withOption(notSent(), d.ResponseMode, "query", "fragment", "form_post"),
	}
	if isOAuth2 {
		return []components.RequestField{scope, responseMode}
	}
	return []components.RequestField{
		scope,
		responseMode,
		{
			Name:    "prompt",
			Label:   "prompt",
			Kind:    "select",
			Value:   d.Extra["prompt"],
			Options: withOption(notSent(), d.Extra["prompt"], "none", "login", "consent", "select_account"),
		},
		text("login_hint", "e.g. user@example.com", "text"),
		text("max_age", "Seconds. Maximum authentication age. Unrelated to auth_request_max_age in the config.", "text"),
		text("acr_values", "Space-separated, in order of preference.", "text"),
		text("ui_locales", "e.g. ja en", "text"),
		text("id_token_hint", "A previously issued ID Token (JWT).", "textarea"),
		text("claims", `JSON claims request parameter, e.g. {"id_token":{"email":null}}`, "textarea"),
	}
}

// notSent is the empty choice of a select: nothing is sent for the parameter.
func notSent() []components.RequestOption {
	return []components.RequestOption{{Value: "", Label: components.DefaultChoice("")}}
}

// withOption appends the given choices, plus the config's own value when it is not
// one of them, so the select can start on what the config sets.
func withOption(options []components.RequestOption, configured string, choices ...string) []components.RequestOption {
	known := false
	for _, c := range choices {
		options = append(options, components.RequestOption{Value: c, Label: c})
		known = known || c == configured
	}
	if configured != "" && !known {
		options = append(options, components.RequestOption{Value: configured, Label: configured})
	}
	return options
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

// parseLoginParams turns the submitted form into the parameters it overrides. A
// field that still holds what the config gave it overrides nothing, which keeps the
// layering (config, then profile, then form): a profile is not undone by a field the
// user never touched. A changed field overrides; a field the config filled and the
// user emptied is returned as "", meaning the parameter is not sent (see
// requestParams). The extra lines are applied last so they can override a field.
func parseLoginParams(q url.Values, isOAuth2 bool, d authorizationDefaults) map[string]string {
	params := map[string]string{}
	configured := func(name string) string {
		switch name {
		case loginParamScope:
			return strings.Join(d.Scopes, " ")
		case "response_mode":
			return d.ResponseMode
		default:
			return d.Extra[name]
		}
	}
	for _, f := range loginOptionFields(isOAuth2, authorizationDefaults{}) {
		if !q.Has(f.Name) { // the form was not submitted (a plain link): nothing to override
			continue
		}
		v := strings.TrimSpace(q.Get(f.Name))
		switch {
		case v == configured(f.Name):
		case v != "":
			params[f.Name] = v
		case f.Name != loginParamScope: // scope cannot be removed: a request without one is not what is meant
			params[f.Name] = ""
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

// requestParams resolves the parameters an authorization request carries beyond the
// standard ones: the configured response_mode and extra_auth_params, then the
// overrides of a reauth profile and the form, where an empty value removes the
// parameter.
func requestParams(responseMode string, configured, overrides map[string]string) map[string]string {
	out := map[string]string{}
	if responseMode != "" {
		out["response_mode"] = responseMode
	}
	for k, v := range configured {
		out[k] = v
	}
	for k, v := range overrides {
		if v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

// idTokenHintDefault says what a Logout that leaves id_token_hint alone does:
// logout_id_token_hint from the config, or sending it when the config says nothing.
func (h *Handler) idTokenHintDefault() string {
	if h.Config.LogoutIDTokenHint != nil && !*h.Config.LogoutIDTokenHint {
		return components.DefaultChoice(idTokenHintOmit)
	}
	return components.DefaultChoice(idTokenHintSend)
}
