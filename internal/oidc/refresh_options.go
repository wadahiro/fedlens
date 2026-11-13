package oidc

import (
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

const (
	refreshParamScope    = "scope"
	refreshParamResource = "resource"
)

// refreshOptions builds the options of the Refresh Token button. The fields start
// empty: a refresh request carries no parameter beyond the grant by default, and
// each field adds one the spec allows.
func (h *Handler) refreshOptions() *components.RequestOptions {
	return &components.RequestOptions{
		ID:     "refresh",
		Label:  "Refresh Token",
		Style:  "outline",
		Action: h.basePath + "/refresh",
		Note:   "Every field is optional. A blank one is left out of the request.",
		Fields: []components.RequestField{
			{
				Name: refreshParamScope, Label: "scope", Kind: "text",
				Help: "RFC 6749 6: a subset of the scope granted at login. Blank sends none, so the grant stays as it was.",
			},
			{
				Name: refreshParamResource, Label: "resource", Kind: "text",
				Help: "RFC 8707: the resource server the new access token is for.",
			},
		},
		ExtraName: loginParamExtra,
		ExtraHelp: "One key=value per line, for parameters the form has no field for, such as audience.",
	}
}

// parseRefreshParams turns the submitted form into the extra parameters of the
// refresh request. The extra lines come last so they can override a field.
func parseRefreshParams(q url.Values) map[string]string {
	params := map[string]string{}
	for _, name := range []string{refreshParamScope, refreshParamResource} {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			params[name] = v
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

// formParamsTransport adds parameters to the form body of token requests.
//
// golang.org/x/oauth2's TokenSource sends grant_type and refresh_token only and
// has no way to add more. Rewriting the request on its way out keeps its client
// authentication, its retry with the other auth style and its response parsing,
// which a hand-built request would have to copy.
type formParamsTransport struct {
	base   http.RoundTripper
	params map[string]string
}

func (t *formParamsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.Body == nil || !strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return t.base.RoundTrip(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body.Close()
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, err
	}
	for k, v := range t.params {
		form.Set(k, v)
	}
	body := form.Encode()
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(strings.NewReader(body))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
	out.ContentLength = int64(len(body))
	return t.base.RoundTrip(out)
}

// tokenRequestRows lists a token request's parameters for display: the usual ones
// in their usual order, then any others sorted, so parameters added by the form
// are shown too.
func tokenRequestRows(params map[string]string) []components.ClaimRow {
	known := []string{"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token", "scope", "resource"}
	seen := map[string]bool{}
	var rows []components.ClaimRow
	for _, k := range known {
		if v, ok := params[k]; ok {
			rows = append(rows, components.ClaimRow{Key: k, Value: v})
			seen[k] = true
		}
	}
	var rest []string
	for k := range params {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		rows = append(rows, components.ClaimRow{Key: k, Value: params[k]})
	}
	return rows
}
