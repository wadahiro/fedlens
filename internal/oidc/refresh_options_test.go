package oidc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestParseRefreshParams(t *testing.T) {
	if got := parseRefreshParams(url.Values{"scope": {""}, "resource": {" "}}); got != nil {
		t.Errorf("blank fields must send nothing, got %v", got)
	}
	q := url.Values{"scope": {" openid "}, "resource": {"https://api.example"}, "extra": {"audience=api\nscope=profile"}}
	want := map[string]string{"scope": "profile", "resource": "https://api.example", "audience": "api"}
	if got := parseRefreshParams(q); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (an extra line overrides a field)", got, want)
	}
}

func TestRefreshOptionsFieldsStartEmpty(t *testing.T) {
	o := (&Handler{basePath: "/oidc"}).refreshOptions()
	if o.Action != "/oidc/refresh" || len(o.Fields) != 2 {
		t.Fatalf("options = %+v", o)
	}
	for _, f := range o.Fields {
		if f.Value != "" {
			t.Errorf("%s starts with %q: a refresh adds nothing by default", f.Name, f.Value)
		}
	}
}

// The oauth2 token source gives no way to add parameters; the transport must add
// them to the body it sends while leaving the grant and client authentication alone.
func TestFormParamsTransportAddsParametersToRefreshRequest(t *testing.T) {
	var got url.Values
	var user string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(b))
		user, _, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"new","token_type":"bearer"}`)
	}))
	defer srv.Close()

	cfg := &oauth2.Config{ClientID: "cid", ClientSecret: "sec", Endpoint: oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInHeader}}
	client := &http.Client{Transport: &formParamsTransport{base: http.DefaultTransport, params: map[string]string{"scope": "openid", "resource": "https://api.example"}}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)

	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: "rt"}).Token()
	if err != nil || tok.AccessToken != "new" {
		t.Fatalf("token = %+v, err = %v", tok, err)
	}
	if got.Get("grant_type") != "refresh_token" || got.Get("refresh_token") != "rt" {
		t.Errorf("the grant was lost: %v", got)
	}
	if got.Get("scope") != "openid" || got.Get("resource") != "https://api.example" {
		t.Errorf("parameters were not added: %v", got)
	}
	if user != "cid" {
		t.Errorf("client authentication was lost, basic user = %q", user)
	}
}

func TestTokenRequestRowsShowAddedParametersAfterTheUsualOnes(t *testing.T) {
	rows := tokenRequestRows(map[string]string{"zzz": "1", "refresh_token": "rt", "grant_type": "refresh_token", "scope": "s", "audience": "a"})
	var keys []string
	for _, r := range rows {
		keys = append(keys, r.Key)
	}
	want := []string{"grant_type", "refresh_token", "scope", "audience", "zzz"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("order = %v, want %v", keys, want)
	}
}
