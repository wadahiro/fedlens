package protocol

import (
	"net/url"
	"testing"
)

func TestParseReauthStep(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		want    int
		wantErr bool
	}{
		{"nothing means the default", "", DefaultReauthStep, false},
		{"a blank profile means the default", "profile=", DefaultReauthStep, false},
		{"profile from the form", "profile=2", 2, false},
		{"legacy step", "step=1", 1, false},
		{"legacy default step", "step=-1", -1, false},
		{"profile wins over step", "profile=0&step=3", 0, false},
		{"not a number", "profile=x", 0, true},
	}
	for _, c := range cases {
		q, _ := url.ParseQuery(c.query)
		got, err := ParseReauthStep(q)
		if (err != nil) != c.wantErr || (!c.wantErr && got != c.want) {
			t.Errorf("%s: got %d, %v; want %d, error=%v", c.name, got, err, c.want, c.wantErr)
		}
	}
}
