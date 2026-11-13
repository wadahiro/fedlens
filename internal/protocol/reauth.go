package protocol

import (
	"net/url"
	"strconv"
	"strings"
)

// DefaultReauthStep selects the re-authentication that uses no configured profile.
const DefaultReauthStep = -1

// ParseReauthStep reads which re-authentication profile a /reauth request asks
// for. "profile" is what the options form submits; "step" is the older query
// parameter and keeps existing /reauth?step=N links working. A request naming
// neither means the default re-authentication.
func ParseReauthStep(q url.Values) (int, error) {
	for _, name := range []string{"profile", "step"} {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			return strconv.Atoi(v)
		}
	}
	return DefaultReauthStep, nil
}
