package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RandomHex generates a hex-encoded random string of n bytes.
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HTMLEscape escapes HTML special characters.
func HTMLEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

// SortedKeys returns the sorted keys of a string-keyed map.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// PrettyJSON formats a JSON RawMessage with indentation.
func PrettyJSON(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return string(data)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(b)
}

// TimestampClaims is the set of claim names that contain Unix timestamps.
var TimestampClaims = map[string]bool{
	"auth_time":  true,
	"exp":        true,
	"iat":        true,
	"nbf":        true,
	"updated_at": true,
}

// FormatClaimValue formats a claim value, with special handling for timestamps.
func FormatClaimValue(key string, v any) string {
	raw := FormatValue(v)
	if !TimestampClaims[key] {
		return raw
	}
	if n, ok := v.(float64); ok && n == float64(int64(n)) {
		t := time.Unix(int64(n), 0).UTC()
		return fmt.Sprintf("%s (%s)", raw, t.Format("2006-01-02T15:04:05 UTC"))
	}
	return raw
}

// FormatValue formats a value for display, handling numeric types.
func FormatValue(v any) string {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return fmt.Sprintf("%d", int64(n))
		}
		return fmt.Sprintf("%g", n)
	case json.Number:
		return n.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}
