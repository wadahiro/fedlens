package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CertificateInfo holds structured metadata for an X.509 certificate.
type CertificateInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    string
	NotAfter     string
	Fingerprint  string // SHA-256 colon-separated hex
}

// ParseCertificateInfo extracts structured metadata from an X.509 certificate.
func ParseCertificateInfo(cert *x509.Certificate) CertificateInfo {
	fingerprint := sha256.Sum256(cert.Raw)
	parts := make([]string, len(fingerprint))
	for i, b := range fingerprint {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    FormatTimestamp(cert.NotBefore.UTC().Format(time.RFC3339)),
		NotAfter:     FormatTimestamp(cert.NotAfter.UTC().Format(time.RFC3339)),
		Fingerprint:  strings.Join(parts, ":"),
	}
}

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

// DisplayLocation is the timezone location configured for display.
// Set from config.Timezone via time.LoadLocation.
var DisplayLocation *time.Location

// TimestampClaims is the set of claim names that contain Unix timestamps.
var TimestampClaims = map[string]bool{
	"auth_time":  true,
	"exp":        true,
	"iat":        true,
	"nbf":        true,
	"updated_at": true,
}

// FormatClaimValue formats a claim value, with special handling for timestamps.
// Preserves raw value and shows UTC + configured timezone if different.
func FormatClaimValue(key string, v any) string {
	raw := FormatValue(v)
	if !TimestampClaims[key] {
		return raw
	}
	if n, ok := v.(float64); ok && n == float64(int64(n)) {
		t := time.Unix(int64(n), 0)
		utcStr := t.UTC().Format("2006-01-02T15:04:05 MST")
		if DisplayLocation != nil && DisplayLocation != time.UTC {
			localStr := t.In(DisplayLocation).Format("2006-01-02T15:04:05 MST")
			return fmt.Sprintf("%s (%s / %s)", raw, utcStr, localStr)
		}
		return fmt.Sprintf("%s (%s)", raw, utcStr)
	}
	return raw
}

// FormatTimestamp formats a time string (e.g. RFC3339) with the configured timezone appended.
// Returns the original string with configured timezone appended if different from UTC.
func FormatTimestamp(original string) string {
	if DisplayLocation == nil || DisplayLocation == time.UTC {
		return original
	}
	t, err := time.Parse(time.RFC3339, original)
	if err != nil {
		return original
	}
	localStr := t.In(DisplayLocation).Format("2006-01-02T15:04:05 MST")
	return fmt.Sprintf("%s (%s)", original, localStr)
}

// FormatValue formats a value for display, handling numeric types.
// Maps and slices are formatted as compact JSON to avoid Go's default map[...] output.
func FormatValue(v any) string {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return fmt.Sprintf("%d", int64(n))
		}
		return fmt.Sprintf("%g", n)
	case json.Number:
		return n.String()
	case map[string]any, []any:
		if b, err := json.Marshal(n); err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
