package protocol

import (
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// CleanGoErrorMessage removes Go HTTP client prefixes like `Get "http://...": `.
func CleanGoErrorMessage(msg string) string {
	for _, method := range []string{"Get", "Post", "Head", "Put", "Delete", "Patch"} {
		prefix := method + " \""
		if strings.HasPrefix(msg, prefix) {
			if idx := strings.Index(msg[len(prefix):], "\": "); idx >= 0 {
				return msg[len(prefix)+idx+3:]
			}
		}
	}
	return msg
}

// FormatHTTPStatusLine formats "HTTP/1.1 200 OK".
func FormatHTTPStatusLine(statusCode int) string {
	return fmt.Sprintf("HTTP/1.1 %d %s", statusCode, http.StatusText(statusCode))
}

// FormatHTTPHeaders formats http.Header into raw HTTP header text.
// Header names are sorted for stable output.
func FormatHTTPHeaders(headers http.Header) string {
	var names []string
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		for _, value := range headers[name] {
			b.WriteString(name + ": " + value + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

var wwwAuthParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// ParseWWWAuthenticate extracts error, error_description, and error_uri
// from a WWW-Authenticate header value (RFC 6750 Section 3).
func ParseWWWAuthenticate(value string) (errCode, errDesc, errURI string) {
	for _, match := range wwwAuthParamRe.FindAllStringSubmatch(value, -1) {
		switch match[1] {
		case "error":
			errCode = match[2]
		case "error_description":
			errDesc = match[2]
		case "error_uri":
			errURI = match[2]
		}
	}
	return
}

// DetectContentLanguage returns Prism.js language class based on Content-Type.
// Returns "json", "markup" (XML/HTML), or "" (plain).
func DetectContentLanguage(contentType string) string {
	ct, _, _ := mime.ParseMediaType(contentType)
	switch {
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		return "json"
	case ct == "application/xml" || ct == "text/xml" || strings.HasSuffix(ct, "+xml") || ct == "text/html":
		return "markup"
	default:
		return ""
	}
}
