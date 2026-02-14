package protocol

import (
	"net/url"
	"sort"
)

// ParseURLParams parses a URL or query string into sorted key-value pairs.
// It handles both full URLs (with ?) and bare query strings (key=value&...).
// Returns nil if the input is empty or unparseable.
func ParseURLParams(raw string) []KeyValue {
	if raw == "" {
		return nil
	}

	var values url.Values
	// Try parsing as full URL first
	if u, err := url.Parse(raw); err == nil && u.RawQuery != "" {
		values = u.Query()
	} else {
		// Try as bare query string
		var err error
		values, err = url.ParseQuery(raw)
		if err != nil || len(values) == 0 {
			return nil
		}
	}

	if len(values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make([]KeyValue, 0, len(keys))
	for _, k := range keys {
		for _, v := range values[k] {
			result = append(result, KeyValue{Key: k, Value: v})
		}
	}
	return result
}

// KeyValue represents a parsed URL parameter.
type KeyValue struct {
	Key   string
	Value string
}
