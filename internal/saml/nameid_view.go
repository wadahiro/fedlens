package saml

import (
	"github.com/wadahiro/fedlens/internal/protocol"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

const nameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

// nameIDRows describes the NameID the IdP returned and sets it beside what the
// AuthnRequest asked for. An IdP is free to ignore the request (the spec lets it
// answer with another format, or an error only when it cannot satisfy it), so the
// comparison is the point: it shows whether the requested format was honoured.
func nameIDRows(authnRequestXML, responseXML string) []components.ClaimRow {
	got, ok := protocol.ExtractSAMLNameID(responseXML)
	if !ok {
		return nil
	}
	var rows []components.ClaimRow
	add := func(k, v string) {
		if v != "" {
			rows = append(rows, components.ClaimRow{Key: k, Value: v})
		}
	}
	add("NameID", got.Value)
	format := got.Format
	if format == "" {
		// An absent Format means unspecified (SAML 2.0 Core 2.2.2).
		format = nameIDFormatUnspecified + " (Format omitted)"
	}
	add("Format", format)
	add("NameQualifier", got.NameQualifier)
	add("SPNameQualifier", got.SPNameQualifier)
	add("SPProvidedID", got.SPProvidedID)

	if authnRequestXML == "" {
		return rows
	}
	want := protocol.ExtractSAMLNameIDPolicy(authnRequestXML)
	switch {
	case !want.Present:
		add("Requested", "no NameIDPolicy was sent; the IdP chose the format")
	case want.Format == "":
		add("Requested", "NameIDPolicy without Format; the IdP chose the format")
	default:
		add("Requested", want.Format)
		received := got.Format
		if received == "" {
			received = nameIDFormatUnspecified
		}
		if received == want.Format {
			add("Result", "matches the requested Format")
		} else {
			add("Result", "differs from the requested Format")
		}
	}
	if want.SPNameQualifier != "" {
		add("Requested SPNameQualifier", want.SPNameQualifier)
		if got.SPNameQualifier == want.SPNameQualifier {
			add("SPNameQualifier result", "matches the requested SPNameQualifier")
		} else {
			add("SPNameQualifier result", "differs from the requested SPNameQualifier")
		}
	}
	return rows
}
