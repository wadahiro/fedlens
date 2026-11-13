package saml

import (
	samlpkg "github.com/crewjam/saml"

	"github.com/wadahiro/fedlens/internal/config"
)

// applyAuthRequest shapes a freshly generated AuthnRequest according to opts.
// Anything opts leaves unset keeps what crewjam generated, so a config without
// auth_request sends the same request as before.
func applyAuthRequest(req *samlpkg.AuthnRequest, opts config.SAMLAuthRequestConfig) {
	applyNameIDPolicy(req, opts)

	if opts.SubjectNameID != "" {
		req.Subject = &samlpkg.Subject{
			NameID: &samlpkg.NameID{
				Format: opts.SubjectNameIDFormat,
				Value:  opts.SubjectNameID,
			},
		}
	}

	if opts.ForceAuthn != nil {
		req.ForceAuthn = opts.ForceAuthn
	}
	if opts.IsPassive != nil {
		req.IsPassive = opts.IsPassive
	}

	if opts.AuthnContextClassRef != "" {
		req.RequestedAuthnContext = &samlpkg.RequestedAuthnContext{
			Comparison:           "exact",
			AuthnContextClassRef: opts.AuthnContextClassRef,
		}
	}
}

func applyNameIDPolicy(req *samlpkg.AuthnRequest, opts config.SAMLAuthRequestConfig) {
	if opts.OmitNameIDPolicy != nil && *opts.OmitNameIDPolicy {
		req.NameIDPolicy = nil
		return
	}
	if req.NameIDPolicy == nil {
		req.NameIDPolicy = &samlpkg.NameIDPolicy{}
	}
	if opts.NameIDFormat != "" {
		format := opts.NameIDFormat
		req.NameIDPolicy.Format = &format
	}
	if opts.AllowCreate != nil {
		req.NameIDPolicy.AllowCreate = opts.AllowCreate
	}
	if opts.SPNameQualifier != "" {
		qualifier := opts.SPNameQualifier
		req.NameIDPolicy.SPNameQualifier = &qualifier
	}
}

// omitSettings removes from the request the settings the user emptied. Settings that
// are simply unset are already absent; the two the SAML library fills in by itself
// when they are unset (the NameIDPolicy's Format and AllowCreate) have to be taken
// out explicitly, or emptying the field would still send them.
func omitSettings(req *samlpkg.AuthnRequest, names []string) {
	if req.NameIDPolicy == nil {
		return
	}
	for _, name := range names {
		switch name {
		case fieldNameIDFormat:
			req.NameIDPolicy.Format = nil
		case fieldAllowCreate:
			req.NameIDPolicy.AllowCreate = nil
		}
	}
}
