# fedlens

A federation protocol debug tool for OIDC and SAML.

## Project Overview

fedlens is a single Go binary that acts as both an **OIDC Relying Party** and a **SAML Service Provider**, displaying raw protocol details in a web UI for debugging and development purposes.

## Architecture

- **Single file**: `main.go` contains all logic
- **Host-based routing**: Routes requests by `Host` header to OIDC or SAML handler
- **No database**: Sessions stored in-memory maps with mutex protection
- **No framework**: Uses only `net/http` stdlib

### Key functions

- `setupOIDC(httpClient)` - Configures OIDC RP, discovery, login/callback/logout handlers
- `setupSAML(httpClient)` - Configures SAML SP, metadata fetch, ACS/login/logout handlers
- `main()` - Wires everything together with host-based routing

### Dependencies

- `github.com/coreos/go-oidc/v3` - OIDC provider discovery and token verification
- `github.com/crewjam/saml` + `samlsp` - SAML SP implementation
- `github.com/beevik/etree` - XML tree manipulation (AuthnRequest serialization, signature parsing)
- `golang.org/x/oauth2` - OAuth2 token exchange

## Conventions

- **Go version**: 1.26+, use modern Go idioms (`var`, `range` over int, etc.)
- **Commit messages**: English, semantic prefix (`test:`, `fix:`, `feat:`, `chore:` etc.)
- **Configuration**: All via environment variables (see README.md)

## Development

```bash
# Build
go build -o fedlens .

# Docker build
docker build -t fedlens .
```

## Current State

### Implemented

- OIDC: Authorization Code Flow, ID Token / Access Token claims display, signature verification, UserInfo, JWKS, Discovery metadata
- SAML: SP-initiated SSO (HTTP-Redirect and HTTP-POST bindings), attributes display, signature verification (Response/Assertion level), AuthnRequest/Response XML display, IdP Metadata
- Navigation tabs between OIDC and SAML views
- Pre-login screens show Discovery metadata (OIDC) and IdP Metadata (SAML)
- SP-initiated Single Logout (OIDC and SAML)
- Self-signed certificate generation for SAML SP

### Future Ideas

- Make it more generic/reusable as an OSS tool
- Improve UI (CSS styling, collapsible sections)
- Support multiple IdP configurations
- Add OIDC PKCE support
- Add token refresh flow display
- Add SAML IdP-initiated SSO support
