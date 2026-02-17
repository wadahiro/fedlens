# fedlens

A federation protocol debug tool for OIDC, OAuth2, and SAML.

## Project Overview

fedlens is a single Go binary that acts as an **OIDC Relying Party**, **OAuth2 Client**, and **SAML Service Provider**, displaying raw protocol details in a web UI for debugging and development purposes.

## Architecture

- **Modular packages**: `internal/config`, `internal/protocol`, `internal/oidc`, `internal/saml`, `internal/ui`
- **Host+Path routing**: Routes requests by `Host` header and URL path prefix based on `base_url` configuration
  - **Host-based**: `base_url = "http://oidc.example.com:3000"` (no path) → routes by host only
  - **Path-based**: `base_url = "http://localhost:3000/keycloak"` → routes by host + path prefix
  - Both modes can be mixed in the same configuration
- **Multiple SP/RP**: TOML configuration allows defining multiple `[[oidc]]`, `[[oauth2]]`, and `[[saml]]` entries, each with its own `base_url`, session store, and IdP connection
- **No database**: Sessions stored in-memory maps with mutex protection
- **No framework**: Uses only `net/http` stdlib
- **UI stack**: templ (type-safe HTML) + htmx 2.0.7 + Pico CSS 2.1.1 + Prism.js 1.30.0, all embedded via `go:embed`

### Key packages

- `main.go` - Entry point: config loading, logger setup, handler initialization, host+path routing, graceful shutdown
- `internal/config/` - TOML configuration loading with environment variable fallback
- `internal/protocol/` - Shared utilities: JWT decode, XML formatting, SAML signature extraction, crypto helpers
- `internal/oidc/` - OIDC RP and OAuth2 Client handlers (login, callback, logout, refresh, introspection), session management
- `internal/saml/` - SAML SP handlers (login, ACS, logout, metadata), session management, certificate handling
- `internal/ui/` - Static assets (`go:embed`) and templ templates

### Dependencies

- `github.com/a-h/templ` - Type-safe HTML templating
- `github.com/BurntSushi/toml` - TOML configuration parser
- `github.com/coreos/go-oidc/v3` - OIDC provider discovery and token verification
- `github.com/crewjam/saml` + `samlsp` - SAML SP implementation
- `github.com/beevik/etree` - XML tree manipulation
- `golang.org/x/oauth2` - OAuth2 token exchange

## Configuration: `base_url` and Path Routing

Each `[[oidc]]`, `[[oauth2]]`, and `[[saml]]` entry requires a `base_url` field (scheme + host + optional path):

- **Host-based**: `base_url = "http://oidc.example.com:3000"` → traditional host-based routing
- **Path-based**: `base_url = "http://localhost:3000/myapp"` → path-prefix routing on same host

When `base_url` includes a path, SAML endpoint paths (`acs_path`, `slo_path`, `metadata_path`) and OIDC `callback_path` are **appended** to the base path:
- Example: `base_url = "http://localhost:3000/myapp"` + `acs_path = "/saml/acs"` → `http://localhost:3000/myapp/saml/acs`

## Conventions

- **Go version**: 1.26+, use modern Go idioms (`var`, `range` over int, etc.)
- **Commit messages**: English, semantic prefix (`test:`, `fix:`, `feat:`, `chore:` etc.)
- **Configuration**: TOML file (via `CONFIG_FILE` env var) or environment variables (legacy mode)

## Development

```bash
# Build (templ generate + go build)
make build

# Development mode (generate + run)
make dev

# Unit tests
make test

# E2E tests (Playwright, requires Docker)
make e2e

# Clean
make clean
```

## Current State

### Implemented

- OIDC: Authorization Code Flow with PKCE support, custom scopes, extra auth params, response mode
- OIDC: ID Token / Access Token claims display, signature verification, UserInfo, JWKS, Discovery metadata
- OIDC: Token Refresh Flow with UI button
- OIDC/OAuth2: Token Introspection (RFC 7662) with HTTP capture
- OAuth2: Authorization Code Flow with PKCE support (reuses OIDC handler with isOAuth2 flag)
- OAuth2: RFC 8414 Discovery or manual endpoint configuration
- OAuth2: Access Token claims display (JWT), signature verification, Token Refresh
- SAML: SP-initiated SSO (HTTP-Redirect and HTTP-POST bindings) and IdP-initiated SSO
- SAML: Attributes display, signature verification (Response/Assertion level), AuthnRequest/Response XML display
- SAML: External certificate loading or auto-generated self-signed cert
- Multiple SP/RP via TOML configuration with tab navigation
- Pico CSS dark mode toggle, Prism.js syntax highlighting, copy buttons, collapsible sections
- SVG sequence diagrams for OIDC and SAML flows
- Structured logging (log/slog), graceful shutdown
- Unit tests (config, protocol/jwt, protocol/crypto)
- E2E test suite (Playwright: Chromium/Firefox/WebKit)
