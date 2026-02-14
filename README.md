# fedlens

A federation protocol debug tool for OIDC and SAML. fedlens acts as both an **OpenID Connect Relying Party** and a **SAML Service Provider**, displaying the raw protocol details at every layer in a single web UI.

## Features

### OIDC (OpenID Connect)

- **ID Token Claims** table with timestamp formatting
- **Access Token Claims** table (when JWT)
- **UserInfo Claims** table
- **Signature Verification** details for ID Token and Access Token (algorithm, key ID, JWKS key info)
- **Authorization Request / Response** raw display
- **Token Response** (full JSON)
- **ID Token / Access Token** decoded header and payload
- **UserInfo Response** (full JSON)
- **JWKS Response** (full JSON)
- **OpenID Provider Configuration** (discovery metadata)

### SAML

- **Attributes** table
- **Signature Verification** details for Response and Assertion (algorithm, digest, certificate info, fingerprint)
- **AuthnRequest XML** (formatted)
- **SAML Response XML** (formatted)
- **IdP Metadata** (formatted XML)

### General

- Navigation tabs to switch between OIDC and SAML views
- All protocol data visible on both pre-login and post-login screens
- Single binary, Docker-ready

## Quick Start

### Docker

```bash
docker build -t fedlens .
docker run -p 3000:3000 \
  -e OIDC_HOST=test-oidc.example.com \
  -e SAML_HOST=test-saml.example.com \
  -e OIDC_ISSUER=https://your-idp.example.com/realms/master \
  -e OIDC_CLIENT_ID=your-client-id \
  -e OIDC_CLIENT_SECRET=your-client-secret \
  -e OIDC_REDIRECT_URI=https://test-oidc.example.com/callback \
  -e SAML_IDP_METADATA_URL=https://your-idp.example.com/realms/master/protocol/saml/descriptor \
  -e SAML_ENTITY_ID=https://test-saml.example.com/saml/metadata \
  -e SAML_ROOT_URL=https://test-saml.example.com \
  fedlens
```

### Build from source

```bash
go build -o fedlens .
```

## Configuration

All configuration is done via environment variables.

| Variable | Required | Description |
|---|---|---|
| `OIDC_HOST` | Yes | Hostname for OIDC requests (e.g. `test-oidc.example.com`) |
| `SAML_HOST` | Yes | Hostname for SAML requests (e.g. `test-saml.example.com`) |
| `OIDC_ISSUER` | Yes | OIDC Issuer URL |
| `OIDC_CLIENT_ID` | Yes | OIDC Client ID |
| `OIDC_CLIENT_SECRET` | Yes | OIDC Client Secret |
| `OIDC_REDIRECT_URI` | Yes | OIDC Redirect URI (callback URL) |
| `SAML_IDP_METADATA_URL` | Yes | SAML IdP Metadata URL |
| `SAML_ENTITY_ID` | Yes | SAML SP Entity ID |
| `SAML_ROOT_URL` | Yes | SAML SP Root URL |
| `LISTEN_ADDR` | No | Listen address (default: `:3000`) |
| `INSECURE_SKIP_VERIFY` | No | Skip TLS certificate verification (default: `false`) |

## How It Works

fedlens runs a single HTTP server that routes requests based on the `Host` header:

- Requests to `OIDC_HOST` are handled by the OIDC Relying Party
- Requests to `SAML_HOST` are handled by the SAML Service Provider

On startup, fedlens fetches OIDC discovery metadata and SAML IdP metadata, making them available on the pre-login screen. After authentication, all protocol exchange details (tokens, assertions, signatures) are displayed.

## License

Apache License 2.0
