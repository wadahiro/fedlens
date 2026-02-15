package protocol

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// IsJWT returns true if the string has the 3-part JWT structure.
func IsJWT(s string) bool {
	return strings.Count(s, ".") == 2
}

// DecodeJWT decodes a JWT's header, payload, and signature.
// Header and payload are pretty-printed JSON; signature is the raw base64url string.
func DecodeJWT(token string) (header, payload, signature string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return token, "", ""
	}
	header = decodeBase64URL(parts[0])
	payload = decodeBase64URL(parts[1])
	if len(parts) == 3 {
		signature = parts[2]
	}
	return
}

// DecodeJWTRaw decodes a JWT's header and payload as raw bytes.
func DecodeJWTRaw(token string) (header, payload []byte) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return []byte(token), nil
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	return h, p
}

// ExtractJWTHeaderInfo extracts the algorithm and key ID from a JWT header.
func ExtractJWTHeaderInfo(jwtRaw string) (alg, kid string) {
	headerRaw, _ := DecodeJWTRaw(jwtRaw)
	if headerRaw == nil {
		return
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) == nil {
		alg = header.Alg
		kid = header.Kid
	}
	return
}

// JWTSignatureInfo holds JWT signature verification details.
type JWTSignatureInfo struct {
	Algorithm string // JWT header alg (e.g. "RS256")
	KeyID     string // JWT header kid
	KeyType   string // JWKS kty (e.g. "RSA")
	KeyUse    string // JWKS use (e.g. "sig")
	KeyAlg    string // JWKS alg
	Verified  bool
}

// BuildJWTSignatureInfo extracts signature info from a JWT and JWKS.
func BuildJWTSignatureInfo(jwtRaw string, jwksRaw json.RawMessage, verified bool) *JWTSignatureInfo {
	alg, kid := ExtractJWTHeaderInfo(jwtRaw)
	if alg == "" {
		return nil
	}
	info := &JWTSignatureInfo{
		Algorithm: alg,
		KeyID:     kid,
		Verified:  verified,
	}
	if len(jwksRaw) > 0 && kid != "" {
		var jwks struct {
			Keys []struct {
				Kid string `json:"kid"`
				Kty string `json:"kty"`
				Use string `json:"use"`
				Alg string `json:"alg"`
			} `json:"keys"`
		}
		if json.Unmarshal(jwksRaw, &jwks) == nil {
			for _, k := range jwks.Keys {
				if k.Kid == kid {
					info.KeyType = k.Kty
					info.KeyUse = k.Use
					info.KeyAlg = k.Alg
					break
				}
			}
		}
	}
	return info
}

// JWKSKeyInfo holds structured metadata for a single JWKS key.
type JWKSKeyInfo struct {
	Kid string
	Kty string
	Alg string
	Use string
}

// ParseJWKSKeys extracts key metadata from raw JWKS JSON.
func ParseJWKSKeys(jwksRaw json.RawMessage) []JWKSKeyInfo {
	if len(jwksRaw) == 0 {
		return nil
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if json.Unmarshal(jwksRaw, &jwks) != nil {
		return nil
	}
	var result []JWKSKeyInfo
	for _, k := range jwks.Keys {
		result = append(result, JWKSKeyInfo{
			Kid: k.Kid,
			Kty: k.Kty,
			Alg: k.Alg,
			Use: k.Use,
		})
	}
	return result
}

// MarshalTokenFields builds a JSON representation of relevant token fields.
func MarshalTokenFields(fields map[string]any) json.RawMessage {
	b, _ := json.Marshal(fields)
	return b
}

func decodeBase64URL(s string) string {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return PrettyJSON(json.RawMessage(b))
}
