package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/getfider/fider/app/pkg/errors"
)

// jsonWebKey is a single key from a JWKS document (RFC 7517).
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// ParseJWKS parses a JWKS document into public keys indexed by key ID.
// RSA and EC keys are supported; keys that cannot be used for id_token
// verification (unknown type, encryption-only, malformed) are skipped.
// An error is returned only when the document is invalid or contains no usable key.
func ParseJWKS(body []byte) (map[string]crypto.PublicKey, error) {
	var keySet jsonWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, errors.Wrap(err, "failed to parse JWKS document")
	}

	keys := make(map[string]crypto.PublicKey)
	for _, key := range keySet.Keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}

		publicKey := parseJSONWebKey(key)
		if publicKey == nil {
			continue
		}

		keys[key.Kid] = publicKey
	}

	if len(keys) == 0 {
		return nil, errors.New("JWKS document contains no usable signing keys")
	}

	return keys, nil
}

func parseJSONWebKey(key jsonWebKey) crypto.PublicKey {
	switch key.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil
		}
		if len(n) == 0 || len(e) == 0 {
			return nil
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
	case "EC":
		var curve elliptic.Curve
		switch key.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil
		}
		x, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil
		}
		y, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			return nil
		}
		if len(x) == 0 || len(y) == 0 {
			return nil
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
	}
	return nil
}
