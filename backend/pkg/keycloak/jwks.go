package keycloak

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwk mirrors the subset of a JSON Web Key we need to reconstruct an RSA
// public key from Keycloak's certs endpoint.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// JWKSCache fetches and caches Keycloak's signing keys, refreshing them on a
// fixed interval so a key rotation on the Keycloak side doesn't require a
// backend restart.
type JWKSCache struct {
	url string

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	lastFet time.Time
	ttl     time.Duration

	httpClient *http.Client
}

func NewJWKSCache(baseURL, realm string) *JWKSCache {
	return &JWKSCache{
		url:        fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", baseURL, realm),
		keys:       make(map[string]*rsa.PublicKey),
		ttl:        10 * time.Minute,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// Key returns the RSA public key for the given kid, refreshing the cache
// from Keycloak if it's stale or the kid isn't known yet.
func (c *JWKSCache) Key(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := time.Since(c.lastFet) > c.ttl
	c.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	if err := c.refresh(); err != nil {
		if ok {
			// Serve the stale key rather than fail hard if Keycloak is
			// briefly unreachable but we already know this kid.
			return key, nil
		}
		return nil, fmt.Errorf("refreshing jwks: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok = c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("no jwk found for kid %q", kid)
	}
	return key, nil
}

func (c *JWKSCache) refresh() error {
	resp, err := c.httpClient.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetching jwks from %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var parsed jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("decoding jwks response: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey, len(parsed.Keys))
	for _, k := range parsed.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(k)
		if err != nil {
			return fmt.Errorf("parsing jwk %s: %w", k.Kid, err)
		}
		newKeys[k.Kid] = pubKey
	}

	c.mu.Lock()
	c.keys = newKeys
	c.lastFet = time.Now()
	c.mu.Unlock()

	return nil
}

func jwkToRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
