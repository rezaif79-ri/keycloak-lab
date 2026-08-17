package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/rezaif/kc-lab-backend/pkg/keycloak"
)

const claimsContextKey = "claims"

// Claims is the subset of a Keycloak access token's payload this backend
// cares about. `realm_access.roles` backs RBAC (§4 middleware/rbac.go);
// `sub`/`preferred_username` back ABAC/ReBAC ownership checks.
type Claims struct {
	jwt.RegisteredClaims
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	RealmAccess       struct{ Roles []string } `json:"realm_access"`
}

// RequireAuth validates the bearer token's signature (via Keycloak's JWKS),
// expiry, issuer, and audience, then stashes the parsed claims in context
// for downstream handlers/middleware. It does NOT check roles or scopes —
// that's deliberately layered on separately (see rbac.go / abac.go) so each
// access-control model stays independently testable.
func RequireAuth(jwks *keycloak.JWKSCache, expectedIssuer string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		rawToken := strings.TrimPrefix(header, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
			kid, ok := t.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("token missing kid header")
			}
			return jwks.Key(kid)
		}, jwt.WithValidMethods([]string{"RS256"}))

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "detail": err.Error()})
			return
		}

		if claims.Issuer != expectedIssuer {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unexpected token issuer"})
			return
		}

		// Also stash the raw token string — needed later to exchange for a
		// UMA ticket (the exchange call must present the user's own token).
		c.Set(claimsContextKey, claims)
		c.Set("raw_token", rawToken)
		c.Next()
	}
}

// ClaimsFromContext retrieves the claims stashed by RequireAuth. Callers in
// handlers/middleware should always check `ok` — this only returns false if
// RequireAuth wasn't run first, which is a wiring bug, not a runtime state
// to silently tolerate.
func ClaimsFromContext(c *gin.Context) (*Claims, bool) {
	v, ok := c.Get(claimsContextKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*Claims)
	return claims, ok
}

func RawTokenFromContext(c *gin.Context) (string, bool) {
	v, ok := c.Get("raw_token")
	if !ok {
		return "", false
	}
	tok, ok := v.(string)
	return tok, ok
}
