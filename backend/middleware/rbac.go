package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRealmRole implements plain RBAC (access-control model #1 in
// CLAUDE.md). It's the "cheap path": no network call to Keycloak, since the
// role list is already embedded in the validated access token's
// realm_access.roles claim. Use this for checks that don't depend on
// resource attributes — e.g. "can this user reach the admin section at
// all", as opposed to "can this user act on THIS specific tagged resource"
// (that's ABAC — see abac.go).
func RequireRealmRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth middleware not run before rbac check"})
			return
		}

		for _, r := range claims.RealmAccess.Roles {
			if r == role {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":         "forbidden",
			"reason":        "rbac",
			"required_role": role,
		})
	}
}
