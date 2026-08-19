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
//
// This is a single-role shorthand for RequireRealmRoles(false, role).
func RequireRealmRole(role string) gin.HandlerFunc {
	return RequireRealmRoles(false, role)
}

// RequireRealmRoles is the multi-role form of RequireRealmRole. With
// requireAll=false the caller needs ANY one of the listed roles (OR);
// with requireAll=true the caller needs EVERY listed role (AND). Same cheap
// path as RequireRealmRole — no network call, just the already-validated
// realm_access.roles claim.
func RequireRealmRoles(requireAll bool, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth middleware not run before rbac check"})
			return
		}

		held := make(map[string]bool, len(claims.RealmAccess.Roles))
		for _, r := range claims.RealmAccess.Roles {
			held[r] = true
		}

		granted := false
		if requireAll {
			granted = true
			for _, role := range roles {
				if !held[role] {
					granted = false
					break
				}
			}
		} else {
			for _, role := range roles {
				if held[role] {
					granted = true
					break
				}
			}
		}

		if granted {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":          "forbidden",
			"reason":         "rbac",
			"required_roles": roles,
			"require_all":    requireAll,
		})
	}
}
