package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/rezaif/kc-lab-backend/pkg/keycloak"
)

// RequireResourcePermission implements the "expensive but authoritative"
// path: ABAC (#2), ReBAC/ownership (#3), and resource-based policies (#9)
// in CLAUDE.md all funnel through here, because all three need Keycloak to
// evaluate live resource attributes (department tag, owner, etc.) that
// aren't present in the access token itself.
//
// resourceNameFn lets the caller build the Keycloak resource name from the
// request (e.g. "document:" + c.Param("id")), since it varies per route.
//
// This is the single-pair shorthand for RequireResourcePermissions.
func RequireResourcePermission(uma *keycloak.UMAClient, scope string, resourceNameFn func(c *gin.Context) string) gin.HandlerFunc {
	return RequireResourcePermissions(uma, false, PermissionSpec{Scope: scope, ResourceFn: resourceNameFn})
}

// PermissionSpec describes one (resource, scope) pair to check for a route.
// The resource name is resolved per request because it usually comes from a
// path parameter, while the scope is fixed at wiring time.
type PermissionSpec struct {
	Scope      string
	ResourceFn func(c *gin.Context) string
}

// RequireResourcePermissions is the multi-pair form of
// RequireResourcePermission. With requireAll=false the caller needs ANY one
// of the listed (resource, scope) pairs; with requireAll=true they need all
// of them.
//
// Every pair is evaluated in a single UMA round trip, so adding checks costs
// nothing beyond a slightly larger form body — the latency is in the call
// itself. On denial the 403 body names exactly which pairs failed, so the
// demo pages can show the boundary instead of a generic error.
func RequireResourcePermissions(uma *keycloak.UMAClient, requireAll bool, specs ...PermissionSpec) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawToken, ok := RawTokenFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth middleware not run before abac check"})
			return
		}

		perms := make([]keycloak.Permission, 0, len(specs))
		for _, s := range specs {
			perms = append(perms, keycloak.Permission{Resource: s.ResourceFn(c), Scope: s.Scope})
		}

		decision, err := uma.Evaluate(rawToken, perms...)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
				"error":  "authorization check failed",
				"detail": fmt.Sprintf("%v", err),
			})
			return
		}

		if !decision.Allowed(requireAll) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":       "forbidden",
				"reason":      "abac/resource-policy",
				"require_all": requireAll,
				"requested":   formatPermissions(perms),
				"denied":      formatPermissions(decision.Denied),
			})
			return
		}

		c.Next()
	}
}

func formatPermissions(perms []keycloak.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p.String())
	}
	return out
}
