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
func RequireResourcePermission(uma *keycloak.UMAClient, scope string, resourceNameFn func(c *gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawToken, ok := RawTokenFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth middleware not run before abac check"})
			return
		}

		resourceName := resourceNameFn(c)

		allowed, err := uma.CheckPermission(rawToken, resourceName, scope)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
				"error":  "authorization check failed",
				"detail": fmt.Sprintf("%v", err),
			})
			return
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":    "forbidden",
				"reason":   "abac/resource-policy",
				"resource": resourceName,
				"scope":    scope,
			})
			return
		}

		c.Next()
	}
}
