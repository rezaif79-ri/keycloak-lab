package main

import (
	"fmt"
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/rezaif/kc-lab-backend/config"
	"github.com/rezaif/kc-lab-backend/handlers"
	"github.com/rezaif/kc-lab-backend/middleware"
	"github.com/rezaif/kc-lab-backend/pkg/keycloak"
)

func main() {
	_ = godotenv.Load() // fine if missing — config falls back to compose defaults

	cfg := config.Load()

	jwks := keycloak.NewJWKSCache(cfg.KeycloakBaseURL, cfg.KeycloakRealm)
	issuer := fmt.Sprintf("%s/realms/%s", cfg.KeycloakBaseURL, cfg.KeycloakRealm)
	uma := keycloak.NewUMAClient(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.ClientID)

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.CORSOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	r.GET("/health", handlers.Health)

	authRequired := middleware.RequireAuth(jwks, issuer)

	api := r.Group("/api", authRequired)
	{
		// #1 RBAC — any authenticated user with the `document-viewer` role.
		api.GET("/documents",
			middleware.RequireRealmRoles(false, []string{"document-viewer", "document-admin"}...),
			handlers.ListDocuments,
		)

		// #2/#9 ABAC + resource-based permission — Keycloak checks the
		// caller's `department` attribute against this document's
		// `department` tag via a live UMA ticket exchange.
		api.GET("/documents/:id",
			middleware.RequireResourcePermission(uma, "document:GetObject", func(c *gin.Context) string {
				return "document:" + c.Param("id")
			}),
			handlers.GetDocument,
		)

		// #3/#5 ReBAC + DAC — only the resource owner can share; Keycloak
		// evaluates a policy that compares the caller to the resource's
		// registered owner attribute.
		api.POST("/documents/:id/share",
			middleware.RequireResourcePermission(uma, "document:Admin", func(c *gin.Context) string {
				return "document:" + c.Param("id")
			}),
			handlers.ShareDocument,
		)
	}

	addr := ":" + cfg.Port
	log.Printf("kc-lab-backend listening on %s (keycloak realm %s at %s)", addr, cfg.KeycloakRealm, cfg.KeycloakBaseURL)
	if err := r.Run(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
