package config

import (
	"os"
)

// Config holds every environment-derived setting the backend needs.
// No magic defaults for security-relevant values in production — but for
// this learning sandbox we fall back to the docker-compose defaults so the
// service boots with zero setup.
type Config struct {
	Port string

	KeycloakBaseURL string // e.g. http://localhost:8180
	KeycloakRealm   string // e.g. demo-realm
	ClientID        string // this backend's own confidential client ID
	ClientSecret    string // this backend's own confidential client secret

	CORSOrigin string
}

func Load() Config {
	return Config{
		Port: getenv("PORT", "9090"),

		KeycloakBaseURL: getenv("KEYCLOAK_BASE_URL", "http://localhost:8180"),
		KeycloakRealm:   getenv("KEYCLOAK_REALM", "demo-realm"),
		ClientID:        getenv("KEYCLOAK_CLIENT_ID", "kc-lab-backend"),
		ClientSecret:    getenv("KEYCLOAK_CLIENT_SECRET", ""),

		CORSOrigin: getenv("CORS_ORIGIN", "http://localhost:5273"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
