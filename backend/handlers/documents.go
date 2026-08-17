package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/rezaif/kc-lab-backend/middleware"
)

// Document is a stand-in for a real app-db row. In a full build this would
// come from Postgres (app-db, port 5533) with a keycloak_resource_id column
// linking it to the matching Keycloak Resource — see CLAUDE.md §3.
type Document struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Department string `json:"department"`
	Owner      string `json:"owner"`
}

var seedDocuments = map[string]Document{
	"invoice-1": {ID: "invoice-1", Title: "Q3 Invoice", Department: "finance", Owner: "alice"},
	"invoice-2": {ID: "invoice-2", Title: "Q4 Invoice", Department: "finance", Owner: "bob"},
}

// ListDocuments — gated purely by RBAC (middleware.RequireRealmRole).
// Reaching this handler already means the role check passed; no further
// per-row filtering demonstrated here on purpose, to keep the RBAC demo
// isolated from the ABAC demo below.
func ListDocuments(c *gin.Context) {
	docs := make([]Document, 0, len(seedDocuments))
	for _, d := range seedDocuments {
		docs = append(docs, d)
	}
	c.JSON(http.StatusOK, gin.H{"documents": docs})
}

// GetDocument — gated by ABAC/resource-based permission
// (middleware.RequireResourcePermission), which already ran before this
// handler executes. If we're here, Keycloak has confirmed the caller's
// department attribute matches this document's department tag.
func GetDocument(c *gin.Context) {
	id := c.Param("id")
	doc, ok := seedDocuments[id]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "document not found"})
		return
	}
	c.JSON(http.StatusOK, doc)
}

// ShareDocument — demonstrates ReBAC/DAC (#3 and #5): only the resource's
// owner may grant access to someone else, checked via UMA against the
// resource's registered `owner` attribute (see middleware.RequireResourcePermission
// wired with the "share" scope in main.go).
func ShareDocument(c *gin.Context) {
	id := c.Param("id")
	claims, _ := middleware.ClaimsFromContext(c)

	c.JSON(http.StatusOK, gin.H{
		"message":   "share permission granted by resource owner",
		"document":  id,
		"granted_by": claims.PreferredUsername,
	})
}
