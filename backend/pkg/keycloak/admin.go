package keycloak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AdminClient talks to Keycloak's Admin REST API. It exists only to manage
// realm configuration (roles, groups, and the Authorization Services objects
// that back CLAUDE.md's access-control models) — the request-path code in
// uma.go and jwks.go never touches it.
//
// Admin credentials authenticate against the master realm via admin-cli,
// while Realm names the realm being managed; those are usually different.
type AdminClient struct {
	baseURL string
	realm   string

	adminRealm string
	clientID   string
	username   string
	password   string

	httpClient *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func NewAdminClient(baseURL, realm, username, password string) *AdminClient {
	return &AdminClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		realm:      realm,
		adminRealm: "master",
		clientID:   "admin-cli",
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// accessToken returns a cached admin token, refreshing it shortly before it
// expires. Keycloak's master-realm admin tokens are short-lived (60s by
// default), which is far shorter than a full sync run takes.
func (c *AdminClient) accessToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", c.clientID)
	form.Set("username", c.username)
	form.Set("password", c.password)

	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.adminRealm)
	resp, err := c.httpClient.PostForm(endpoint, form)
	if err != nil {
		return "", fmt.Errorf("requesting admin token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("admin token request returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decoding admin token response: %w", err)
	}

	c.token = tok.AccessToken
	// Refresh with a margin so a long-running sync never uses a stale token.
	c.tokenExp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-10 * time.Second)
	return c.token, nil
}

// do issues an authenticated Admin API request. path is relative to the
// managed realm, e.g. "clients?clientId=kc-lab-backend". A nil out skips
// response decoding, which suits the many endpoints returning 201/204.
func (c *AdminClient) do(method, path string, in, out any) error {
	token, err := c.accessToken()
	if err != nil {
		return err
	}

	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding %s %s body: %w", method, path, err)
		}
		body = bytes.NewReader(encoded)
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/%s", c.baseURL, c.realm, path)
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return fmt.Errorf("building %s %s request: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding %s %s response: %w", method, path, err)
	}
	return nil
}

func (c *AdminClient) get(path string, out any) error { return c.do(http.MethodGet, path, nil, out) }
func (c *AdminClient) post(path string, in any) error { return c.do(http.MethodPost, path, in, nil) }
func (c *AdminClient) put(path string, in any) error  { return c.do(http.MethodPut, path, in, nil) }
func (c *AdminClient) delete(path string) error       { return c.do(http.MethodDelete, path, nil, nil) }

// namedRef is the shape Keycloak returns for most lookups: an internal UUID
// plus the human-facing name that config files reference instead.
type namedRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ResourceServerID resolves a client's clientId (e.g. "kc-lab-backend") to
// the internal UUID that every Authorization Services path is keyed by.
func (c *AdminClient) ResourceServerID(clientID string) (string, error) {
	var clients []struct {
		ID                           string `json:"id"`
		ClientID                     string `json:"clientId"`
		AuthorizationServicesEnabled bool   `json:"authorizationServicesEnabled"`
	}
	if err := c.get("clients?clientId="+url.QueryEscape(clientID), &clients); err != nil {
		return "", fmt.Errorf("looking up client %q: %w", clientID, err)
	}
	if len(clients) == 0 {
		return "", fmt.Errorf("client %q not found in realm %q", clientID, c.realm)
	}
	if !clients[0].AuthorizationServicesEnabled {
		return "", fmt.Errorf("client %q does not have Authorization Services enabled", clientID)
	}
	return clients[0].ID, nil
}

// RealmRoleIDs maps realm role names to their UUIDs.
func (c *AdminClient) RealmRoleIDs() (map[string]string, error) {
	var roles []namedRef
	if err := c.get("roles?max=1000", &roles); err != nil {
		return nil, fmt.Errorf("listing realm roles: %w", err)
	}
	out := make(map[string]string, len(roles))
	for _, r := range roles {
		out[r.Name] = r.ID
	}
	return out, nil
}

// GroupPaths returns the set of group paths that exist in the realm,
// including nested ones.
func (c *AdminClient) GroupPaths() (map[string]string, error) {
	var groups []struct {
		ID      string `json:"id"`
		Path    string `json:"path"`
		SubGrps []struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		} `json:"subGroups"`
	}
	if err := c.get("groups?max=1000", &groups); err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}
	out := make(map[string]string, len(groups))
	for _, g := range groups {
		out[g.Path] = g.ID
		for _, sub := range g.SubGrps {
			out[sub.Path] = sub.ID
		}
	}
	return out, nil
}

// UserID resolves a username to its UUID. User Policies reference users by
// UUID, so a missing user has to fail loudly rather than silently produce a
// policy that can never match.
func (c *AdminClient) UserID(username string) (string, error) {
	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := c.get("users?exact=true&username="+url.QueryEscape(username), &users); err != nil {
		return "", fmt.Errorf("looking up user %q: %w", username, err)
	}
	for _, u := range users {
		if u.Username == username {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("user %q not found in realm %q", username, c.realm)
}

// CreateRealmRole adds a realm role. Existing roles are left untouched.
func (c *AdminClient) CreateRealmRole(name string) error {
	return c.post("roles", map[string]string{"name": name})
}

// CreateGroup adds a top-level group by name (path "/name").
func (c *AdminClient) CreateGroup(name string) error {
	return c.post("groups", map[string]string{"name": name})
}
