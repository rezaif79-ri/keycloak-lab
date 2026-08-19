package keycloak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// UMAClient exchanges a user's access token for a Requesting Party Token
// (RPT) by asking Keycloak's Authorization Services whether the user is
// permitted a given scope on a given resource. This is the "expensive but
// authoritative" check — used for ABAC/ReBAC/resource-based permissions
// that can't be decided from the access token's claims alone (e.g. because
// the decision depends on resource attributes set after the token was
// issued, like a document's `department` tag).
type UMAClient struct {
	tokenURL string
	audience string // the resource server's client ID (this backend, or a dedicated one)

	httpClient *http.Client
}

func NewUMAClient(baseURL, realm, audience string) *UMAClient {
	return &UMAClient{
		tokenURL:   fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, realm),
		audience:   audience,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// Permission is one (resource, scope) pair to evaluate — the unit Keycloak's
// UMA endpoint accepts in its `permission` parameter.
type Permission struct {
	Resource string // Keycloak resource *name*, e.g. "document:invoice-1"
	Scope    string // Keycloak scope name, e.g. "document:GetObject"
}

// String renders the pair in the wire format the UMA endpoint expects.
func (p Permission) String() string {
	return p.Resource + "#" + p.Scope
}

// Decision is the outcome of evaluating a set of permissions in one call.
// It deliberately keeps the granted and denied sets rather than collapsing
// to a bool: CLAUDE.md §5 wants the access-control boundary visible in the
// UI, and "which pair failed" is what makes a 403 explainable.
type Decision struct {
	Granted []Permission
	Denied  []Permission
}

// Any reports whether at least one requested permission was granted.
func (d Decision) Any() bool { return len(d.Granted) > 0 }

// All reports whether every requested permission was granted.
func (d Decision) All() bool { return len(d.Denied) == 0 && len(d.Granted) > 0 }

// Allowed folds the decision under the caller's chosen strategy, mirroring
// the requireAll flag used by middleware.RequireRealmRoles.
func (d Decision) Allowed(requireAll bool) bool {
	if requireAll {
		return d.All()
	}
	return d.Any()
}

// CheckPermission asks Keycloak: "can the bearer of userAccessToken perform
// `scope` on `resourceName`?" It returns (true, nil) only on an explicit
// grant. Any denial (Keycloak returns 403) is reported as (false, nil), not
// an error — a denial is an expected outcome, not a failure of the check
// itself. Only network/transport/parsing problems are returned as errors.
//
// This is the single-pair shorthand for Evaluate.
func (c *UMAClient) CheckPermission(userAccessToken, resourceName, scope string) (bool, error) {
	decision, err := c.Evaluate(userAccessToken, Permission{Resource: resourceName, Scope: scope})
	if err != nil {
		return false, err
	}
	return decision.Any(), nil
}

// Evaluate asks Keycloak about several (resource, scope) pairs in a single
// round trip and reports which were granted.
//
// It uses `response_mode=permissions` rather than `decision`: decision mode
// collapses the whole request to one boolean whose multi-permission
// aggregation is Keycloak's to define, whereas permissions mode returns the
// granted set and lets the caller apply either ANY or ALL semantics itself.
// One request either way — the expensive part is the round trip, not the
// number of pairs in it, so batching N checks here beats N calls to
// CheckPermission.
//
// A 403 from Keycloak means nothing was granted; that is an expected verdict,
// so it yields a Decision with everything denied and a nil error, matching
// CheckPermission's contract.
func (c *UMAClient) Evaluate(userAccessToken string, perms ...Permission) (*Decision, error) {
	if len(perms) == 0 {
		return &Decision{}, nil
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Set("audience", c.audience)
	form.Set("response_mode", "permissions") // return the granted set, not an opaque RPT
	for _, p := range perms {
		form.Add("permission", p.String()) // Add, not Set — the parameter repeats
	}

	req, err := http.NewRequest(http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building uma ticket request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+userAccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling keycloak uma endpoint: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Keycloak groups its answer by resource, listing the scopes it
		// granted on each — not one entry per requested pair.
		var granted []struct {
			ResourceID   string   `json:"rsid"`
			ResourceName string   `json:"rsname"`
			Scopes       []string `json:"scopes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&granted); err != nil {
			return nil, fmt.Errorf("decoding uma permissions response: %w", err)
		}

		grantedScopes := make(map[string][]string, len(granted))
		for _, g := range granted {
			grantedScopes[g.ResourceName] = g.Scopes
		}

		decision := &Decision{}
		for _, p := range perms {
			scopes, ok := grantedScopes[p.Resource]
			if !ok {
				decision.Denied = append(decision.Denied, p)
				continue
			}
			// An entry with no scopes is a resource-wide grant (a
			// resource-based permission rather than a scope-based one), so
			// it covers whichever scope we asked about on that resource.
			if len(scopes) == 0 || slices.Contains(scopes, p.Scope) {
				decision.Granted = append(decision.Granted, p)
				continue
			}
			decision.Denied = append(decision.Denied, p)
		}
		return decision, nil

	case http.StatusForbidden:
		return &Decision{Denied: append([]Permission(nil), perms...)}, nil

	default:
		return nil, fmt.Errorf("unexpected status %d from uma endpoint", resp.StatusCode)
	}
}
