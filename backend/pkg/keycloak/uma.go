package keycloak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// CheckPermission asks Keycloak: "can the bearer of userAccessToken perform
// `scope` on `resourceName`?" It returns (true, nil) only on an explicit
// grant. Any denial (Keycloak returns 403) is reported as (false, nil), not
// an error — a denial is an expected outcome, not a failure of the check
// itself. Only network/transport/parsing problems are returned as errors.
func (c *UMAClient) CheckPermission(userAccessToken, resourceName, scope string) (bool, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Set("audience", c.audience)
	form.Set("permission", fmt.Sprintf("%s#%s", resourceName, scope))
	form.Set("response_mode", "decision") // ask for a plain {"result": true/false} instead of a full RPT

	req, err := http.NewRequest(http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("building uma ticket request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+userAccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("calling keycloak uma endpoint: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var decision struct {
			Result bool `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
			return false, fmt.Errorf("decoding uma decision response: %w", err)
		}
		return decision.Result, nil
	case http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status %d from uma endpoint", resp.StatusCode)
	}
}
