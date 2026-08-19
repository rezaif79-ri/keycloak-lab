package keycloak

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newStub stands in for Keycloak's token endpoint so the decision-folding
// logic can be tested without a live realm. It echoes back whichever granted
// permissions the test supplies, in Keycloak's response_mode=permissions shape.
func newStub(t *testing.T, status int, body string) (*UMAClient, *[]string) {
	t.Helper()
	var gotPermissions []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing stub request form: %v", err)
		}
		gotPermissions = r.Form["permission"]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != "" {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("writing stub response: %v", err)
			}
		}
	}))
	t.Cleanup(srv.Close)

	return &UMAClient{tokenURL: srv.URL, audience: "kc-lab-backend", httpClient: srv.Client()}, &gotPermissions
}

func TestEvaluateSendsOneRepeatedParamPerPair(t *testing.T) {
	uma, got := newStub(t, http.StatusOK, `[]`)

	_, err := uma.Evaluate("tok",
		Permission{Resource: "document:invoice-1", Scope: "document:GetObject"},
		Permission{Resource: "document:invoice-2", Scope: "document:GetObject"},
	)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	want := []string{"document:invoice-1#document:GetObject", "document:invoice-2#document:GetObject"}
	if len(*got) != len(want) {
		t.Fatalf("sent %d permission params, want %d: %v", len(*got), len(want), *got)
	}
	for i, w := range want {
		if (*got)[i] != w {
			t.Errorf("permission[%d] = %q, want %q", i, (*got)[i], w)
		}
	}
}

func TestEvaluatePartialGrantSplitsGrantedAndDenied(t *testing.T) {
	// Keycloak granted GetObject on invoice-2 only — the exact shape the live
	// realm produces for viewer-user today.
	uma, _ := newStub(t, http.StatusOK,
		`[{"rsid":"b1f","rsname":"document:invoice-2","scopes":["document:GetObject"]}]`)

	getInv1 := Permission{Resource: "document:invoice-1", Scope: "document:GetObject"}
	getInv2 := Permission{Resource: "document:invoice-2", Scope: "document:GetObject"}

	d, err := uma.Evaluate("tok", getInv1, getInv2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if len(d.Granted) != 1 || d.Granted[0] != getInv2 {
		t.Errorf("Granted = %v, want [%v]", d.Granted, getInv2)
	}
	if len(d.Denied) != 1 || d.Denied[0] != getInv1 {
		t.Errorf("Denied = %v, want [%v]", d.Denied, getInv1)
	}
	if !d.Any() {
		t.Error("Any() = false, want true — one pair was granted")
	}
	if d.All() {
		t.Error("All() = true, want false — one pair was denied")
	}
	if !d.Allowed(false) {
		t.Error("Allowed(requireAll=false) = false, want true")
	}
	if d.Allowed(true) {
		t.Error("Allowed(requireAll=true) = true, want false")
	}
}

func TestEvaluateWrongScopeOnGrantedResourceIsDenied(t *testing.T) {
	// The resource comes back granted, but only for a scope we did not ask
	// about. Matching on resource name alone would wrongly permit this.
	uma, _ := newStub(t, http.StatusOK,
		`[{"rsid":"3d0","rsname":"document:invoice-1","scopes":["document:GetObject"]}]`)

	admin := Permission{Resource: "document:invoice-1", Scope: "document:Admin"}

	d, err := uma.Evaluate("tok", admin)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Any() {
		t.Errorf("Any() = true, want false — Admin was never granted, got %v", d.Granted)
	}
}

func TestEvaluateResourceWideGrantCoversAnyScope(t *testing.T) {
	// A resource-based (not scope-based) permission returns no scopes list.
	uma, _ := newStub(t, http.StatusOK,
		`[{"rsid":"3d0","rsname":"document:invoice-1","scopes":[]}]`)

	d, err := uma.Evaluate("tok", Permission{Resource: "document:invoice-1", Scope: "document:Admin"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.All() {
		t.Errorf("All() = false, want true — an empty scopes list is a resource-wide grant, got %v", d.Denied)
	}
}

func TestEvaluateForbiddenIsDenialNotError(t *testing.T) {
	uma, _ := newStub(t, http.StatusForbidden, `{"error":"access_denied"}`)

	p := Permission{Resource: "document:invoice-1", Scope: "document:Admin"}
	d, err := uma.Evaluate("tok", p)
	if err != nil {
		t.Fatalf("Evaluate returned an error for a 403; a denial is an expected verdict: %v", err)
	}
	if d.Any() {
		t.Error("Any() = true, want false")
	}
	if len(d.Denied) != 1 || d.Denied[0] != p {
		t.Errorf("Denied = %v, want [%v]", d.Denied, p)
	}
}

func TestEvaluateServerErrorIsAnError(t *testing.T) {
	uma, _ := newStub(t, http.StatusInternalServerError, ``)

	if _, err := uma.Evaluate("tok", Permission{Resource: "r", Scope: "s"}); err == nil {
		t.Error("Evaluate returned nil error for a 500; transport failures must not read as denials")
	}
}

func TestEvaluateNoPermissionsMakesNoCall(t *testing.T) {
	uma, got := newStub(t, http.StatusOK, `[]`)

	d, err := uma.Evaluate("tok")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(*got) != 0 {
		t.Errorf("called Keycloak with %v for an empty permission set", *got)
	}
	if d.Any() || d.All() {
		t.Error("an empty permission set should satisfy neither Any() nor All()")
	}
}

func TestCheckPermissionStillUsesAnySemantics(t *testing.T) {
	uma, got := newStub(t, http.StatusOK,
		`[{"rsid":"b1f","rsname":"document:invoice-2","scopes":["document:GetObject"]}]`)

	ok, err := uma.CheckPermission("tok", "document:invoice-2", "document:GetObject")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !ok {
		t.Error("CheckPermission = false, want true")
	}
	if len(*got) != 1 || (*got)[0] != "document:invoice-2#document:GetObject" {
		t.Errorf("sent %v, want one pair", *got)
	}
}
