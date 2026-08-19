package keycloak

import (
	"strings"
	"testing"
)

// validSpec is the shape a correct lab config takes; each test perturbs one
// thing so the assertion is about that perturbation alone.
func validSpec() *AuthzSpec {
	s := &AuthzSpec{
		Client:     "kc-lab-backend",
		RealmRoles: []string{"document-viewer", "document-admin"},
		Groups:     []string{"/dept-finance"},
		Scopes:     []string{"document:GetObject", "document:Admin"},
		Resources: []ResourceRule{{
			Name:   "document:invoice-1",
			Type:   "document",
			Scopes: []string{"document:GetObject", "document:Admin"},
		}},
		Policies: []PolicyRule{
			{Name: "policy-document-viewer", Type: "role", Roles: []string{"document-viewer"}},
			{Name: "policy-document-admin", Type: "role", Roles: []string{"document-admin"}},
			{Name: "policy-tag-department", Type: "group", Groups: []string{"/dept-finance"}},
		},
		Permissions: []PermissionRule{{
			Name:      "perm-invoice1-getobject",
			Resources: []string{"document:invoice-1"},
			Scopes:    []string{"document:GetObject"},
			Policies:  []string{"policy-document-viewer", "policy-tag-department"},
		}},
	}
	s.applyDefaults()
	return s
}

func assertProblem(t *testing.T, problems []string, want string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Errorf("no problem mentioning %q; got %v", want, problems)
}

func TestValidateAcceptsAGoodSpec(t *testing.T) {
	if problems := validSpec().Validate(); len(problems) > 0 {
		t.Errorf("valid spec rejected: %v", problems)
	}
}

// The live realm had U+200B pasted into three permission names, invisible in
// the admin console. Catching it in review is the entire point of the file.
func TestValidateRejectsZeroWidthCharactersInNames(t *testing.T) {
	s := validSpec()
	s.Permissions[0].Name = "​perm-invoice1-getobject"

	assertProblem(t, s.Validate(), "invisible zero-width character")
}

// UNANIMOUS over two role policies means "must hold both roles at once",
// which is almost never the intent and locked every user out of invoice-1.
func TestValidateFlagsUnanimousOverMultipleRolePolicies(t *testing.T) {
	s := validSpec()
	s.Permissions[0].Policies = []string{"policy-document-viewer", "policy-document-admin"}

	assertProblem(t, s.Validate(), "must hold every one of those roles")
}

func TestValidateAllowsAffirmativeOverMultipleRolePolicies(t *testing.T) {
	s := validSpec()
	s.Permissions[0].Policies = []string{"policy-document-viewer", "policy-document-admin"}
	s.Permissions[0].DecisionStrategy = "AFFIRMATIVE"

	for _, p := range s.Validate() {
		if strings.Contains(p, "must hold every one of those roles") {
			t.Errorf("AFFIRMATIVE wrongly flagged: %s", p)
		}
	}
}

// An aggregate policy is the other correct way to express "any of these
// roles" while keeping the permission itself UNANIMOUS.
func TestValidateAllowsAggregatePolicyUnderUnanimous(t *testing.T) {
	s := validSpec()
	s.Policies = append(s.Policies, PolicyRule{
		Name: "policy-can-read", Type: "aggregate", DecisionStrategy: "AFFIRMATIVE",
		Policies: []string{"policy-document-viewer", "policy-document-admin"},
	})
	s.Permissions[0].Policies = []string{"policy-can-read", "policy-tag-department"}

	if problems := s.Validate(); len(problems) > 0 {
		t.Errorf("aggregate form rejected: %v", problems)
	}
}

// perm-invoice1-admin had a stray document:GetObject scope, silently widening
// what the admin permission governed.
func TestValidateRejectsScopeNotAttachedToResource(t *testing.T) {
	s := validSpec()
	s.Resources[0].Scopes = []string{"document:Admin"} // GetObject no longer attached

	assertProblem(t, s.Validate(), "not attached to the resource")
}

func TestValidateRejectsDanglingReferences(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*AuthzSpec)
		want   string
	}{
		{"unknown policy", func(s *AuthzSpec) {
			s.Permissions[0].Policies = []string{"policy-owner-carol"}
		}, `applies undeclared policy "policy-owner-carol"`},
		{"unknown resource", func(s *AuthzSpec) {
			s.Permissions[0].Resources = []string{"document:invoice-9"}
		}, `names undeclared resource "document:invoice-9"`},
		{"unknown scope", func(s *AuthzSpec) {
			s.Permissions[0].Scopes = []string{"document:Delete"}
		}, `names undeclared scope "document:Delete"`},
		{"unknown role", func(s *AuthzSpec) {
			s.Policies[0].Roles = []string{"document-superuser"}
		}, `not in realmRoles`},
		{"unknown group", func(s *AuthzSpec) {
			s.Policies[2].Groups = []string{"/dept-legal"}
		}, `not in groups`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := validSpec()
			tc.mutate(s)
			assertProblem(t, s.Validate(), tc.want)
		})
	}
}

// A permission with no policies grants nothing, and a resource with no
// permission is unreachable — both look fine in the console.
func TestValidateRejectsPermissionWithNoPolicies(t *testing.T) {
	s := validSpec()
	s.Permissions[0].Policies = nil

	assertProblem(t, s.Validate(), "can never grant anything")
}

func TestValidateRejectsPermissionTargetingNothing(t *testing.T) {
	s := validSpec()
	s.Permissions[0].Resources = nil

	assertProblem(t, s.Validate(), "names neither resources nor a resourceType")
}

func TestValidateRejectsBothResourcesAndResourceType(t *testing.T) {
	s := validSpec()
	s.Permissions[0].ResourceType = "document"

	assertProblem(t, s.Validate(), "Keycloak honours only one")
}

func TestValidateRejectsDuplicateNames(t *testing.T) {
	s := validSpec()
	s.Policies = append(s.Policies, PolicyRule{
		Name: "policy-document-viewer", Type: "role", Roles: []string{"document-viewer"},
	})

	assertProblem(t, s.Validate(), `policy "policy-document-viewer" is declared twice`)
}

func TestApplyDefaultsFillsStrategyAndType(t *testing.T) {
	s := &AuthzSpec{Permissions: []PermissionRule{{Name: "p"}}, Policies: []PolicyRule{{Name: "q", Type: "role"}}}
	s.applyDefaults()

	if s.Permissions[0].Type != "scope" {
		t.Errorf("permission type = %q, want %q", s.Permissions[0].Type, "scope")
	}
	if s.Permissions[0].DecisionStrategy != "UNANIMOUS" {
		t.Errorf("decisionStrategy = %q, want UNANIMOUS", s.Permissions[0].DecisionStrategy)
	}
	if s.Policies[0].Logic != "POSITIVE" {
		t.Errorf("logic = %q, want POSITIVE", s.Policies[0].Logic)
	}
}

// --- diff helpers ---------------------------------------------------------

func TestDiffSetReportsOnlyTheDelta(t *testing.T) {
	got := diffSet("policies", []string{"a", "b"}, []string{"b", "c"})
	if !strings.Contains(got, "+c") || !strings.Contains(got, "-a") {
		t.Errorf("diffSet = %q, want +c and -a", got)
	}
	if strings.Contains(got, "b") && !strings.Contains(got, "policies") {
		t.Errorf("diffSet = %q, unchanged member should not appear", got)
	}
}

func TestDiffSetIgnoresOrder(t *testing.T) {
	if got := diffSet("scopes", []string{"a", "b"}, []string{"b", "a"}); got != "" {
		t.Errorf("diffSet = %q, want empty for a reordering", got)
	}
}

// The ZWSP drift shows up as an add and a remove that look identical; the
// diff must still report it rather than treating the names as equal.
func TestDiffSetSeesZeroWidthDifference(t *testing.T) {
	got := diffSet("policies", []string{"​policy-document-admin"}, []string{"policy-document-admin"})
	if got == "" {
		t.Error("diffSet treated names differing only by U+200B as equal")
	}
}

func TestPermissionFromConfigParsesJSONInJSON(t *testing.T) {
	p := permissionFromConfig("perm-invoice1-admin", "scope", "UNANIMOUS", map[string]string{
		"resources":     `["document:invoice-1"]`,
		"scopes":        `["document:Admin","document:GetObject"]`,
		"applyPolicies": `["policy-document-admin","policy-owner-alice"]`,
	})

	if len(p.Scopes) != 2 || p.Scopes[0] != "document:Admin" {
		t.Errorf("Scopes = %v", p.Scopes)
	}
	if len(p.Policies) != 2 || p.Policies[1] != "policy-owner-alice" {
		t.Errorf("Policies = %v", p.Policies)
	}
	if len(p.Resources) != 1 || p.Resources[0] != "document:invoice-1" {
		t.Errorf("Resources = %v", p.Resources)
	}
}

func TestPolicyFromConfigParsesEachType(t *testing.T) {
	role := policyFromConfig("r", "role", "POSITIVE", "", map[string]string{
		"roles": `[{"id":"document-viewer","required":false}]`,
	})
	if len(role.Roles) != 1 || role.Roles[0] != "document-viewer" {
		t.Errorf("role policy Roles = %v", role.Roles)
	}

	group := policyFromConfig("g", "group", "POSITIVE", "", map[string]string{
		"groups": `[{"path":"/dept-finance","extendChildren":false}]`,
	})
	if len(group.Groups) != 1 || group.Groups[0] != "/dept-finance" {
		t.Errorf("group policy Groups = %v", group.Groups)
	}

	user := policyFromConfig("u", "user", "POSITIVE", "", map[string]string{
		"users": `["alice"]`,
	})
	if len(user.Users) != 1 || user.Users[0] != "alice" {
		t.Errorf("user policy Users = %v", user.Users)
	}
}
