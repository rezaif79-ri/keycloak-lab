package keycloak

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"
)

// AuthzSpec is the checked-in desired state for a client's Authorization
// Services configuration — the file form of README.md §2.5–2.8.
//
// Everything references everything else by *name*, never by UUID, so the file
// is portable across realms and reviewable in a diff. Resolving names to the
// internal IDs Keycloak actually wants is the sync layer's job.
type AuthzSpec struct {
	Client      string           `json:"client"`
	RealmRoles  []string         `json:"realmRoles,omitempty"`
	Groups      []string         `json:"groups,omitempty"`
	Scopes      []string         `json:"scopes"`
	Resources   []ResourceRule   `json:"resources"`
	Policies    []PolicyRule     `json:"policies"`
	Permissions []PermissionRule `json:"permissions"`
}

// ResourceRule is one protected thing — CLAUDE.md's "noun".
type ResourceRule struct {
	Name        string              `json:"name"`
	DisplayName string              `json:"displayName,omitempty"`
	Type        string              `json:"type,omitempty"`
	URIs        []string            `json:"uris,omitempty"`
	Scopes      []string            `json:"scopes,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

// PolicyRule is one reusable condition evaluated against the caller —
// CLAUDE.md's "who". Note it never names a resource; that binding lives in
// PermissionRule, which is the whole point of the model.
type PolicyRule struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // role | group | user | aggregate
	Logic string `json:"logic,omitempty"`

	Roles  []string `json:"roles,omitempty"`  // type=role
	Groups []string `json:"groups,omitempty"` // type=group, full paths e.g. "/dept-finance"
	Users  []string `json:"users,omitempty"`  // type=user, usernames

	Policies         []string `json:"policies,omitempty"`         // type=aggregate
	DecisionStrategy string   `json:"decisionStrategy,omitempty"` // type=aggregate
}

// PermissionRule binds resources × scopes × policies — CLAUDE.md's "sentence",
// and the only object where "who" meets "what".
type PermissionRule struct {
	Name             string   `json:"name"`
	Type             string   `json:"type,omitempty"` // scope (default) | resource
	Resources        []string `json:"resources,omitempty"`
	ResourceType     string   `json:"resourceType,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	Policies         []string `json:"policies,omitempty"`
	DecisionStrategy string   `json:"decisionStrategy,omitempty"` // UNANIMOUS (default) | AFFIRMATIVE | CONSENSUS
}

// LoadAuthzSpec reads and validates a spec file.
func LoadAuthzSpec(path string) (*AuthzSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading authz spec %s: %w", path, err)
	}

	var spec AuthzSpec
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields() // a typo'd key must fail loudly, not vanish
	if err := decoder.Decode(&spec); err != nil {
		return nil, fmt.Errorf("parsing authz spec %s: %w", path, err)
	}

	spec.applyDefaults()
	if problems := spec.Validate(); len(problems) > 0 {
		return nil, fmt.Errorf("authz spec %s is invalid:\n  - %s", path, strings.Join(problems, "\n  - "))
	}
	return &spec, nil
}

func (s *AuthzSpec) applyDefaults() {
	for i := range s.Policies {
		if s.Policies[i].Logic == "" {
			s.Policies[i].Logic = "POSITIVE"
		}
		if s.Policies[i].Type == "aggregate" && s.Policies[i].DecisionStrategy == "" {
			s.Policies[i].DecisionStrategy = "UNANIMOUS"
		}
	}
	for i := range s.Permissions {
		if s.Permissions[i].Type == "" {
			s.Permissions[i].Type = "scope"
		}
		if s.Permissions[i].DecisionStrategy == "" {
			s.Permissions[i].DecisionStrategy = "UNANIMOUS"
		}
	}
}

// Validate catches the config mistakes that are invisible in the admin console
// but fatal at runtime. Every rule here corresponds to a real failure mode:
// unreachable resources, permissions nobody can ever satisfy, and names that
// look correct but contain characters no one can see.
func (s *AuthzSpec) Validate() []string {
	var problems []string

	if s.Client == "" {
		problems = append(problems, `"client" is required`)
	}

	scopes := toSet(s.Scopes)
	roles := toSet(s.RealmRoles)
	resources := make(map[string]bool, len(s.Resources))
	policies := make(map[string]bool, len(s.Policies))

	groups := make(map[string]bool, len(s.Groups))
	for _, g := range s.Groups {
		groups["/"+strings.TrimPrefix(g, "/")] = true
	}

	// Names must be clean: a zero-width or control character produces an
	// object that looks right in the console and is unfindable by script.
	checkName := func(kind, name string) {
		if name == "" {
			problems = append(problems, fmt.Sprintf("%s has an empty name", kind))
			return
		}
		if name != strings.TrimSpace(name) {
			problems = append(problems, fmt.Sprintf("%s %q has leading or trailing whitespace", kind, name))
		}
		for i, r := range name {
			switch r {
			case '\u200B', '\u200C', '\u200D', '\uFEFF': // ZWSP, ZWNJ, ZWJ, BOM
				problems = append(problems, fmt.Sprintf("%s %q contains an invisible zero-width character at byte %d (U+%04X)", kind, name, i, r))
				return
			}
			if unicode.IsControl(r) {
				problems = append(problems, fmt.Sprintf("%s %q contains a control character at byte %d", kind, name, i))
				return
			}
		}
	}

	for _, sc := range s.Scopes {
		checkName("scope", sc)
	}

	for _, r := range s.Resources {
		checkName("resource", r.Name)
		if resources[r.Name] {
			problems = append(problems, fmt.Sprintf("resource %q is declared twice", r.Name))
		}
		resources[r.Name] = true
		for _, sc := range r.Scopes {
			if !scopes[sc] {
				problems = append(problems, fmt.Sprintf("resource %q attaches undeclared scope %q", r.Name, sc))
			}
		}
	}

	for _, p := range s.Policies {
		checkName("policy", p.Name)
		if policies[p.Name] {
			problems = append(problems, fmt.Sprintf("policy %q is declared twice", p.Name))
		}
		policies[p.Name] = true

		switch p.Type {
		case "role":
			if len(p.Roles) == 0 {
				problems = append(problems, fmt.Sprintf("role policy %q lists no roles", p.Name))
			}
			for _, r := range p.Roles {
				if len(s.RealmRoles) > 0 && !roles[r] {
					problems = append(problems, fmt.Sprintf("policy %q references role %q, which is not in realmRoles", p.Name, r))
				}
			}
		case "group":
			if len(p.Groups) == 0 {
				problems = append(problems, fmt.Sprintf("group policy %q lists no groups", p.Name))
			}
			for _, g := range p.Groups {
				path := "/" + strings.TrimPrefix(g, "/")
				if len(s.Groups) > 0 && !groups[path] {
					problems = append(problems, fmt.Sprintf("policy %q references group %q, which is not in groups", p.Name, g))
				}
			}
		case "user":
			if len(p.Users) == 0 {
				problems = append(problems, fmt.Sprintf("user policy %q lists no users", p.Name))
			}
		case "aggregate":
			if len(p.Policies) == 0 {
				problems = append(problems, fmt.Sprintf("aggregate policy %q lists no policies", p.Name))
			}
		default:
			problems = append(problems, fmt.Sprintf("policy %q has unsupported type %q (want role, group, user or aggregate)", p.Name, p.Type))
		}
	}

	// Aggregate members are checked after all policy names are known, so
	// ordering in the file does not matter.
	for _, p := range s.Policies {
		for _, member := range p.Policies {
			if !policies[member] {
				problems = append(problems, fmt.Sprintf("aggregate policy %q references undeclared policy %q", p.Name, member))
			}
		}
	}

	seenPerm := make(map[string]bool, len(s.Permissions))
	for _, perm := range s.Permissions {
		checkName("permission", perm.Name)
		if seenPerm[perm.Name] {
			problems = append(problems, fmt.Sprintf("permission %q is declared twice", perm.Name))
		}
		seenPerm[perm.Name] = true

		if len(perm.Policies) == 0 {
			problems = append(problems, fmt.Sprintf("permission %q applies no policies, so it can never grant anything", perm.Name))
		}
		for _, name := range perm.Policies {
			if !policies[name] {
				problems = append(problems, fmt.Sprintf("permission %q applies undeclared policy %q", perm.Name, name))
			}
		}

		if len(perm.Resources) == 0 && perm.ResourceType == "" {
			problems = append(problems, fmt.Sprintf("permission %q names neither resources nor a resourceType", perm.Name))
		}
		if len(perm.Resources) > 0 && perm.ResourceType != "" {
			problems = append(problems, fmt.Sprintf("permission %q sets both resources and resourceType; Keycloak honours only one", perm.Name))
		}
		for _, r := range perm.Resources {
			if !resources[r] {
				problems = append(problems, fmt.Sprintf("permission %q names undeclared resource %q", perm.Name, r))
			}
		}

		switch perm.Type {
		case "scope":
			if len(perm.Scopes) == 0 {
				problems = append(problems, fmt.Sprintf("scope permission %q lists no scopes", perm.Name))
			}
		case "resource":
			if len(perm.Scopes) > 0 {
				problems = append(problems, fmt.Sprintf("resource permission %q lists scopes, which that type ignores; use type \"scope\"", perm.Name))
			}
		default:
			problems = append(problems, fmt.Sprintf("permission %q has unsupported type %q (want scope or resource)", perm.Name, perm.Type))
		}

		for _, sc := range perm.Scopes {
			if !scopes[sc] {
				problems = append(problems, fmt.Sprintf("permission %q names undeclared scope %q", perm.Name, sc))
			}
		}

		// Each named resource must actually carry every scope the permission
		// governs, or the permission silently covers nothing.
		for _, rName := range perm.Resources {
			for _, res := range s.Resources {
				if res.Name != rName {
					continue
				}
				attached := toSet(res.Scopes)
				for _, sc := range perm.Scopes {
					if !attached[sc] {
						problems = append(problems, fmt.Sprintf("permission %q governs scope %q on resource %q, but that scope is not attached to the resource", perm.Name, sc, rName))
					}
				}
			}
		}

		if strings.EqualFold(perm.DecisionStrategy, "UNANIMOUS") {
			if names := s.roledPolicies(perm.Policies); len(names) > 1 {
				problems = append(problems, fmt.Sprintf(
					"permission %q is UNANIMOUS over %d role policies (%s), so a caller must hold every one of those roles at once — use AFFIRMATIVE, or an aggregate policy, if you meant \"any of\"",
					perm.Name, len(names), strings.Join(names, ", ")))
			}
		}
	}

	sort.Strings(problems)
	return problems
}

// roledPolicies returns the names of the referenced policies that are role
// policies — the set that turns a UNANIMOUS permission into an unsatisfiable
// "must hold both roles" rule.
func (s *AuthzSpec) roledPolicies(names []string) []string {
	byName := make(map[string]PolicyRule, len(s.Policies))
	for _, p := range s.Policies {
		byName[p.Name] = p
	}
	var out []string
	for _, n := range names {
		if p, ok := byName[n]; ok && p.Type == "role" {
			out = append(out, n)
		}
	}
	return out
}

func toSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}
