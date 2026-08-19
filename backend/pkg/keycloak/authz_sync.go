package keycloak

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Action is one change the sync would make, or did make.
type Action struct {
	Op     string // create | update | delete
	Kind   string // realm-role | group | scope | resource | policy | permission
	Name   string
	Detail string
}

func (a Action) String() string {
	s := fmt.Sprintf("%-6s %-11s %s", a.Op, a.Kind, a.Name)
	if a.Detail != "" {
		s += "\n              " + strings.ReplaceAll(a.Detail, "\n", "\n              ")
	}
	return s
}

// Plan is the diff between a spec file and a live realm.
type Plan struct {
	Actions []Action
}

func (p Plan) Empty() bool { return len(p.Actions) == 0 }

func (p Plan) String() string {
	if p.Empty() {
		return "no changes — realm matches spec"
	}
	lines := make([]string, 0, len(p.Actions))
	for _, a := range p.Actions {
		lines = append(lines, "  "+a.String())
	}
	return strings.Join(lines, "\n")
}

// resourceServerRep is Keycloak's export shape for a client's whole
// authorization config. One GET returns the complete current state with every
// cross-reference already rendered as a name, which is what makes a
// name-keyed diff possible.
//
// It deliberately carries no UUIDs — not for resources, scopes, or policies.
// That is what makes it portable between realms, and why writes have to source
// their IDs from the per-object list endpoints instead (see fetchIDMaps).
type resourceServerRep struct {
	Resources []struct {
		Name        string              `json:"name"`
		DisplayName string              `json:"displayName"`
		Type        string              `json:"type"`
		URIs        []string            `json:"uris"`
		Scopes      []namedRef          `json:"scopes"`
		Attributes  map[string][]string `json:"attributes"`
	} `json:"resources"`
	Scopes []struct {
		Name string `json:"name"`
	} `json:"scopes"`
	Policies []struct {
		Name             string            `json:"name"`
		Type             string            `json:"type"`
		Logic            string            `json:"logic"`
		DecisionStrategy string            `json:"decisionStrategy"`
		Config           map[string]string `json:"config"`
	} `json:"policies"`
}

// fetchIDMaps reads the name→UUID lookups that every write call needs. The
// settings export cannot supply these, so each object type is listed from its
// own endpoint. The policy listing covers permissions too — Keycloak stores
// both in the same table, which is why a permission is deleted via /policy/{id}.
func (s *AuthzSyncer) fetchIDMaps() (scopes, resources, policies map[string]string, err error) {
	var scopeList []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := s.admin.get(s.base()+"/scope?max=1000", &scopeList); err != nil {
		return nil, nil, nil, fmt.Errorf("listing scopes: %w", err)
	}
	var resourceList []struct {
		ID   string `json:"_id"`
		Name string `json:"name"`
	}
	if err := s.admin.get(s.base()+"/resource?max=1000", &resourceList); err != nil {
		return nil, nil, nil, fmt.Errorf("listing resources: %w", err)
	}
	var policyList []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := s.admin.get(s.base()+"/policy?max=1000", &policyList); err != nil {
		return nil, nil, nil, fmt.Errorf("listing policies: %w", err)
	}

	scopes = make(map[string]string, len(scopeList))
	for _, v := range scopeList {
		scopes[v.Name] = v.ID
	}
	resources = make(map[string]string, len(resourceList))
	for _, v := range resourceList {
		resources[v.Name] = v.ID
	}
	policies = make(map[string]string, len(policyList))
	for _, v := range policyList {
		policies[v.Name] = v.ID
	}
	return scopes, resources, policies, nil
}

// AuthzSyncer reconciles a live realm towards an AuthzSpec.
type AuthzSyncer struct {
	admin *AdminClient
	spec  *AuthzSpec

	rsID    string
	current *resourceServerRep
}

func NewAuthzSyncer(admin *AdminClient, spec *AuthzSpec) *AuthzSyncer {
	return &AuthzSyncer{admin: admin, spec: spec}
}

func (s *AuthzSyncer) base() string {
	return "clients/" + s.rsID + "/authz/resource-server"
}

// load resolves the client and pulls current state.
func (s *AuthzSyncer) load() error {
	if s.current != nil {
		return nil
	}
	rsID, err := s.admin.ResourceServerID(s.spec.Client)
	if err != nil {
		return err
	}
	s.rsID = rsID

	var rep resourceServerRep
	if err := s.admin.get(s.base()+"/settings", &rep); err != nil {
		return fmt.Errorf("reading current authorization settings: %w", err)
	}
	s.current = &rep
	return nil
}

// Plan computes the diff without changing anything. prune controls whether
// live objects absent from the spec are reported for deletion; it defaults off
// so that Keycloak's built-in "Default Resource"/"Default Policy" objects, and
// anything created by hand outside the spec, are left alone.
func (s *AuthzSyncer) Plan(prune bool) (*Plan, error) {
	if err := s.load(); err != nil {
		return nil, err
	}

	plan := &Plan{}

	// --- realm-level prerequisites --------------------------------------
	roleIDs, err := s.admin.RealmRoleIDs()
	if err != nil {
		return nil, err
	}
	for _, name := range s.spec.RealmRoles {
		if _, ok := roleIDs[name]; !ok {
			plan.Actions = append(plan.Actions, Action{Op: "create", Kind: "realm-role", Name: name})
		}
	}

	groupPaths, err := s.admin.GroupPaths()
	if err != nil {
		return nil, err
	}
	for _, g := range s.spec.Groups {
		path := "/" + strings.TrimPrefix(g, "/")
		if _, ok := groupPaths[path]; !ok {
			plan.Actions = append(plan.Actions, Action{Op: "create", Kind: "group", Name: path})
		}
	}

	// --- scopes ----------------------------------------------------------
	liveScopes := make(map[string]bool, len(s.current.Scopes))
	for _, sc := range s.current.Scopes {
		liveScopes[sc.Name] = true
	}
	for _, want := range s.spec.Scopes {
		if !liveScopes[want] {
			plan.Actions = append(plan.Actions, Action{Op: "create", Kind: "scope", Name: want})
		}
	}
	if prune {
		specScopes := toSet(s.spec.Scopes)
		for _, sc := range s.current.Scopes {
			if !specScopes[sc.Name] {
				plan.Actions = append(plan.Actions, Action{Op: "delete", Kind: "scope", Name: sc.Name})
			}
		}
	}

	// --- resources -------------------------------------------------------
	liveResources := make(map[string]ResourceRule, len(s.current.Resources))
	for _, r := range s.current.Resources {
		scopes := make([]string, 0, len(r.Scopes))
		for _, sc := range r.Scopes {
			scopes = append(scopes, sc.Name)
		}
		liveResources[r.Name] = ResourceRule{
			Name: r.Name, DisplayName: r.DisplayName, Type: r.Type,
			URIs: r.URIs, Scopes: scopes, Attributes: r.Attributes,
		}
	}
	for _, want := range s.spec.Resources {
		live, ok := liveResources[want.Name]
		if !ok {
			plan.Actions = append(plan.Actions, Action{Op: "create", Kind: "resource", Name: want.Name})
			continue
		}
		if d := diffResource(live, want); d != "" {
			plan.Actions = append(plan.Actions, Action{Op: "update", Kind: "resource", Name: want.Name, Detail: d})
		}
	}
	if prune {
		specResources := make(map[string]bool, len(s.spec.Resources))
		for _, r := range s.spec.Resources {
			specResources[r.Name] = true
		}
		for _, r := range s.current.Resources {
			if !specResources[r.Name] && r.Type != "urn:"+s.spec.Client+":resources:default" {
				plan.Actions = append(plan.Actions, Action{Op: "delete", Kind: "resource", Name: r.Name})
			}
		}
	}

	// --- policies and permissions ---------------------------------------
	livePolicies := make(map[string]PolicyRule)
	livePermissions := make(map[string]PermissionRule)
	for _, p := range s.current.Policies {
		switch p.Type {
		case "scope", "resource":
			livePermissions[p.Name] = permissionFromConfig(p.Name, p.Type, p.DecisionStrategy, p.Config)
		default:
			livePolicies[p.Name] = policyFromConfig(p.Name, p.Type, p.Logic, p.DecisionStrategy, p.Config)
		}
	}

	for _, want := range s.spec.Policies {
		live, ok := livePolicies[want.Name]
		if !ok {
			plan.Actions = append(plan.Actions, Action{Op: "create", Kind: "policy", Name: want.Name})
			continue
		}
		if d := diffPolicy(live, want); d != "" {
			plan.Actions = append(plan.Actions, Action{Op: "update", Kind: "policy", Name: want.Name, Detail: d})
		}
	}

	for _, want := range s.spec.Permissions {
		live, ok := livePermissions[want.Name]
		if !ok {
			plan.Actions = append(plan.Actions, Action{Op: "create", Kind: "permission", Name: want.Name})
			continue
		}
		if d := diffPermission(live, want); d != "" {
			plan.Actions = append(plan.Actions, Action{Op: "update", Kind: "permission", Name: want.Name, Detail: d})
		}
	}

	if prune {
		specPolicies := make(map[string]bool, len(s.spec.Policies))
		for _, p := range s.spec.Policies {
			specPolicies[p.Name] = true
		}
		specPerms := make(map[string]bool, len(s.spec.Permissions))
		for _, p := range s.spec.Permissions {
			specPerms[p.Name] = true
		}
		for name := range livePolicies {
			if !specPolicies[name] && name != "Default Policy" {
				plan.Actions = append(plan.Actions, Action{Op: "delete", Kind: "policy", Name: name})
			}
		}
		for name := range livePermissions {
			if !specPerms[name] && name != "Default Permission" {
				plan.Actions = append(plan.Actions, Action{Op: "delete", Kind: "permission", Name: name})
			}
		}
	}

	sort.SliceStable(plan.Actions, func(i, j int) bool {
		return kindOrder(plan.Actions[i].Kind) < kindOrder(plan.Actions[j].Kind)
	})
	return plan, nil
}

// kindOrder sequences changes so dependencies exist before their referrers:
// roles and groups before the policies that test them, scopes and resources
// before the permissions that bind them.
func kindOrder(kind string) int {
	switch kind {
	case "realm-role":
		return 0
	case "group":
		return 1
	case "scope":
		return 2
	case "resource":
		return 3
	case "policy":
		return 4
	case "permission":
		return 5
	}
	return 6
}

// --- normalisation from Keycloak's JSON-in-JSON config fields -------------

func policyFromConfig(name, typ, logic, strategy string, cfg map[string]string) PolicyRule {
	p := PolicyRule{Name: name, Type: typ, Logic: logic}
	switch typ {
	case "role":
		var roles []struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(cfg["roles"]), &roles)
		for _, r := range roles {
			p.Roles = append(p.Roles, r.ID)
		}
	case "group":
		var groups []struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal([]byte(cfg["groups"]), &groups)
		for _, g := range groups {
			p.Groups = append(p.Groups, g.Path)
		}
	case "user":
		_ = json.Unmarshal([]byte(cfg["users"]), &p.Users)
	case "aggregate":
		_ = json.Unmarshal([]byte(cfg["applyPolicies"]), &p.Policies)
		p.DecisionStrategy = strategy
	}
	return p
}

func permissionFromConfig(name, typ, strategy string, cfg map[string]string) PermissionRule {
	p := PermissionRule{Name: name, Type: typ, DecisionStrategy: strategy, ResourceType: cfg["defaultResourceType"]}
	_ = json.Unmarshal([]byte(cfg["resources"]), &p.Resources)
	_ = json.Unmarshal([]byte(cfg["scopes"]), &p.Scopes)
	_ = json.Unmarshal([]byte(cfg["applyPolicies"]), &p.Policies)
	return p
}

// --- diffing --------------------------------------------------------------

func diffResource(live, want ResourceRule) string {
	var parts []string
	if want.Type != "" && live.Type != want.Type {
		parts = append(parts, fmt.Sprintf("type: %q -> %q", live.Type, want.Type))
	}
	if d := diffSet("scopes", live.Scopes, want.Scopes); d != "" {
		parts = append(parts, d)
	}
	if d := diffAttrs(live.Attributes, want.Attributes); d != "" {
		parts = append(parts, d)
	}
	return strings.Join(parts, "\n")
}

func diffPolicy(live, want PolicyRule) string {
	var parts []string
	if live.Type != want.Type {
		parts = append(parts, fmt.Sprintf("type: %q -> %q", live.Type, want.Type))
	}
	if want.Logic != "" && live.Logic != want.Logic {
		parts = append(parts, fmt.Sprintf("logic: %q -> %q", live.Logic, want.Logic))
	}
	if d := diffSet("roles", live.Roles, want.Roles); d != "" {
		parts = append(parts, d)
	}
	if d := diffSet("groups", normalisePaths(live.Groups), normalisePaths(want.Groups)); d != "" {
		parts = append(parts, d)
	}
	if d := diffSet("users", live.Users, want.Users); d != "" {
		parts = append(parts, d)
	}
	if d := diffSet("policies", live.Policies, want.Policies); d != "" {
		parts = append(parts, d)
	}
	return strings.Join(parts, "\n")
}

func diffPermission(live, want PermissionRule) string {
	var parts []string
	if live.Type != want.Type {
		parts = append(parts, fmt.Sprintf("type: %q -> %q", live.Type, want.Type))
	}
	if !strings.EqualFold(live.DecisionStrategy, want.DecisionStrategy) {
		parts = append(parts, fmt.Sprintf("decisionStrategy: %q -> %q", live.DecisionStrategy, want.DecisionStrategy))
	}
	if live.ResourceType != want.ResourceType {
		parts = append(parts, fmt.Sprintf("resourceType: %q -> %q", live.ResourceType, want.ResourceType))
	}
	if d := diffSet("resources", live.Resources, want.Resources); d != "" {
		parts = append(parts, d)
	}
	if d := diffSet("scopes", live.Scopes, want.Scopes); d != "" {
		parts = append(parts, d)
	}
	if d := diffSet("policies", live.Policies, want.Policies); d != "" {
		parts = append(parts, d)
	}
	return strings.Join(parts, "\n")
}

func normalisePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, "/"+strings.TrimPrefix(p, "/"))
	}
	return out
}

// diffSet reports added and removed members, ignoring order. Rendering the
// delta rather than both full lists is what makes an accidental extra policy
// or scope jump out of the plan.
func diffSet(label string, live, want []string) string {
	liveSet, wantSet := toSet(live), toSet(want)
	var added, removed []string
	for _, w := range want {
		if !liveSet[w] {
			added = append(added, w)
		}
	}
	for _, l := range live {
		if !wantSet[l] {
			removed = append(removed, l)
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return ""
	}
	sort.Strings(added)
	sort.Strings(removed)

	var parts []string
	if len(added) > 0 {
		parts = append(parts, "+"+strings.Join(added, " +"))
	}
	if len(removed) > 0 {
		parts = append(parts, "-"+strings.Join(removed, " -"))
	}
	return label + ": " + strings.Join(parts, "  ")
}

func diffAttrs(live, want map[string][]string) string {
	if len(want) == 0 {
		return ""
	}
	var parts []string
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Join(live[k], ",") != strings.Join(want[k], ",") {
			parts = append(parts, fmt.Sprintf("attribute %s: %v -> %v", k, live[k], want[k]))
		}
	}
	return strings.Join(parts, "\n")
}

// --- apply ----------------------------------------------------------------

// Apply performs the planned changes in dependency order and returns what it
// did. It re-plans internally, so calling Plan first is optional.
func (s *AuthzSyncer) Apply(prune bool) ([]Action, error) {
	plan, err := s.Plan(prune)
	if err != nil {
		return nil, err
	}
	if plan.Empty() {
		return nil, nil
	}

	// Realm-level objects first, then reload so new IDs are visible.
	for _, a := range plan.Actions {
		switch {
		case a.Kind == "realm-role" && a.Op == "create":
			if err := s.admin.CreateRealmRole(a.Name); err != nil {
				return nil, fmt.Errorf("creating realm role %q: %w", a.Name, err)
			}
		case a.Kind == "group" && a.Op == "create":
			if err := s.admin.CreateGroup(strings.TrimPrefix(a.Name, "/")); err != nil {
				return nil, fmt.Errorf("creating group %q: %w", a.Name, err)
			}
		}
	}

	ids, err := s.resolveIDs()
	if err != nil {
		return nil, err
	}

	for _, a := range plan.Actions {
		if err := s.applyAction(a, ids); err != nil {
			return nil, fmt.Errorf("applying %s %s %q: %w", a.Op, a.Kind, a.Name, err)
		}
		// Newly created objects need their IDs before later actions can
		// reference them, so refresh the maps as we go.
		if a.Op == "create" && (a.Kind == "scope" || a.Kind == "resource" || a.Kind == "policy") {
			if ids, err = s.resolveIDs(); err != nil {
				return nil, err
			}
		}
	}

	s.current = nil // force a reload if this syncer is reused
	return plan.Actions, nil
}

// idMaps holds every name→UUID lookup the create/update calls need.
type idMaps struct {
	roles     map[string]string
	groups    map[string]string
	users     map[string]string
	scopes    map[string]string
	resources map[string]string
	policies  map[string]string
}

func (s *AuthzSyncer) resolveIDs() (*idMaps, error) {
	roles, err := s.admin.RealmRoleIDs()
	if err != nil {
		return nil, err
	}
	groups, err := s.admin.GroupPaths()
	if err != nil {
		return nil, err
	}

	var rep resourceServerRep
	if err := s.admin.get(s.base()+"/settings", &rep); err != nil {
		return nil, fmt.Errorf("re-reading authorization settings: %w", err)
	}
	s.current = &rep

	scopeIDs, resourceIDs, policyIDs, err := s.fetchIDMaps()
	if err != nil {
		return nil, err
	}

	ids := &idMaps{
		roles: roles, groups: groups,
		users:     map[string]string{},
		scopes:    scopeIDs,
		resources: resourceIDs,
		policies:  policyIDs,
	}

	// User Policies reference UUIDs, so every username in the spec has to
	// resolve before we try to write one.
	for _, p := range s.spec.Policies {
		for _, username := range p.Users {
			if _, ok := ids.users[username]; ok {
				continue
			}
			uid, err := s.admin.UserID(username)
			if err != nil {
				return nil, fmt.Errorf("policy %q: %w", p.Name, err)
			}
			ids.users[username] = uid
		}
	}
	return ids, nil
}

func (s *AuthzSyncer) applyAction(a Action, ids *idMaps) error {
	switch a.Kind {
	case "realm-role", "group":
		return nil // handled before ID resolution

	case "scope":
		switch a.Op {
		case "create":
			return s.admin.post(s.base()+"/scope", map[string]string{"name": a.Name})
		case "delete":
			return s.admin.delete(s.base() + "/scope/" + ids.scopes[a.Name])
		}

	case "resource":
		switch a.Op {
		case "create":
			return s.admin.post(s.base()+"/resource", s.resourceBody(a.Name))
		case "update":
			body := s.resourceBody(a.Name)
			body["_id"] = ids.resources[a.Name]
			return s.admin.put(s.base()+"/resource/"+ids.resources[a.Name], body)
		case "delete":
			return s.admin.delete(s.base() + "/resource/" + ids.resources[a.Name])
		}

	case "policy":
		rule, ok := s.specPolicy(a.Name)
		if a.Op == "delete" || !ok {
			return s.admin.delete(s.base() + "/policy/" + ids.policies[a.Name])
		}
		body, err := s.policyBody(rule, ids)
		if err != nil {
			return err
		}
		if a.Op == "create" {
			return s.admin.post(s.base()+"/policy/"+rule.Type, body)
		}
		body["id"] = ids.policies[a.Name]
		return s.admin.put(s.base()+"/policy/"+rule.Type+"/"+ids.policies[a.Name], body)

	case "permission":
		rule, ok := s.specPermission(a.Name)
		if a.Op == "delete" || !ok {
			return s.admin.delete(s.base() + "/policy/" + ids.policies[a.Name])
		}
		body := s.permissionBody(rule, ids)
		if a.Op == "create" {
			return s.admin.post(s.base()+"/permission/"+rule.Type, body)
		}
		body["id"] = ids.policies[a.Name]
		return s.admin.put(s.base()+"/permission/"+rule.Type+"/"+ids.policies[a.Name], body)
	}
	return fmt.Errorf("unsupported action %s %s", a.Op, a.Kind)
}

func (s *AuthzSyncer) specPolicy(name string) (PolicyRule, bool) {
	for _, p := range s.spec.Policies {
		if p.Name == name {
			return p, true
		}
	}
	return PolicyRule{}, false
}

func (s *AuthzSyncer) specPermission(name string) (PermissionRule, bool) {
	for _, p := range s.spec.Permissions {
		if p.Name == name {
			return p, true
		}
	}
	return PermissionRule{}, false
}

func (s *AuthzSyncer) resourceBody(name string) map[string]any {
	for _, r := range s.spec.Resources {
		if r.Name != name {
			continue
		}
		scopes := make([]map[string]string, 0, len(r.Scopes))
		for _, sc := range r.Scopes {
			scopes = append(scopes, map[string]string{"name": sc})
		}
		body := map[string]any{
			"name":       r.Name,
			"type":       r.Type,
			"scopes":     scopes,
			"attributes": r.Attributes,
		}
		if r.DisplayName != "" {
			body["displayName"] = r.DisplayName
		}
		if len(r.URIs) > 0 {
			body["uris"] = r.URIs
		}
		return body
	}
	return map[string]any{"name": name}
}

func (s *AuthzSyncer) policyBody(p PolicyRule, ids *idMaps) (map[string]any, error) {
	body := map[string]any{"name": p.Name, "logic": p.Logic}

	switch p.Type {
	case "role":
		roles := make([]map[string]any, 0, len(p.Roles))
		for _, name := range p.Roles {
			id, ok := ids.roles[name]
			if !ok {
				return nil, fmt.Errorf("realm role %q not found", name)
			}
			roles = append(roles, map[string]any{"id": id, "required": false})
		}
		body["roles"] = roles

	case "group":
		groups := make([]map[string]any, 0, len(p.Groups))
		for _, path := range normalisePaths(p.Groups) {
			id, ok := ids.groups[path]
			if !ok {
				return nil, fmt.Errorf("group %q not found", path)
			}
			groups = append(groups, map[string]any{"id": id, "extendChildren": false})
		}
		body["groups"] = groups

	case "user":
		users := make([]string, 0, len(p.Users))
		for _, username := range p.Users {
			id, ok := ids.users[username]
			if !ok {
				return nil, fmt.Errorf("user %q not found", username)
			}
			users = append(users, id)
		}
		body["users"] = users

	case "aggregate":
		policies := make([]string, 0, len(p.Policies))
		for _, name := range p.Policies {
			id, ok := ids.policies[name]
			if !ok {
				return nil, fmt.Errorf("policy %q not found", name)
			}
			policies = append(policies, id)
		}
		body["policies"] = policies
		body["decisionStrategy"] = p.DecisionStrategy
	}
	return body, nil
}

func (s *AuthzSyncer) permissionBody(p PermissionRule, ids *idMaps) map[string]any {
	body := map[string]any{
		"name":             p.Name,
		"decisionStrategy": p.DecisionStrategy,
	}

	resources := make([]string, 0, len(p.Resources))
	for _, name := range p.Resources {
		if id, ok := ids.resources[name]; ok {
			resources = append(resources, id)
		}
	}
	if len(resources) > 0 {
		body["resources"] = resources
	}
	if p.ResourceType != "" {
		body["resourceType"] = p.ResourceType
	}

	scopes := make([]string, 0, len(p.Scopes))
	for _, name := range p.Scopes {
		if id, ok := ids.scopes[name]; ok {
			scopes = append(scopes, id)
		}
	}
	if len(scopes) > 0 {
		body["scopes"] = scopes
	}

	policies := make([]string, 0, len(p.Policies))
	for _, name := range p.Policies {
		if id, ok := ids.policies[name]; ok {
			policies = append(policies, id)
		}
	}
	body["policies"] = policies
	return body
}

// Export renders the live realm as a spec file, so an existing hand-clicked
// realm can be captured into version control as a starting baseline.
func (s *AuthzSyncer) Export() (*AuthzSpec, error) {
	if err := s.load(); err != nil {
		return nil, err
	}

	spec := &AuthzSpec{Client: s.spec.Client}
	for _, sc := range s.current.Scopes {
		spec.Scopes = append(spec.Scopes, sc.Name)
	}
	for _, r := range s.current.Resources {
		scopes := make([]string, 0, len(r.Scopes))
		for _, sc := range r.Scopes {
			scopes = append(scopes, sc.Name)
		}
		spec.Resources = append(spec.Resources, ResourceRule{
			Name: r.Name, DisplayName: r.DisplayName, Type: r.Type,
			URIs: r.URIs, Scopes: scopes, Attributes: r.Attributes,
		})
	}
	for _, p := range s.current.Policies {
		switch p.Type {
		case "scope", "resource":
			spec.Permissions = append(spec.Permissions, permissionFromConfig(p.Name, p.Type, p.DecisionStrategy, p.Config))
		case "js":
			continue // Keycloak's built-in Default Policy; not reproducible on 26
		default:
			spec.Policies = append(spec.Policies, policyFromConfig(p.Name, p.Type, p.Logic, p.DecisionStrategy, p.Config))
		}
	}

	roleNames := map[string]bool{}
	for _, p := range spec.Policies {
		for _, r := range p.Roles {
			roleNames[r] = true
		}
		for _, g := range p.Groups {
			spec.Groups = appendUnique(spec.Groups, g)
		}
	}
	for name := range roleNames {
		spec.RealmRoles = append(spec.RealmRoles, name)
	}
	sort.Strings(spec.RealmRoles)
	sort.Strings(spec.Groups)
	return spec, nil
}

func appendUnique(list []string, v string) []string {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}

// EvaluateFor asks Keycloak's policy-evaluation endpoint how a given user
// would fare on a set of (resource, scope) pairs. It is read-only, and it is
// the fastest way to prove a spec change did what you intended without
// logging in as each test user.
func (s *AuthzSyncer) EvaluateFor(username string, perms []Permission) (map[string]string, error) {
	if err := s.load(); err != nil {
		return nil, err
	}
	userID, err := s.admin.UserID(username)
	if err != nil {
		return nil, err
	}

	_, resourceIDs, _, err := s.fetchIDMaps()
	if err != nil {
		return nil, err
	}

	out := make(map[string]string, len(perms))
	for _, p := range perms {
		id, ok := resourceIDs[p.Resource]
		if !ok {
			out[p.String()] = "RESOURCE_NOT_FOUND"
			continue
		}
		body := map[string]any{
			"userId":       userID,
			"clientId":     s.rsID,
			"entitlements": false,
			"context":      map[string]any{"attributes": map[string]any{}},
			"resources": []map[string]any{{
				"_id":    id,
				"name":   p.Resource,
				"scopes": []map[string]string{{"name": p.Scope}},
			}},
		}
		var result struct {
			Results []struct {
				Status string `json:"status"`
			} `json:"results"`
		}
		if err := s.admin.do("POST", s.base()+"/policy/evaluate", body, &result); err != nil {
			return nil, fmt.Errorf("evaluating %s for %s: %w", p, username, err)
		}
		if len(result.Results) == 0 {
			out[p.String()] = "NO_RESULT"
			continue
		}
		out[p.String()] = result.Results[0].Status
	}
	return out, nil
}
