// Command authz-sync manages a Keycloak client's Authorization Services
// configuration — resources, scopes, policies and permissions — from a
// checked-in spec file instead of the admin console.
//
// It replaces the click-through in README.md §2.5–2.8. The console is fine for
// learning what the objects are; it is a poor way to keep them correct, since
// nothing there diffs, reviews, or replays a configuration.
//
//	go run ./cmd/authz-sync -plan               # show drift, change nothing
//	go run ./cmd/authz-sync -apply              # converge the realm onto the spec
//	go run ./cmd/authz-sync -apply -prune       # also delete objects absent from the spec
//	go run ./cmd/authz-sync -export > authz/demo-realm.json
//	go run ./cmd/authz-sync -evaluate viewer-user
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/joho/godotenv"

	"github.com/rezaif/kc-lab-backend/config"
	"github.com/rezaif/kc-lab-backend/pkg/keycloak"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "authz-sync: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		specPath  = flag.String("spec", "authz/demo-realm.json", "path to the authorization spec file")
		doPlan    = flag.Bool("plan", false, "print the diff between the spec and the live realm, then exit")
		doApply   = flag.Bool("apply", false, "converge the live realm onto the spec")
		doExport  = flag.Bool("export", false, "print the live realm as a spec file")
		prune     = flag.Bool("prune", false, "with -apply, delete live objects the spec does not declare")
		evaluate  = flag.String("evaluate", "", "username to run the realm's permission matrix against (read-only)")
		adminUser = flag.String("admin-user", envOr("KEYCLOAK_ADMIN", "admin"), "Keycloak admin username (master realm)")
		adminPass = flag.String("admin-password", envOr("KEYCLOAK_ADMIN_PASSWORD", "admin123"), "Keycloak admin password")
	)
	flag.Parse()

	if !*doPlan && !*doApply && !*doExport && *evaluate == "" {
		*doPlan = true // safest default: show drift, change nothing
	}

	_ = godotenv.Load()
	cfg := config.Load()

	admin := keycloak.NewAdminClient(cfg.KeycloakBaseURL, cfg.KeycloakRealm, *adminUser, *adminPass)

	// -export does not need a valid spec file, only the client name.
	if *doExport {
		syncer := keycloak.NewAuthzSyncer(admin, &keycloak.AuthzSpec{Client: cfg.ClientID})
		spec, err := syncer.Export()
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(spec)
	}

	spec, err := keycloak.LoadAuthzSpec(*specPath)
	if err != nil {
		return err
	}
	syncer := keycloak.NewAuthzSyncer(admin, spec)

	if *evaluate != "" {
		return runEvaluate(syncer, spec, *evaluate)
	}

	if *doApply {
		actions, err := syncer.Apply(*prune)
		if err != nil {
			return err
		}
		if len(actions) == 0 {
			fmt.Println("no changes — realm already matches", *specPath)
			return nil
		}
		fmt.Printf("applied %d change(s) from %s:\n", len(actions), *specPath)
		for _, a := range actions {
			fmt.Println("  " + a.String())
		}
		return nil
	}

	plan, err := syncer.Plan(*prune)
	if err != nil {
		return err
	}
	fmt.Printf("plan for %s (client %q, realm %q):\n", *specPath, spec.Client, cfg.KeycloakRealm)
	fmt.Println(plan.String())
	if !plan.Empty() {
		fmt.Printf("\n%d change(s) pending — re-run with -apply to converge\n", len(plan.Actions))
	}
	return nil
}

// runEvaluate prints the full (resource × scope) verdict matrix for one user,
// which is the quickest way to confirm a spec change had the intended effect.
func runEvaluate(syncer *keycloak.AuthzSyncer, spec *keycloak.AuthzSpec, username string) error {
	var perms []keycloak.Permission
	for _, r := range spec.Resources {
		for _, sc := range r.Scopes {
			perms = append(perms, keycloak.Permission{Resource: r.Name, Scope: sc})
		}
	}
	sort.Slice(perms, func(i, j int) bool { return perms[i].String() < perms[j].String() })

	results, err := syncer.EvaluateFor(username, perms)
	if err != nil {
		return err
	}

	width := 0
	for _, p := range perms {
		if n := len(p.String()); n > width {
			width = n
		}
	}
	fmt.Printf("permission matrix for %q:\n", username)
	permitted := 0
	for _, p := range perms {
		status := results[p.String()]
		if status == "PERMIT" {
			permitted++
		}
		fmt.Printf("  %-*s  %s\n", width, p.String(), status)
	}
	fmt.Printf("\n%d of %d permitted\n", permitted, len(perms))
	return nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
