# CLAUDE.md — Keycloak Access Control Lab

This file is the project brief and architectural contract for Claude (or any
engineer) working in this repo. It's a learning sandbox: a React frontend +
Go/Gin backend + Keycloak, built to explore every major access-control model,
using AWS IAM as the reference vocabulary since that's the mental model this
was scoped against.

---

## 1. Goal

Demonstrate, with working code, how each access-control paradigm below maps
onto Keycloak primitives, and expose one demo page/endpoint per paradigm so
the difference is visible in practice, not just in docs.

## 2. Access control models covered

AWS IAM is actually a blend of several of these, which is why "do it like
AWS" undersells how many distinct models are in play. Implementing this
properly means covering all of them, since a real platform mixes them too.

| # | Model | AWS analogy | Keycloak mechanism | Demo page/endpoint |
|---|---|---|---|---|
| 1 | **RBAC** (Role-Based Access Control) | Identity-based policy attached to an IAM Role | Realm Roles / Client Roles + Role Policy | `/documents` (viewer vs admin role) |
| 2 | **ABAC** (Attribute-Based Access Control) | Tag-based conditions (`aws:ResourceTag/x == aws:PrincipalTag/x`) | User Attributes + Resource Attributes + JS/Rule Policy | `/documents/:id` (department tag match) |
| 3 | **ReBAC** (Relationship-Based Access Control) | Resource-based policy (e.g. S3 bucket policy naming a specific principal), or Google Zanzibar-style "is owner of" | UMA Resource ownership (`resource.getOwner()`) + custom Policy checking the caller IS the resource owner | `/documents/:id/share` (only the resource owner can share it) |
| 4 | **PBAC** (Policy-Based Access Control) | The IAM policy engine itself (combining statements w/ Allow/Deny + Conditions) | Keycloak **Permissions** (Resource + Scope + Policies + Decision Strategy) | The whole Authorization Services layer — every permission below is a "policy" in this sense |
| 5 | **DAC** (Discretionary Access Control) | Resource owner can grant access to others (S3 object ACL granted by the object owner) | UMA **Permission Ticket** flow — resource owner grants a specific user a specific scope | `/documents/:id/share` |
| 6 | **MAC** (Mandatory Access Control) | Not native to AWS IAM (more an OS/SELinux/military-classification concept) — closest AWS analog is a Permission Boundary that caps what any identity-based policy can grant, no matter what | Client Scope restriction / **Client Policies** that hard-cap which scopes a client can ever request, regardless of user policy | Documented only — not usually user-facing |
| 7 | **Group-based access** | IAM Groups | Keycloak **Groups** (+ Group Policy) | Alternative implementation path for #1 when JS policies aren't available |
| 8 | **Session / context-based control** | IAM Condition keys like `aws:MultiFactorAuthPresent`, `aws:SourceIp`, time-of-day conditions | Keycloak **Time Policy**, **Client Policy**, custom claims checked in JS/Rule Policy (e.g. `acr` claim for MFA level) | `/admin/danger-zone` (requires step-up MFA — see §6) |
| 9 | **Resource-based policy** | S3 bucket policy / SQS queue policy (the resource itself carries the policy, not the identity) | A **Permission** scoped to one specific Resource (not a Resource *Type*) | `/documents/:id` uses a per-resource Permission |
| 10 | **Federation / cross-account trust** | AssumeRole via IAM Role trust policy, or federation via SAML/OIDC IdP | Keycloak **Identity Brokering** (federate to Google/GitHub/another Keycloak realm) | Out of scope for v1, documented as a "next step" |

If more come up during implementation (e.g. **XACML**-style externalized
policy evaluation, which is essentially what UMA/Permission Tickets already
give you), add a row rather than silently deviating from this table.

> **JS/Rule Policy availability:** the image pinned in `docker-compose.yml`
> (`quay.io/keycloak/keycloak:26.0`) has script-based policy providers
> removed upstream — there is no JavaScript option in Create Policy on this
> build, not even behind a feature flag. Row #2's ABAC tag-match and row
> #3's ownership check are therefore implemented with the built-in
> fallbacks instead: row #7's **Group Policy** (one group per department)
> for #2, and a **User Policy per resource owner** for #3. Both trade
> generic runtime attribute comparison for per-resource policy wiring —
> concrete steps and the tradeoff are spelled out in `README.md` §2.7. If a
> future need requires true dynamic comparison again, the replacement is a
> custom Java SPI Policy Provider, not the JS provider.

## 3. Architecture

```
frontend (React, Vite, TS)  --OIDC-->  Keycloak :8180  --stores-->  keycloak-db (Postgres) :5532
        |                                    |
        | Bearer <access_token>              | UMA ticket exchange (RPT)
        v                                    v
backend (Go + Gin) :9090  <-- validates JWT via JWKS, calls Keycloak Authorization Services -->
        |
        v
   app-db (Postgres) :5533   (app's own domain data — NOT Keycloak's tables)
```

- Keycloak is the **only** source of truth for identity, roles, groups,
  and authorization decisions (resources/scopes/policies/permissions).
- The Go backend never re-implements policy logic locally — it either
  validates a JWT's embedded claims (cheap, for RBAC) or calls Keycloak's
  UMA endpoint (for ABAC/ReBAC/resource-based checks that need live
  evaluation against resource attributes).
- `app-db` holds only application data (e.g. the invoice/document records
  themselves) with a `keycloak_resource_id` column linking each row to its
  Keycloak-registered Resource. Keycloak never stores your business data;
  your app never stores authorization decisions.

## 4. Backend conventions (Go + Gin)

Deviates from the Clean-Architecture/Echo/GORM pattern used in this
engineer's other projects (`identity-portal`) **on purpose** — this repo
uses **Gin** and a flatter structure, since it's an isolated learning
sandbox, not part of that platform. Don't port Echo/Fx/Goose patterns in
here unless explicitly asked.

- `middleware/auth.go` — validates the incoming JWT against Keycloak's JWKS
  endpoint (`/realms/{realm}/protocol/openid-connect/certs`), caches keys,
  rejects on `exp`/`iss`/`aud` mismatch. Populates `c.Set("claims", ...)`.
- `middleware/rbac.go` — reads `realm_access.roles` / `resource_access` off
  the already-validated claims. No network call — this is the cheap,
  fast-path check for #1 (RBAC).
- `middleware/abac.go` — for endpoints needing ABAC/ReBAC/resource-based
  checks, exchanges the user's token for a **Requesting Party Token (RPT)**
  via the `urn:ietf:params:oauth:grant-type:uma-ticket` grant, asking
  Keycloak "can this user do `document:GetObject` on resource `document:{id}`?"
  This is the expensive but source-of-truth path — every project needs both
  a cheap and an expensive check, this is where you show you understand
  that trade-off.
- Every handler returns wrapped errors (`fmt.Errorf("...: %w", err)`), no
  swallowed errors, explicit `defer rows.Close()` after error checks — same
  standards as the rest of this engineer's Go work even though the layering
  differs.
- `cmd/authz-sync` — config-as-code for the Authorization Services objects
  (resources, scopes, policies, permissions), reconciling the realm onto
  `authz/demo-realm.json` via the Admin REST API. This is the **only**
  sanctioned migration-shaped thing in this repo; the no-Goose rule above
  still holds for app data, and this tool manages Keycloak config, not
  `app-db` schema. It is desired-state and idempotent, not a versioned
  up/down ladder, because policy config has no meaningful "down". See
  `README.md` §2.11 for why the spec is name-keyed and what it validates.

## 5. Frontend conventions (React + TypeScript + Vite)

- Uses `keycloak-js` directly (not NextAuth — there's no Next.js here by
  request). `src/lib/keycloak.ts` holds a single shared `Keycloak` instance.
- "Login" and "Register" pages are **thin wrappers that redirect into
  Keycloak's hosted login/registration UI** (`keycloak.login()` /
  `keycloak.register()`) — Keycloak owns the actual credential UI. This is
  the correct integration pattern (never hand-roll a password form that
  talks to Keycloak's token endpoint directly from a public client); the
  custom pages exist so you have a branded entry point and a place to show
  loading/error states.
- `components/ProtectedRoute.tsx` gates on `keycloak.authenticated`, and
  optionally on a required realm role, redirecting unauthenticated users
  into login.
- Each demo page calls the backend with `Authorization: Bearer <token>` and
  renders the raw 200/403 response distinctly, so the access-control
  boundary is visible, not hidden behind a generic error toast.
- Strict TypeScript, no `any`; API response shapes defined as `interface`s
  matching the Go structs' JSON tags exactly.

## 6. Step-up / session-based control (item #8)

Keycloak supports **step-up authentication** via `acr` (Authentication
Context Class Reference) claims — e.g. require `acr=gold` (meaning: user
completed MFA) to reach a "danger zone" page, separate from just checking a
role. This models AWS's `aws:MultiFactorAuthPresent` condition key. Wire
this up last, after RBAC/ABAC are working — it needs a **Conditional OTP**
authentication flow configured in the realm first, which is its own
mini-project.

## 7. Non-standard ports (reference)

| Service | Port | Why exposed |
|---|---|---|
| Keycloak UI/API | `8180` | Admin console + OIDC endpoints |
| Keycloak's Postgres | `5532` | So you can `psql`/inspect Keycloak's own schema if curious |
| App Postgres | `5533` | Inspect your own domain tables directly |
| pgAdmin | `5480` | GUI for both Postgres instances |
| Go backend | `9090` | REST API |
| React frontend | `5273` | Vite dev server |

## 8. Explicit non-goals for v1

- No production TLS/cert setup — this is `start-dev` Keycloak, HTTP only.
- No refresh-token rotation hardening — access tokens are short-lived and
  refreshed via `keycloak-js`'s built-in silent refresh, nothing custom.
- Identity brokering (federating to Google/GitHub) is documented (see
  table row #10) but not implemented — add a new `CLAUDE.md` section before
  starting that, don't bolt it on silently.
