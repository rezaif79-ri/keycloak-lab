# Keycloak Access Control Lab

Companion setup guide to `CLAUDE.md` (read that first for the architecture
and the full access-control model table).

## 1. Start Keycloak + Postgres

```bash
docker compose up -d
```

- Keycloak admin console: http://localhost:8180/admin (`admin` / `admin123`)
- pgAdmin: http://localhost:5480 (`admin@local.dev` / `admin123`)

## 2. Configure Keycloak (one-time, via admin console)

Go to http://localhost:8180/admin and log in with `admin` / `admin123`.

### 2.1 Create the realm

Realm dropdown (top-left) → **Create Realm** → name `demo-realm` → **Create**.
Stay inside `demo-realm` for every step below.

### 2.2 Create realm roles

**Realm roles** → **Create role**, twice:

- `document-viewer`
- `document-admin`

### 2.3 Create the frontend client (public)

**Clients** → **Create client**

- Client type: `OpenID Connect`
- Client ID: `kc-lab-frontend`
- Next → **Client authentication: OFF** (this makes it public — a SPA can't
  keep a secret, so it authenticates via redirect URI matching instead)
- **Standard flow: ON**, all other flows OFF
- Next → **Login settings**:
  - Valid redirect URIs: `http://localhost:5273/*`
  - Web origins: `http://localhost:5273`
- Save

### 2.4 Create the backend client (confidential)

**Clients** → **Create client**

- Client type: `OpenID Connect`
- Client ID: `kc-lab-backend`
- Next → **Client authentication: ON** (this makes it confidential — it can
  hold a secret, since it's a server, not a browser)
- **Standard flow: OFF**, **Service accounts roles: ON** (needed so the
  backend itself can call Keycloak's Authorization Services APIs),
  **Authorization: ON** — this last toggle is what unlocks the
  **Authorization** tab in the next step
- Next → Login settings can be left blank (this client never handles a
  browser redirect)
- Save
- Go to the **Credentials** tab → copy the **Client secret** → paste it into
  `backend/.env` as `KEYCLOAK_CLIENT_SECRET`

### 2.5 Define scopes (actions)

On `kc-lab-backend` → **Authorization** tab → **Scopes** → **Create scope**, twice:

- `document:GetObject`
- `document:Admin`

### 2.6 Define resources (with tags as attributes)

**Authorization** → **Resources** → **Create resource**

**Resource 1:**

- Name: `document:invoice-1`
- Type: `document`
- Scopes: attach both `document:GetObject` and `document:Admin`
- Attributes (the "tags"):
  - `department` = `finance`
  - `owner` = `alice`

**Resource 2** (repeat with different values):

- Name: `document:invoice-2`
- Type: `document`
- Scopes: same two
- Attributes:
  - `department` = `finance`
  - `owner` = `bob`

### 2.7 Create policies

**Authorization** → **Policies** → **Create policy**

**Role policies** (identity-based, backs RBAC on `/api/documents`):

- `policy-document-viewer` → Role Policy → Realm Roles: `document-viewer`
- `policy-document-admin` → Role Policy → Realm Roles: `document-admin`

**Tag policy** (attribute-based, backs `GET /api/documents/:id`):

The image pinned in `docker-compose.yml` is `quay.io/keycloak/keycloak:26.0`.
Script-based providers (JS policies included) were removed upstream as of
this version, not just gated behind a flag — "Create policy" on this build
won't offer a JavaScript option at all. Use the built-in Group Policy
fallback below; it's the mechanism CLAUDE.md row #7 already names for this
exact situation.

1. **Groups** → **Create group** → `dept-finance`.
2. Put every finance test user in it (do this while creating them in §2.9,
   or come back and add them after) — group membership is what this policy
   checks, not the `department` user attribute. Keep setting the attribute
   too if you like (harmless, useful for display), but it no longer gates
   anything.
3. **Authorization** → **Policies** → **Create policy** → **Group**:
   - Name: `policy-tag-department`
   - Groups: `dept-finance` → **Extend to children: OFF**

This isn't a generic runtime comparison of two arbitrary attribute values
the way the JS snippet was — it's "this resource's permission is wired to
the finance group," decided per-resource at permission-binding time (§2.8)
rather than per-evaluation. That's fine for two fixed documents in one
department; if you outgrow it, the real replacement is a custom Java SPI
Policy Provider (compiled, deployed as a JAR) — heavier than this lab needs
today.

<details>
<summary>If you're on a Keycloak build that still has the JS provider</summary>

```javascript
var context = $evaluation.getContext();
var identity = context.getIdentity();
var permission = $evaluation.getPermission();
var resource = permission.getResource();

var userDept = identity.getAttributes().getValue("department").asString(0);
var resourceDept = resource.getAttribute("department")[0];

if (userDept && resourceDept && userDept === resourceDept) {
  $evaluation.grant();
} else {
  $evaluation.deny();
}
```

Name it `policy-tag-department` and skip the Group steps above.

</details>

**Ownership policy** (ReBAC/DAC, backs `POST /api/documents/:id/share`):

Same cause, same fix-shape: no JS provider on this image, and ownership is
inherently a per-resource, per-user comparison — exactly what a Group/Role
policy can't express (they evaluate the same for every resource). The
honest built-in fallback is a **User Policy per owner**, one per document:

- **Authorization** → **Policies** → **Create policy** → **User**:
  - `policy-owner-alice` → Users: `alice`
  - `policy-owner-bob` → Users: `bob`

This only works because the lab has two fixed documents with two fixed
owners — a new document means a new policy, so it doesn't scale past a
handful of resources. Bind each to its matching document's Admin permission
in §2.8 (unlike the tag policy above, these are **not** shared across both
resources).

<details>
<summary>If you're on a Keycloak build that still has the JS provider</summary>

```javascript
var context = $evaluation.getContext();
var identity = context.getIdentity();
var permission = $evaluation.getPermission();
var resource = permission.getResource();

var username = identity.getAttributes().getValue("username").asString(0);
var resourceOwner = resource.getAttribute("owner")[0];

if (username && resourceOwner && username === resourceOwner) {
  $evaluation.grant();
} else {
  $evaluation.deny();
}
```

Name it `policy-resource-owner` and reuse it across both resources' Admin
permissions instead of creating per-owner User Policies.

</details>

### 2.8 Create permissions (bind resource + scope + policies)

**Authorization** → **Permissions** → **Create permission** → **Scope-based
permission** — not Resource-based: that type has no Scopes field at all
(it grants the whole resource under one policy set regardless of which
scope was requested), so it can't express "GetObject and Admin on the same
resource, gated by different policies," which is exactly what we need here.

**`perm-invoice1-getobject`**

- Resources: `document:invoice-1`
- Scopes: `document:GetObject`
- Apply Policy: `policy-document-viewer` AND `policy-tag-department`
- Decision Strategy: `Unanimous`

**`perm-invoice1-admin`**

- Resources: `document:invoice-1`
- Scopes: `document:Admin`
- Apply Policy: `policy-document-admin` AND `policy-owner-alice`
  (or `policy-resource-owner` if you're on the JS-provider path)
- Decision Strategy: `Unanimous`

**`perm-invoice2-getobject`**

- Resources: `document:invoice-2`
- Scopes: `document:GetObject`
- Apply Policy: `policy-document-viewer` AND `policy-tag-department`
- Decision Strategy: `Unanimous`

**`perm-invoice2-admin`**

- Resources: `document:invoice-2`
- Scopes: `document:Admin`
- Apply Policy: `policy-document-admin` AND `policy-owner-bob`
  (or `policy-resource-owner` if you're on the JS-provider path)
- Decision Strategy: `Unanimous`

Note the asymmetry: the two `getobject` permissions point at the *same*
`policy-tag-department` (department doesn't vary per document here — both
are `finance`), but the two `admin` permissions each point at a *different*
owner policy, because ownership does vary per document. Don't copy-paste
the owner policy across both like you can with the tag policy.

### 2.9 Create test users

**Users** → **Add user**, create at least two:

**`viewer-user`**

- Role mapping tab → assign `document-viewer`
- Groups tab → join `dept-finance` (this is what `policy-tag-department`
  actually checks now — see §2.7)
- Attributes tab → `department` = `finance` (optional, display only)
- Credentials tab → Set password (e.g. `testpass123`), **Temporary: OFF**

**`admin-user`**

- Role mapping tab → assign `document-admin`
- Groups tab → join `dept-finance`
- Attributes tab → `department` = `finance` (optional, display only)
- Credentials tab → same as above

The share/ownership demo needs two more users with **literal usernames
matching the `owner` resource attributes from §2.6** — `policy-owner-alice`
and `policy-owner-bob` (or the JS `policy-resource-owner`, which compares
against the username claim the same way) only pass for users actually named
`alice`/`bob`:

**`alice`** — Role mapping → `document-admin`, Groups → `dept-finance`,
password set same as above. Logging in as `alice` and hitting
`POST /documents/invoice-1/share` should PERMIT (role + ownership both
pass); the same call against `invoice-2` should DENY (role passes,
ownership doesn't — alice isn't `invoice-2`'s owner).

**`bob`** — same setup, mirrors `alice` for `invoice-2`.

To see denials as well as approvals on the RBAC/ABAC pages too, create a
further user with no group membership (fails the tag policy on both
documents, since they're not in `dept-finance`) and no assigned role (fails
RBAC on `/api/documents` entirely).

### 2.10 Sanity-check before touching the frontend

**Authorization** → **Evaluate** tab on `kc-lab-backend`. Pick `viewer-user`,
resource `document:invoice-1`, scopes `document:GetObject` and
`document:Admin`, click Evaluate — expect `PERMIT` on the first, `DENY` on
the second (viewer-user lacks `document-admin` and isn't the owner). Confirm
this before running the actual frontend/backend, since it isolates policy
misconfiguration from application bugs.

## 3. Run the backend

```bash
cd backend
cp .env.example .env    # fill in KEYCLOAK_CLIENT_SECRET
go mod tidy
go run main.go
```

Backend listens on http://localhost:9090. Check http://localhost:9090/health.

## 4. Run the frontend

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

Frontend on http://localhost:5273. Log in, then visit each demo page from
the home screen to see RBAC, ABAC, and ReBAC/DAC checks succeed or fail
depending on the test user's roles/attributes and which document you hit.

## 5. Inspecting the databases directly

```bash
# Keycloak's own schema
psql -h localhost -p 5532 -U keycloak -d keycloak

# This app's own domain data (once you wire app-db into the backend)
psql -h localhost -p 5533 -U appuser -d appdb
```

Or use pgAdmin at http://localhost:5480 and add both servers using the
same host/port/credentials.
