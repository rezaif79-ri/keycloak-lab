import keycloak from '../lib/keycloak';

// Deliberately does NOT render a password form. Keycloak owns the actual
// credential UI (its hosted login page) — a public SPA client should never
// collect a password and post it to the token endpoint directly. This page
// exists purely as a branded entry point with a clear call to action.
export default function Login() {
  return (
    <div className="auth-page">
      <h1>Keycloak Access Control Lab</h1>
      <p>Sign in to explore RBAC, ABAC, ReBAC and DAC demos.</p>
      <button className="primary" onClick={() => keycloak.login()}>
        Log in
      </button>
      <p className="auth-secondary">
        Don't have an account?{' '}
        <button className="link" onClick={() => keycloak.register()}>
          Register
        </button>
      </p>
    </div>
  );
}
