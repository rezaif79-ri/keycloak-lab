import keycloak from '../lib/keycloak';

// Same pattern as Login: hands off to Keycloak's hosted registration flow
// (keycloak.register()) rather than posting a signup form to a custom
// endpoint. Keycloak handles password policy, email verification, etc.
export default function Register() {
  return (
    <div className="auth-page">
      <h1>Create an account</h1>
      <p>Registration is handled by Keycloak's built-in registration flow.</p>
      <button className="primary" onClick={() => keycloak.register()}>
        Register
      </button>
      <p className="auth-secondary">
        Already have an account?{' '}
        <button className="link" onClick={() => keycloak.login()}>
          Log in
        </button>
      </p>
    </div>
  );
}
