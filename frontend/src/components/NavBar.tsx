import { Link } from 'react-router-dom';
import keycloak from '../lib/keycloak';

export default function NavBar() {
  return (
    <nav className="navbar">
      <div className="navbar-links">
        <Link to="/">Home</Link>
        <Link to="/documents">RBAC demo</Link>
        <Link to="/documents/invoice-1">ABAC demo</Link>
        <Link to="/documents/invoice-1/share">ReBAC/DAC demo</Link>
      </div>
      <div className="navbar-user">
        {keycloak.authenticated ? (
          <>
            <span>{keycloak.tokenParsed?.preferred_username}</span>
            <button onClick={() => keycloak.logout({ redirectUri: window.location.origin })}>
              Logout
            </button>
          </>
        ) : (
          <button onClick={() => keycloak.login()}>Login</button>
        )}
      </div>
    </nav>
  );
}
