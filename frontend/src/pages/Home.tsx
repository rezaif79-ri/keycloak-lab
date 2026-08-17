import { Link } from 'react-router-dom';
import keycloak from '../lib/keycloak';

export default function Home() {
  const roles = keycloak.tokenParsed?.realm_access?.roles ?? [];

  return (
    <div className="home-page">
      <h1>Welcome, {keycloak.tokenParsed?.preferred_username}</h1>
      <p>Your realm roles: {roles.length ? roles.join(', ') : '(none)'}</p>

      <h2>Access control demos</h2>
      <ul className="demo-list">
        <li>
          <Link to="/documents">RBAC — role-based list</Link>
          <p>Requires the <code>document-viewer</code> realm role, checked from the JWT alone.</p>
        </li>
        <li>
          <Link to="/documents/invoice-1">ABAC — tag-based single document</Link>
          <p>Requires your <code>department</code> user attribute to match the document's <code>department</code> tag, checked live against Keycloak.</p>
        </li>
        <li>
          <Link to="/documents/invoice-1/share">ReBAC / DAC — share a document</Link>
          <p>Only the document's registered owner can grant access to it.</p>
        </li>
      </ul>
    </div>
  );
}
