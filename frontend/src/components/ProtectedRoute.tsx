import { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import keycloak from '../lib/keycloak';

interface ProtectedRouteProps {
  children: ReactNode;
  requiredRole?: string; // client-side UX gate only — the backend re-checks
                          // every call via RBAC/ABAC middleware regardless.
                          // Never treat this prop as the security boundary.
}

export default function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  if (!keycloak.authenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && !keycloak.hasRealmRole(requiredRole)) {
    return (
      <div className="denied-panel">
        <h2>Access denied</h2>
        <p>
          Your account is missing the realm role <code>{requiredRole}</code>.
          This is a client-side hint only — the backend independently
          enforces this via RBAC middleware.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
