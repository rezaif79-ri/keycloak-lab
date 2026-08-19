import { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import keycloak from '../lib/keycloak';

interface ProtectedRouteProps {
  children: ReactNode;
  requiredRole?: string; // single-role shorthand — equivalent to requiredRoles={[requiredRole]}
  requiredRoles?: string[]; // client-side UX gate only — the backend re-checks
                             // every call via RBAC/ABAC middleware regardless.
                             // Never treat this prop as the security boundary.
  requireAll?: boolean; // true = user must hold every role in requiredRoles.
                         // false (default) = any one role is sufficient.
}

export default function ProtectedRoute({
  children,
  requiredRole,
  requiredRoles,
  requireAll = false,
}: ProtectedRouteProps) {
  if (!keycloak.authenticated) {
    return <Navigate to="/login" replace />;
  }

  const roles = requiredRoles ?? (requiredRole ? [requiredRole] : []);
  const hasAccess =
    roles.length === 0 ||
    (requireAll
      ? roles.every((role) => keycloak.hasRealmRole(role))
      : roles.some((role) => keycloak.hasRealmRole(role)));

  if (!hasAccess) {
    return (
      <div className="denied-panel">
        <h2>Access denied</h2>
        <p>
          Your account is missing the {requireAll ? 'required' : 'necessary'} realm{' '}
          {roles.length > 1 ? 'roles' : 'role'}:{' '}
          {roles.map((role) => (
            <code key={role}>{role} </code>
          ))}
          This is a client-side hint only — the backend independently
          enforces this via RBAC middleware.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
