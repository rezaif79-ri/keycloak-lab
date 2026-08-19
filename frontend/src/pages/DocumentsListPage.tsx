import { useEffect, useState } from 'react';
import { apiCall } from '../lib/api';

interface Document {
  id: string;
  title: string;
  department: string;
  owner: string;
}

// Demonstrates RBAC (#1): the backend's /api/documents route is gated by
// middleware.RequireRealmRole("document-viewer") — a cheap, JWT-only check,
// no call out to Keycloak's authorization engine on this path.
export default function DocumentsListPage() {
  const [result, setResult] = useState<{ status: number; documents?: Document[]; error?: string } | null>(null);

  useEffect(() => {
    apiCall<{ documents: Document[] }>('/api/documents').then((res) => {
      setResult({ status: res.status, documents: res.data?.documents, error: (res.data as any)?.error });
    });
  }, []);

  if (!result) return <p>Loading…</p>;

  return (
    <div>
      <h1>RBAC demo — document list</h1>
      <p>
        Backend check: <code>RequireRealmRole("document-viewer" or "document-admin")</code>. Response status:{' '}
        <strong>{result.status}</strong>
      </p>
      {result.error && <p className="error-banner">Denied: {result.error}</p>}
      {result.documents && (
        <ul>
          {result.documents.map((d) => (
            <li key={d.id}>
              {d.title} — department: {d.department}, owner: {d.owner}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
