import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiCall } from '../lib/api';

// Demonstrates ABAC + resource-based policy (#2 / #9): the backend's
// /api/documents/:id route exchanges the user's token for a UMA decision,
// which Keycloak evaluates by comparing the user's `department` attribute
// against the resource's `department` tag — live, not from the JWT.
export default function DocumentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [result, setResult] = useState<{ status: number; body: any } | null>(null);

  useEffect(() => {
    apiCall(`/api/documents/${id}`).then((res) => {
      setResult({ status: res.status, body: res.data });
    });
  }, [id]);

  if (!result) return <p>Loading…</p>;

  return (
    <div>
      <h1>ABAC demo — document {id}</h1>
      <p>
        Backend check: UMA ticket for scope <code>document:GetObject</code> on resource{' '}
        <code>document:{id}</code>. Response status: <strong>{result.status}</strong>
      </p>
      {result.status === 403 && (
        <p className="error-banner">
          Denied by tag policy — your <code>department</code> attribute doesn't match this
          document's <code>department</code> tag.
        </p>
      )}
      <pre>{JSON.stringify(result.body, null, 2)}</pre>
    </div>
  );
}
