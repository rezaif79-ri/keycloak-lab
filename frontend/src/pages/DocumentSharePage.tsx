import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiCall } from '../lib/api';

// Demonstrates ReBAC + DAC (#3 / #5): only the resource's registered owner
// can perform the `document:Admin` scope (used here to model "share"),
// checked via the same UMA path as the ABAC demo but against an ownership
// policy instead of a tag-matching one.
export default function DocumentSharePage() {
  const { id } = useParams<{ id: string }>();
  const [result, setResult] = useState<{ status: number; body: any } | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleShare() {
    setLoading(true);
    const res = await apiCall(`/api/documents/${id}/share`, { method: 'POST' });
    setResult({ status: res.status, body: res.data });
    setLoading(false);
  }

  return (
    <div>
      <h1>ReBAC / DAC demo — share document {id}</h1>
      <p>
        Backend check: UMA ticket for scope <code>document:Admin</code>, granted only if you are
        this document's registered owner.
      </p>
      <button onClick={handleShare} disabled={loading}>
        {loading ? 'Checking…' : 'Attempt to share'}
      </button>
      {result && (
        <>
          <p>
            Response status: <strong>{result.status}</strong>
          </p>
          {result.status === 403 && (
            <p className="error-banner">Denied — you are not this document's owner.</p>
          )}
          <pre>{JSON.stringify(result.body, null, 2)}</pre>
        </>
      )}
    </div>
  );
}
