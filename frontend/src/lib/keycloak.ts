import Keycloak from 'keycloak-js';

// A single shared instance, initialized once in main.tsx. Every component
// imports this rather than constructing its own — Keycloak's silent-refresh
// iframe and token state are process-wide, not per-component.
const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL ?? 'http://localhost:8180',
  realm: import.meta.env.VITE_KEYCLOAK_REALM ?? 'demo-realm',
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID ?? 'kc-lab-frontend',
});

export default keycloak;
