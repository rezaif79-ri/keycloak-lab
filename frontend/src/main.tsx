import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import keycloak from './lib/keycloak';
import './styles.css';

// check-sso (not login-required): renders the app for unauthenticated
// visitors too, since /login and /register need to be reachable without
// forcing a redirect loop. ProtectedRoute handles per-page enforcement.
keycloak
  .init({ onLoad: 'check-sso', silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html' })
  .then(() => {
    ReactDOM.createRoot(document.getElementById('root')!).render(
      <React.StrictMode>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </React.StrictMode>,
    );
  })
  .catch((err) => {
    console.error('Keycloak init failed', err);
  });
