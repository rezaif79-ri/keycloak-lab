import { Routes, Route } from 'react-router-dom';
import NavBar from './components/NavBar';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import Register from './pages/Register';
import Home from './pages/Home';
import DocumentsListPage from './pages/DocumentsListPage';
import DocumentDetailPage from './pages/DocumentDetailPage';
import DocumentSharePage from './pages/DocumentSharePage';
import keycloak from './lib/keycloak';

export default function App() {
  return (
    <>
      {keycloak.authenticated && <NavBar />}
      <main className="app-content">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Home />
              </ProtectedRoute>
            }
          />
          <Route
            path="/documents"
            element={
              <ProtectedRoute requiredRoles={["document-viewer", "document-admin"]} requireAll={true}>
                <DocumentsListPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/documents/:id"
            element={
              <ProtectedRoute>
                <DocumentDetailPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/documents/:id/share"
            element={
              <ProtectedRoute>
                <DocumentSharePage />
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>
    </>
  );
}
