import React, { useState, useEffect } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { setPublicTenantSlug, checkPublicDashboard } from './api'

// ── Auth helpers ─────────────────────────────────────────────────────────────

function getSession() {
  const token = localStorage.getItem('vargate_session');
  const tenantId = localStorage.getItem('vargate_tenant_id');
  if (token && tenantId) return { token, tenantId };
  return null;
}

function setSession(token, tenantId) {
  localStorage.setItem('vargate_session', token);
  localStorage.setItem('vargate_tenant_id', tenantId);
}

function clearSession() {
  localStorage.removeItem('vargate_session');
  localStorage.removeItem('vargate_tenant_id');
  // Also clear legacy PIN auth
  sessionStorage.removeItem('vargate_unlocked');
}

// ── Legacy PIN support (backward compat for demo) ───────────────────────────

const LEGACY_PIN = import.meta.env.VITE_PIN || '284729';
const ENABLE_PIN_FALLBACK = import.meta.env.VITE_ENABLE_PIN !== 'false';

// ── Auth Gate ────────────────────────────────────────────────────────────────

function AuthGate({ children }) {
  const [session, setSessionState] = useState(null);
  const [view, setView] = useState('login'); // login | signup | pin
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Form state
  const [apiKey, setApiKey] = useState('');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [pin, setPin] = useState('');

  useEffect(() => {
    const s = getSession();
    if (s) {
      setSessionState(s);
      return;
    }
    // Legacy PIN check
    if (sessionStorage.getItem('vargate_unlocked') === 'yes') {
      setSessionState({ token: 'pin', tenantId: 'vargate-internal' });
    }
  }, []);

  const handleApiKeyLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const resp = await fetch('/api/auth/session', {
        method: 'POST',
        headers: { 'X-API-Key': apiKey },
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || 'Invalid API key');
      }
      const data = await resp.json();
      setSession(data.session_token, data.tenant_id);
      setSessionState({ token: data.session_token, tenantId: data.tenant_id });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGitHubLogin = async () => {
    setLoading(true);
    setError('');
    try {
      const resp = await fetch('/api/auth/github');
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || 'GitHub OAuth not available');
      }
      const data = await resp.json();
      window.location.href = data.redirect_url;
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const handleEmailSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const resp = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, name }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || 'Signup failed');
      setSuccess('Verification email sent! Check your inbox.');
      setView('login');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handlePinLogin = (digit) => {
    if (pin.length < 6) {
      const newPin = pin + digit;
      setPin(newPin);
      setError('');
      if (newPin.length === 6) {
        setTimeout(() => {
          if (newPin === LEGACY_PIN) {
            sessionStorage.setItem('vargate_unlocked', 'yes');
            setSessionState({ token: 'pin', tenantId: 'vargate-internal' });
          } else {
            setError('Incorrect PIN');
            setPin('');
          }
        }, 150);
      }
    }
  };

  const handleLogout = () => {
    clearSession();
    setSessionState(null);
    setView('login');
  };

  // Check URL for OAuth callback redirect (server redirects here with token in query params)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    const tenantId = params.get('tenant_id');
    if (token && tenantId) {
      setSession(token, tenantId);
      setSessionState({ token, tenantId });
      const isNew = params.get('new_user') === 'true';
      if (isNew) {
        setSuccess('Account created! Check your dashboard settings for your API key.');
      }
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  if (session) {
    return React.cloneElement(children, { session, onLogout: handleLogout });
  }

  // ── Render auth form ──────────────────────────────────────────────────────
  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0a0e1a 0%, #0f172a 40%, #1a1040 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
    }}>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-8px); } 75% { transform: translateX(8px); } }
        .auth-btn { padding: 12px 24px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.05); color: #e2e8f0; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s; width: 100%; }
        .auth-btn:hover { background: rgba(255,255,255,0.1); }
        .auth-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .auth-btn-primary { background: #6366f1; border-color: #6366f1; }
        .auth-btn-primary:hover { background: #5558e6; }
        .auth-btn-github { background: #24292e; border-color: #30363d; display: flex; align-items: center; justify-content: center; gap: 10px; }
        .auth-btn-github:hover { background: #30363d; }
        .auth-input { width: 100%; padding: 12px 16px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.05); color: #e2e8f0; font-size: 14px; outline: none; box-sizing: border-box; }
        .auth-input:focus { border-color: #6366f1; }
        .auth-input::placeholder { color: rgba(255,255,255,0.3); }
        .auth-link { color: #818cf8; cursor: pointer; font-size: 13px; }
        .auth-link:hover { text-decoration: underline; }
        .pin-btn:hover { background: rgba(255,255,255,0.12) !important; }
        .pin-btn:active { background: rgba(255,255,255,0.2) !important; transform: scale(0.95); }
      `}</style>

      <div style={{
        animation: 'fadeIn 0.6s ease-out',
        textAlign: 'center',
        padding: '48px 40px',
        borderRadius: '24px',
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(20px)',
        width: '380px',
      }}>
        <div style={{ fontSize: '14px', fontWeight: 700, letterSpacing: '4px', textTransform: 'uppercase', color: 'rgba(255,255,255,0.3)', marginBottom: '8px' }}>VARGATE</div>
        <div style={{ fontSize: '22px', fontWeight: 600, color: '#e2e8f0', marginBottom: '8px' }}>Audit Dashboard</div>

        {error && <div style={{ color: '#ef4444', fontSize: '13px', marginBottom: '12px', padding: '8px', background: 'rgba(239,68,68,0.1)', borderRadius: '8px' }}>{error}</div>}
        {success && <div style={{ color: '#10b981', fontSize: '13px', marginBottom: '12px', padding: '8px', background: 'rgba(16,185,129,0.1)', borderRadius: '8px' }}>{success}</div>}

        {view === 'login' && (
          <div style={{ marginTop: '24px' }}>
            <form onSubmit={handleApiKeyLogin}>
              <input className="auth-input" type="password" placeholder="API Key (vg-...)" value={apiKey} onChange={e => setApiKey(e.target.value)} style={{ marginBottom: '12px' }} />
              <button className="auth-btn auth-btn-primary" type="submit" disabled={loading || !apiKey}>{loading ? 'Signing in...' : 'Sign in with API Key'}</button>
            </form>

            <div style={{ margin: '20px 0', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.1)' }} />
              <span style={{ color: 'rgba(255,255,255,0.3)', fontSize: '12px' }}>or</span>
              <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.1)' }} />
            </div>

            <button className="auth-btn auth-btn-github" onClick={handleGitHubLogin} disabled={loading} style={{ marginBottom: '12px' }}>
              <svg width="20" height="20" viewBox="0 0 98 96" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg> Sign in with GitHub
            </button>

            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'center', gap: '16px' }}>
              <span className="auth-link" onClick={() => setView('signup')}>Create account</span>
              {ENABLE_PIN_FALLBACK && <span className="auth-link" onClick={() => setView('pin')}>PIN access</span>}
            </div>
          </div>
        )}

        {view === 'signup' && (
          <div style={{ marginTop: '24px' }}>
            <div style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', marginBottom: '20px' }}>Sign up to get your API key and dashboard</div>
            <form onSubmit={handleEmailSignup}>
              <input className="auth-input" type="text" placeholder="Organization name" value={name} onChange={e => setName(e.target.value)} style={{ marginBottom: '12px' }} />
              <input className="auth-input" type="email" placeholder="Work email" value={email} onChange={e => setEmail(e.target.value)} style={{ marginBottom: '12px' }} />
              <button className="auth-btn auth-btn-primary" type="submit" disabled={loading || !email || !name}>{loading ? 'Sending...' : 'Sign up with Email'}</button>
            </form>

            <div style={{ margin: '20px 0', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.1)' }} />
              <span style={{ color: 'rgba(255,255,255,0.3)', fontSize: '12px' }}>or</span>
              <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.1)' }} />
            </div>

            <button className="auth-btn auth-btn-github" onClick={handleGitHubLogin} disabled={loading}>
              <svg width="20" height="20" viewBox="0 0 98 96" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg> Sign up with GitHub
            </button>

            <div style={{ marginTop: '20px' }}>
              <span className="auth-link" onClick={() => setView('login')}>Already have an account? Sign in</span>
            </div>
          </div>
        )}

        {view === 'pin' && (
          <div style={{ marginTop: '24px' }}>
            <div style={{ fontSize: '13px', color: 'rgba(255,255,255,0.35)', marginBottom: '24px' }}>Enter demo PIN</div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', marginBottom: '24px' }}>
              {[0,1,2,3,4,5].map(i => (
                <div key={i} style={{
                  width: '14px', height: '14px', borderRadius: '50%',
                  border: `2px solid ${error ? '#ef4444' : pin.length > i ? '#6366f1' : 'rgba(255,255,255,0.2)'}`,
                  background: pin.length > i ? (error ? '#ef4444' : '#6366f1') : 'transparent',
                  transition: 'all 0.15s ease',
                }} />
              ))}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', maxWidth: '240px', margin: '0 auto' }}>
              {['1','2','3','4','5','6','7','8','9','','0','<'].map((d, i) => (
                d === '' ? <div key={i} /> :
                <button key={i} className="pin-btn" onClick={() => d === '<' ? setPin(pin.slice(0, -1)) : handlePinLogin(d)}
                  style={{ width: '64px', height: '52px', borderRadius: '14px', border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.05)', color: '#e2e8f0', fontSize: '20px', fontWeight: 500, cursor: 'pointer', transition: 'all 0.15s ease', outline: 'none' }}>
                  {d}
                </button>
              ))}
            </div>
            <div style={{ marginTop: '20px' }}>
              <span className="auth-link" onClick={() => setView('login')}>Back to sign in</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Public dashboard route check ─────────────────────────────────────────────

function Router() {
  const path = window.location.pathname;

  // Public dashboard: /dashboard/{slug}
  if (path.startsWith('/dashboard/')) {
    const slug = path.split('/dashboard/')[1].replace(/\/$/, '');
    if (slug) {
      return <PublicDashboardLoader slug={slug} />;
    }
  }

  // Main app with auth
  return (
    <AuthGate>
      <App />
    </AuthGate>
  );
}

// Public dashboard — checks if tenant is public, then renders full App in read-only mode
function PublicDashboardLoader({ slug }) {
  const [status, setStatus] = React.useState('loading'); // loading | public | private | error
  const [tenantName, setTenantName] = React.useState('');

  React.useEffect(() => {
    checkPublicDashboard(slug)
      .then(data => {
        if (data && data.tenant_name) {
          // Tenant is public — set up public viewer mode
          setPublicTenantSlug(slug);
          setTenantName(data.tenant_name);
          setStatus('public');
        } else {
          setStatus('private');
        }
      })
      .catch(() => setStatus('error'));
  }, [slug]);

  if (status === 'loading') {
    return (
      <div style={{ minHeight: '100vh', background: '#0a0e1a', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'rgba(255,255,255,0.5)', fontFamily: 'Inter, sans-serif' }}>
        Loading...
      </div>
    );
  }

  if (status === 'private' || status === 'error') {
    return (
      <div style={{ minHeight: '100vh', background: '#0a0e1a', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#e2e8f0', fontFamily: 'Inter, sans-serif' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>404</div>
          <div style={{ color: 'rgba(255,255,255,0.5)' }}>
            {status === 'private' ? 'This dashboard is not public' : 'Dashboard not found'}
          </div>
          <a href="/dashboard/" style={{ color: '#818cf8', fontSize: '13px', marginTop: '16px', display: 'inline-block' }}>
            Sign in to your dashboard →
          </a>
        </div>
      </div>
    );
  }

  // Public tenant — render full dashboard in read-only mode
  return (
    <App
      session={{ token: null, tenantId: slug, isPublic: true, tenantName }}
      onLogout={null}
    />
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Router />
  </React.StrictMode>,
)
