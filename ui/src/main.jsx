import React, { useState, useEffect } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'

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

  // Check URL for OAuth callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    if (code) {
      fetch(`/api/auth/github/callback?code=${code}&state=${state || ''}`)
        .then(r => r.json())
        .then(data => {
          if (data.session_token) {
            setSession(data.session_token, data.tenant_id);
            setSessionState({ token: data.session_token, tenantId: data.tenant_id });
            window.history.replaceState({}, '', '/');
            if (data.api_key) {
              setSuccess(`Account created! Your API key: ${data.api_key}`);
            }
          }
        })
        .catch(() => setError('GitHub authentication failed'));
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
        .auth-btn-github { background: #24292e; border-color: #30363d; }
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
              <span style={{ marginRight: '8px' }}>&#9679;</span> Sign in with GitHub
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
              <span style={{ marginRight: '8px' }}>&#9679;</span> Sign up with GitHub
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
    const slug = path.split('/dashboard/')[1];
    return <PublicDashboard slug={slug} />;
  }

  // Main app with auth
  return (
    <AuthGate>
      <App />
    </AuthGate>
  );
}

// Lazy-loaded public dashboard
function PublicDashboard({ slug }) {
  const [data, setData] = React.useState(null);
  const [error, setError] = React.useState('');

  React.useEffect(() => {
    fetch(`/api/dashboard/public/${slug}`)
      .then(r => {
        if (!r.ok) throw new Error(r.status === 403 ? 'This dashboard is not public' : 'Dashboard not found');
        return r.json();
      })
      .then(setData)
      .catch(e => setError(e.message));
  }, [slug]);

  if (error) return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#e2e8f0', fontFamily: 'Inter, sans-serif' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>404</div>
        <div style={{ color: 'rgba(255,255,255,0.5)' }}>{error}</div>
      </div>
    </div>
  );

  if (!data) return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'rgba(255,255,255,0.5)', fontFamily: 'Inter, sans-serif' }}>
      Loading...
    </div>
  );

  const { stats, chain_integrity, violation_breakdown, recent_actions, tenant_name } = data;

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0a0e1a 0%, #0f172a 40%, #1a1040 100%)', color: '#e2e8f0', fontFamily: 'Inter, sans-serif', padding: '40px 20px' }}>
      <div style={{ maxWidth: '900px', margin: '0 auto' }}>
        <div style={{ marginBottom: '40px', textAlign: 'center' }}>
          <div style={{ fontSize: '12px', fontWeight: 700, letterSpacing: '3px', color: 'rgba(255,255,255,0.3)', marginBottom: '8px' }}>VARGATE PUBLIC AUDIT</div>
          <div style={{ fontSize: '28px', fontWeight: 700 }}>{tenant_name}</div>
          <div style={{ fontSize: '13px', color: 'rgba(255,255,255,0.4)', marginTop: '4px' }}>
            Chain integrity: <span style={{ color: chain_integrity.valid ? '#10b981' : '#ef4444' }}>{chain_integrity.valid ? 'INTACT' : 'BROKEN'}</span>
            {' '} | {chain_integrity.record_count} records
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '32px' }}>
          {[
            { label: 'Total Actions', value: stats.total_actions, color: '#818cf8' },
            { label: 'Allowed', value: stats.allowed, color: '#10b981' },
            { label: 'Denied', value: stats.denied, color: '#ef4444' },
          ].map(s => (
            <div key={s.label} style={{ padding: '20px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.06)', textAlign: 'center' }}>
              <div style={{ fontSize: '28px', fontWeight: 700, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.4)', marginTop: '4px' }}>{s.label}</div>
            </div>
          ))}
        </div>

        {Object.keys(violation_breakdown).length > 0 && (
          <div style={{ padding: '20px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.06)', marginBottom: '32px' }}>
            <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'rgba(255,255,255,0.5)' }}>Violation Breakdown</div>
            {Object.entries(violation_breakdown).sort((a, b) => b[1] - a[1]).map(([v, count]) => (
              <div key={v} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: '13px' }}>
                <span style={{ color: '#f59e0b' }}>{v}</span>
                <span style={{ color: 'rgba(255,255,255,0.5)' }}>{count}</span>
              </div>
            ))}
          </div>
        )}

        <div style={{ padding: '20px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '12px', color: 'rgba(255,255,255,0.5)' }}>Recent Actions</div>
          {recent_actions.map(a => (
            <div key={a.action_id} style={{ display: 'flex', gap: '12px', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: '13px', alignItems: 'center' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: a.decision === 'allow' ? '#10b981' : '#ef4444', flexShrink: 0 }} />
              <span style={{ flex: 1 }}>{a.tool}.{a.method}</span>
              <span style={{ color: 'rgba(255,255,255,0.4)' }}>{a.agent_id}</span>
              <span style={{ color: 'rgba(255,255,255,0.3)', fontSize: '12px' }}>{new Date(a.created_at).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>

        <div style={{ textAlign: 'center', marginTop: '40px', fontSize: '12px', color: 'rgba(255,255,255,0.2)' }}>
          Powered by <a href="https://vargate.ai" style={{ color: '#818cf8', textDecoration: 'none' }}>Vargate</a> — AI Agent Governance
        </div>
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Router />
  </React.StrictMode>,
)
