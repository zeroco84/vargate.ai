import React, { useState, useEffect, useRef } from 'react';
import { parseBundleRevision, fetchMyTenants, switchTenant } from '../api';

export default function Header({ chain, liveMode, setLiveMode, anchorStatus, policy, view, setView, onLogout, session, onTenantSwitch, isPublic }) {
  const valid = chain?.valid;
  const count = chain?.record_count ?? 0;
  const failedId = chain?.failed_at_action_id;
  const anchorConnected = anchorStatus?.blockchain_connected;
  const bundleRev = parseBundleRevision(policy?.revision);

  // Tenant switcher state
  const [tenants, setTenants] = useState([]);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [switching, setSwitching] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    if (isPublic) return;
    fetchMyTenants()
      .then(data => setTenants(data?.tenants || []))
      .catch(() => {});
  }, [session?.tenantId, isPublic]);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleSwitch = async (tenantId) => {
    if (tenantId === session?.tenantId) {
      setDropdownOpen(false);
      return;
    }
    setSwitching(true);
    try {
      const result = await switchTenant(tenantId);
      if (result?.session_token && result?.tenant_id) {
        localStorage.setItem('vargate_session', result.session_token);
        localStorage.setItem('vargate_tenant_id', result.tenant_id);
        if (onTenantSwitch) onTenantSwitch(result);
        setDropdownOpen(false);
      }
    } catch (err) {
      console.error('Tenant switch failed:', err);
    } finally {
      setSwitching(false);
    }
  };

  const currentTenant = tenants.find(t => t.current) || { name: session?.tenantId || '—' };

  // Build status line
  let statusText, statusClass;
  if (!valid && failedId) {
    statusText = `⚠ Chain integrity violation detected — record ${failedId.slice(0, 8)}…`;
    statusClass = 'amber';
  } else {
    const parts = [`● Chain intact`];
    if (anchorConnected) parts.push('Anchored');
    parts.push(`${count} records`);
    statusText = parts.join(' · ');
    statusClass = 'green';
  }

  return (
    <header className="header">
      <div className="header-left">
        <span className="header-logo">VARGATE</span>
        <span className="header-subtitle">{isPublic ? 'Public Audit Dashboard' : 'Supervision Gateway'}</span>
        {isPublic && session?.tenantName && (
          <span style={{ color: 'var(--text-faint)', marginLeft: '8px', fontSize: '0.75rem' }}>
            — {session.tenantName}
          </span>
        )}
      </div>

      <div className="header-center">
        <span className={`status-dot ${statusClass}`} />
        <span style={{ color: statusClass === 'amber' ? 'var(--accent-amber)' : 'var(--text-secondary)' }}>
          {statusText}
        </span>
        {bundleRev.since !== '—' && (
          <span style={{ color: 'var(--text-faint)', marginLeft: '8px' }}>
            Policy active since {bundleRev.since}
          </span>
        )}
      </div>

      <div className="header-right">
        {/* Tenant switcher — hidden for public viewers */}
        {!isPublic && tenants.length > 1 && (
          <div ref={dropdownRef} style={{ position: 'relative' }}>
            <button
              className="header-nav-btn"
              onClick={() => setDropdownOpen(!dropdownOpen)}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                borderColor: dropdownOpen ? 'var(--accent-blue-border)' : undefined,
                background: dropdownOpen ? 'var(--bg-card)' : undefined,
              }}
            >
              <span style={{
                width: '6px', height: '6px', borderRadius: '50%',
                background: 'var(--accent-green)', flexShrink: 0,
              }} />
              <span style={{ maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {currentTenant.name || currentTenant.tenant_id}
              </span>
              <span style={{ fontSize: '.6rem', color: 'var(--text-faint)' }}>▾</span>
            </button>

            {dropdownOpen && (
              <div style={{
                position: 'absolute', top: 'calc(100% + 4px)', right: 0,
                background: 'var(--bg-elevated)', border: '1px solid var(--border-medium)',
                borderRadius: 'var(--radius-md)', padding: '4px', minWidth: '200px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.4)', zIndex: 200,
              }}>
                <div style={{
                  padding: '6px 10px', fontSize: '.65rem', fontWeight: 600,
                  color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.08em',
                }}>
                  Switch tenant
                </div>
                {tenants.map(t => (
                  <button
                    key={t.tenant_id}
                    onClick={() => handleSwitch(t.tenant_id)}
                    disabled={switching}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '8px',
                      width: '100%', padding: '8px 10px', border: 'none',
                      background: t.current ? 'var(--bg-hover)' : 'transparent',
                      color: t.current ? 'var(--text-primary)' : 'var(--text-secondary)',
                      borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                      fontSize: '.78rem', fontFamily: 'var(--font-body)',
                      textAlign: 'left',
                    }}
                    onMouseEnter={e => { if (!t.current) e.target.style.background = 'var(--bg-hover)'; }}
                    onMouseLeave={e => { if (!t.current) e.target.style.background = 'transparent'; }}
                  >
                    <span style={{
                      width: '6px', height: '6px', borderRadius: '50%',
                      background: t.current ? 'var(--accent-green)' : 'var(--border-medium)',
                      flexShrink: 0,
                    }} />
                    <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.name}
                    </span>
                    {t.current && (
                      <span style={{ fontSize: '.65rem', color: 'var(--accent-green)', fontWeight: 600 }}>
                        active
                      </span>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        <button
          className={`header-nav-btn ${view === 'dashboard' ? 'active' : ''}`}
          onClick={() => setView('dashboard')}
        >
          Dashboard
        </button>
        {!isPublic && (
          <>
            <button
              className={`header-nav-btn ${view === 'approvals' ? 'active' : ''}`}
              onClick={() => setView('approvals')}
            >
              Approvals
            </button>
            <button
              className={`header-nav-btn ${view === 'settings' ? 'active' : ''}`}
              onClick={() => setView('settings')}
            >
              Tools
            </button>
            <button
              className={`header-nav-btn ${view === 'account' ? 'active' : ''}`}
              onClick={() => setView('account')}
            >
              Settings
            </button>
          </>
        )}
        {!isPublic && onLogout && (
          <button
            className="header-nav-btn"
            onClick={onLogout}
            style={{ color: 'var(--text-faint)' }}
          >
            Logout
          </button>
        )}

        <div
          style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}
          onClick={() => setLiveMode(!liveMode)}
        >
          <div className={`live-dot ${liveMode ? '' : 'inactive'}`} />
          <span className={`live-label ${liveMode ? '' : 'inactive'}`}>
            {liveMode ? 'Live' : 'Paused'}
          </span>
        </div>

        {isPublic && (
          <a
            href="/dashboard/"
            className="header-nav-btn"
            style={{ color: 'var(--accent-blue)', textDecoration: 'none', fontSize: '0.75rem' }}
          >
            Sign in →
          </a>
        )}
      </div>
    </header>
  );
}
