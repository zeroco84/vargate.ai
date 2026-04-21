import React, { useState, useEffect } from 'react';
import { fetchCredentials, fetchCredentialAccessLog, registerCredential, deleteCredential, startTwitterOAuth, formatTime, truncate } from '../../api';

const TWITTER_FIELDS = ['api_key', 'api_secret', 'access_token', 'access_secret'];
const INSTAGRAM_FIELDS = ['access_token', 'ig_user_id'];

export default function VaultManage() {
  const [credentials, setCredentials] = useState([]);
  const [accessLog, setAccessLog] = useState([]);
  const [toolId, setToolId] = useState('');
  const [credName, setCredName] = useState('api_key');
  const [credValue, setCredValue] = useState('');
  const [twitterCreds, setTwitterCreds] = useState({ api_key: '', api_secret: '', access_token: '', access_secret: '' });
  const [twitterOauth2, setTwitterOauth2] = useState({ client_id: '', client_secret: '' });
  const [showTwitterLegacy, setShowTwitterLegacy] = useState(false);
  const [instagramCreds, setInstagramCreds] = useState({ access_token: '', ig_user_id: '' });
  const [status, setStatus] = useState(null);

  const isTwitter = toolId === 'twitter';
  const isInstagram = toolId === 'instagram';
  const twitterReady = isTwitter && TWITTER_FIELDS.every(f => twitterCreds[f]);
  const twitterOauth2Ready = isTwitter && twitterOauth2.client_id && twitterOauth2.client_secret;
  const instagramReady = isInstagram && INSTAGRAM_FIELDS.every(f => instagramCreds[f]);
  const isMultiField = isTwitter || isInstagram;

  // Derived once per render from window.location so customers on any
  // deployment (vargate.ai, developer.vargate.ai, self-hosted) see the
  // correct URL to register in their Twitter app.
  const twitterCallbackUrl = typeof window !== 'undefined'
    ? `${window.location.origin}/api/oauth/twitter/callback`
    : 'https://vargate.ai/api/oauth/twitter/callback';

  const handleTwitterConnect = async () => {
    if (!twitterOauth2Ready) return;
    setStatus(null);
    const data = await startTwitterOAuth(twitterOauth2.client_id, twitterOauth2.client_secret);
    if (data?.authorize_url) {
      // Open Twitter consent page. After the user approves, Twitter
      // redirects to /api/oauth/twitter/callback which stores the
      // tokens in the vault and shows a success/failure page.
      const popup = window.open(data.authorize_url, 'vargate_twitter_oauth', 'width=600,height=800');
      if (!popup) {
        setStatus({ type: 'error', message: 'Popup blocked — allow popups for this site and try again.' });
        return;
      }
      setStatus({ type: 'ok', message: 'Twitter consent page opened. Approve in the popup, then come back here.' });
      // Poll for a new twitter/oauth2 credential appearing in the vault
      const startTime = Date.now();
      const poll = setInterval(async () => {
        if (Date.now() - startTime > 120000 || popup.closed) {
          clearInterval(poll);
          refresh();
          return;
        }
        const creds = await fetchCredentials();
        if (creds?.credentials?.some(c => c.tool_id === 'twitter' && c.name === 'oauth2')) {
          clearInterval(poll);
          setStatus({ type: 'ok', message: 'Twitter connected via OAuth 2.0.' });
          setTwitterOauth2({ client_id: '', client_secret: '' });
          setToolId('');
          refresh();
          try { popup.close(); } catch (e) { /* cross-origin may throw */ }
        }
      }, 2000);
    } else {
      setStatus({ type: 'error', message: 'Could not start OAuth flow — check your client ID/secret.' });
    }
  };

  const refresh = async () => {
    const [creds, log] = await Promise.all([
      fetchCredentials(),
      fetchCredentialAccessLog(),
    ]);
    setCredentials(creds?.credentials || []);
    setAccessLog(log?.entries || []);
  };

  useEffect(() => { refresh(); }, []);

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!toolId) return;

    let name = credName;
    let value = credValue;

    if (isTwitter) {
      if (!twitterReady) return;
      name = 'api_key';
      value = JSON.stringify(twitterCreds);
    } else if (isInstagram) {
      if (!instagramReady) return;
      name = 'access_token';
      value = JSON.stringify(instagramCreds);
    } else if (!credValue) {
      return;
    }

    setStatus(null);
    const data = await registerCredential(toolId, name, value);
    if (data?.registered) {
      setStatus({ type: 'ok', message: `Credential registered for ${toolId}/${name}` });
      setToolId('');
      setCredValue('');
      setTwitterCreds({ api_key: '', api_secret: '', access_token: '', access_secret: '' });
      setInstagramCreds({ access_token: '', ig_user_id: '' });
      refresh();
    } else {
      setStatus({ type: 'error', message: 'Registration failed' });
    }
  };

  const handleDelete = async (tid, name) => {
    await deleteCredential(tid, name);
    refresh();
  };

  const inputStyle = { width: '100%', boxSizing: 'border-box' };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Vault Management</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
          {credentials.length} registered
        </span>
      </div>
      <div className="panel-body">
        {/* Registered credentials */}
        {credentials.length > 0 && (
          <div style={{ marginBottom: 'var(--space-lg)' }}>
            <div className="label" style={{ marginBottom: 'var(--space-sm)' }}>Registered Credentials</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-xs)' }}>
              {credentials.map((c, i) => (
                <div key={i} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: 'var(--space-sm) var(--space-md)',
                  background: 'var(--bg-base)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  <div>
                    <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>{c.tool_id}</span>
                    <span style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginLeft: '8px' }}>
                      {c.name}
                    </span>
                  </div>
                  <button
                    className="btn btn-ghost"
                    style={{ padding: '2px 8px', fontSize: '0.68rem' }}
                    onClick={() => handleDelete(c.tool_id, c.name)}
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Registration form */}
        <form onSubmit={handleRegister}>
          <div className="label" style={{ marginBottom: 'var(--space-sm)' }}>Register New Credential</div>

          {/* Tool selector row */}
          <div style={{ display: 'flex', gap: 'var(--space-md)', flexWrap: 'wrap', alignItems: 'end' }}>
            <div>
              <label className="label">Tool</label>
              <select className="select" value={toolId} onChange={e => setToolId(e.target.value)} style={{ width: '140px' }}>
                <option value="">Select...</option>
                <option value="gmail">Gmail</option>
                <option value="salesforce">Salesforce</option>
                <option value="stripe">Stripe</option>
                <option value="slack">Slack</option>
                <option value="substack">Substack</option>
                <option value="twitter">Twitter / X</option>
                <option value="instagram">Instagram</option>
              </select>
            </div>

            {/* Standard single-secret form */}
            {!isMultiField && (
              <>
                <div>
                  <label className="label">Name</label>
                  <input className="input" value={credName} onChange={e => setCredName(e.target.value)} style={{ width: '120px' }} />
                </div>
                <div>
                  <label className="label">Secret</label>
                  <input
                    className="input"
                    type="password"
                    value={credValue}
                    onChange={e => setCredValue(e.target.value)}
                    placeholder="••••••••"
                    style={{ width: '160px' }}
                  />
                </div>
                <button className="btn btn-success" type="submit" disabled={!toolId || !credValue}>
                  Register
                </button>
              </>
            )}
          </div>

          {/* Twitter — OAuth 2.0 primary, OAuth 1.0a collapsible fallback */}
          {isTwitter && (
            <div style={{ marginTop: 'var(--space-md)' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 'var(--space-sm)' }}>
                OAuth 2.0 unlocks follow, DM, tweet, and read operations — recommended.
                Create an app at <code>developer.x.com</code>, enable OAuth 2.0 with PKCE,
                add the callback URL below to the app's whitelist, then paste the
                Client ID and Client Secret and click Connect.
              </div>

              {/* Callback URL display — user must register this in their Twitter app */}
              <div style={{
                marginBottom: 'var(--space-sm)',
                padding: 'var(--space-sm) var(--space-md)',
                background: 'var(--bg-base)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.7rem',
              }}>
                <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Callback URL to register in your Twitter app:
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
                  <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-primary)', flex: 1, wordBreak: 'break-all' }}>
                    {twitterCallbackUrl}
                  </code>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ padding: '2px 10px', fontSize: '0.68rem' }}
                    onClick={() => {
                      navigator.clipboard?.writeText(twitterCallbackUrl);
                      setStatus({ type: 'ok', message: 'Callback URL copied.' });
                    }}
                  >
                    Copy
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-sm)', maxWidth: '480px' }}>
                <div>
                  <label className="label">Client ID</label>
                  <input
                    className="input"
                    type="text"
                    value={twitterOauth2.client_id}
                    onChange={e => setTwitterOauth2(p => ({ ...p, client_id: e.target.value }))}
                    placeholder="OAuth 2.0 Client ID"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label className="label">Client Secret</label>
                  <input
                    className="input"
                    type="password"
                    value={twitterOauth2.client_secret}
                    onChange={e => setTwitterOauth2(p => ({ ...p, client_secret: e.target.value }))}
                    placeholder="OAuth 2.0 Client Secret"
                    style={inputStyle}
                  />
                </div>
              </div>
              <div style={{ marginTop: 'var(--space-sm)', display: 'flex', gap: 'var(--space-sm)', alignItems: 'center' }}>
                <button
                  type="button"
                  className="btn btn-success"
                  disabled={!twitterOauth2Ready}
                  onClick={handleTwitterConnect}
                >
                  Connect with Twitter
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ fontSize: '0.7rem' }}
                  onClick={() => setShowTwitterLegacy(v => !v)}
                >
                  {showTwitterLegacy ? 'Hide' : 'Show'} legacy OAuth 1.0a
                </button>
              </div>

              {/* Legacy OAuth 1.0a form — kept for backward compat / apps not on OAuth 2.0 */}
              {showTwitterLegacy && (
                <div style={{ marginTop: 'var(--space-md)', padding: 'var(--space-md)', border: '1px dashed var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 'var(--space-sm)' }}>
                    Legacy OAuth 1.0a (tweets only — no DMs, no follows). Paste the four keys from your Twitter app.
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-sm)', maxWidth: '480px' }}>
                    <div>
                      <label className="label">API Key</label>
                      <input className="input" type="password" value={twitterCreds.api_key}
                        onChange={e => setTwitterCreds(p => ({ ...p, api_key: e.target.value }))}
                        placeholder="Consumer API Key" style={inputStyle} />
                    </div>
                    <div>
                      <label className="label">API Secret</label>
                      <input className="input" type="password" value={twitterCreds.api_secret}
                        onChange={e => setTwitterCreds(p => ({ ...p, api_secret: e.target.value }))}
                        placeholder="Consumer API Secret" style={inputStyle} />
                    </div>
                    <div>
                      <label className="label">Access Token</label>
                      <input className="input" type="password" value={twitterCreds.access_token}
                        onChange={e => setTwitterCreds(p => ({ ...p, access_token: e.target.value }))}
                        placeholder="Access Token" style={inputStyle} />
                    </div>
                    <div>
                      <label className="label">Access Secret</label>
                      <input className="input" type="password" value={twitterCreds.access_secret}
                        onChange={e => setTwitterCreds(p => ({ ...p, access_secret: e.target.value }))}
                        placeholder="Access Token Secret" style={inputStyle} />
                    </div>
                  </div>
                  <div style={{ marginTop: 'var(--space-sm)' }}>
                    <button className="btn btn-ghost" type="submit" disabled={!twitterReady}>
                      Register legacy credentials
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Instagram Graph API form (access_token + ig_user_id) */}
          {isInstagram && (
            <div style={{ marginTop: 'var(--space-md)' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 'var(--space-sm)' }}>
                Instagram requires a long-lived Graph API access token with instagram_content_publish
                permission, plus the connected IG Business/Creator user ID.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-sm)', maxWidth: '480px' }}>
                <div>
                  <label className="label">Access Token</label>
                  <input
                    className="input"
                    type="password"
                    value={instagramCreds.access_token}
                    onChange={e => setInstagramCreds(p => ({ ...p, access_token: e.target.value }))}
                    placeholder="Long-lived user token"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label className="label">IG User ID</label>
                  <input
                    className="input"
                    type="text"
                    value={instagramCreds.ig_user_id}
                    onChange={e => setInstagramCreds(p => ({ ...p, ig_user_id: e.target.value }))}
                    placeholder="17841..."
                    style={inputStyle}
                  />
                </div>
              </div>
              <div style={{ marginTop: 'var(--space-sm)' }}>
                <button className="btn btn-success" type="submit" disabled={!instagramReady}>
                  Register
                </button>
              </div>
            </div>
          )}
        </form>

        {status && (
          <div style={{
            marginTop: 'var(--space-md)',
            padding: 'var(--space-sm) var(--space-md)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.78rem',
            background: status.type === 'ok' ? 'var(--accent-green-bg)' : 'var(--accent-red-bg)',
            color: status.type === 'ok' ? 'var(--accent-green)' : 'var(--accent-red)',
            border: `1px solid ${status.type === 'ok' ? 'var(--accent-green-border)' : 'var(--accent-red-border)'}`,
          }}>
            {status.message}
          </div>
        )}

        {/* Access log */}
        {accessLog.length > 0 && (
          <div style={{ marginTop: 'var(--space-xl)' }}>
            <div className="label" style={{ marginBottom: 'var(--space-sm)' }}>Access Log</div>
            <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
              <table style={{ width: '100%', fontSize: '0.68rem', fontFamily: 'var(--font-mono)' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Time</th>
                    <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Tool</th>
                    <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Name</th>
                    <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Agent</th>
                  </tr>
                </thead>
                <tbody>
                  {accessLog.map((entry, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '4px', color: 'var(--text-muted)' }}>{formatTime(entry.accessed_at)}</td>
                      <td style={{ padding: '4px', color: 'var(--text-secondary)' }}>{entry.tool_id}</td>
                      <td style={{ padding: '4px', color: 'var(--text-muted)' }}>{entry.name}</td>
                      <td style={{ padding: '4px', color: 'var(--text-faint)' }}>{truncate(entry.agent_id, 18)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
