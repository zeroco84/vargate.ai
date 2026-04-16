import React, { useState, useEffect } from 'react';
import { fetchCredentials, fetchCredentialAccessLog, registerCredential, deleteCredential, formatTime, truncate } from '../../api';

const TWITTER_FIELDS = ['api_key', 'api_secret', 'access_token', 'access_secret'];
const INSTAGRAM_FIELDS = ['access_token', 'ig_user_id'];

export default function VaultManage() {
  const [credentials, setCredentials] = useState([]);
  const [accessLog, setAccessLog] = useState([]);
  const [toolId, setToolId] = useState('');
  const [credName, setCredName] = useState('api_key');
  const [credValue, setCredValue] = useState('');
  const [twitterCreds, setTwitterCreds] = useState({ api_key: '', api_secret: '', access_token: '', access_secret: '' });
  const [instagramCreds, setInstagramCreds] = useState({ access_token: '', ig_user_id: '' });
  const [status, setStatus] = useState(null);

  const isTwitter = toolId === 'twitter';
  const isInstagram = toolId === 'instagram';
  const twitterReady = isTwitter && TWITTER_FIELDS.every(f => twitterCreds[f]);
  const instagramReady = isInstagram && INSTAGRAM_FIELDS.every(f => instagramCreds[f]);
  const isMultiField = isTwitter || isInstagram;

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

          {/* Twitter OAuth 1.0a multi-field form */}
          {isTwitter && (
            <div style={{ marginTop: 'var(--space-md)' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 'var(--space-sm)' }}>
                Twitter requires OAuth 1.0a. Enter all four keys from developer.x.com.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-sm)', maxWidth: '480px' }}>
                <div>
                  <label className="label">API Key</label>
                  <input
                    className="input"
                    type="password"
                    value={twitterCreds.api_key}
                    onChange={e => setTwitterCreds(p => ({ ...p, api_key: e.target.value }))}
                    placeholder="Consumer API Key"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label className="label">API Secret</label>
                  <input
                    className="input"
                    type="password"
                    value={twitterCreds.api_secret}
                    onChange={e => setTwitterCreds(p => ({ ...p, api_secret: e.target.value }))}
                    placeholder="Consumer API Secret"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label className="label">Access Token</label>
                  <input
                    className="input"
                    type="password"
                    value={twitterCreds.access_token}
                    onChange={e => setTwitterCreds(p => ({ ...p, access_token: e.target.value }))}
                    placeholder="Access Token"
                    style={inputStyle}
                  />
                </div>
                <div>
                  <label className="label">Access Secret</label>
                  <input
                    className="input"
                    type="password"
                    value={twitterCreds.access_secret}
                    onChange={e => setTwitterCreds(p => ({ ...p, access_secret: e.target.value }))}
                    placeholder="Access Token Secret"
                    style={inputStyle}
                  />
                </div>
              </div>
              <div style={{ marginTop: 'var(--space-sm)' }}>
                <button className="btn btn-success" type="submit" disabled={!twitterReady}>
                  Register
                </button>
              </div>
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
