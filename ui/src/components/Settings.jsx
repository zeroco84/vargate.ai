import React, { useState, useEffect } from 'react';
import { fetchDashboardMe, updateSettings, rotateApiKey } from '../api';

// Keep in sync with valid_tools in gateway/routes_tenant.py and with
// @tools annotations in policies/vargate/gtm_policy.rego.
const APPROVABLE_TOOLS = [
  'substack/create_post',
  'substack/create_note',
  'substack/delete_note',
  'twitter/create_tweet',
  'twitter/delete_tweet',
  'twitter/follow_user',
  'twitter/unfollow_user',
  'twitter/send_dm',
  'instagram/create_post',
  'resend/send',
  'gmail/send_email',
  'salesforce/update_record',
  'stripe/create_charge',
  'stripe/create_transfer',
  'slack/post_message',
];

export default function Settings({ onBack }) {
  const [me, setMe] = useState(null);
  const [publicDashboard, setPublicDashboard] = useState(false);
  const [autoApprove, setAutoApprove] = useState([]);
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [newKey, setNewKey] = useState('');
  const [copied, setCopied] = useState(false);
  const [msg, setMsg] = useState('');
  const [addingRule, setAddingRule] = useState(false);

  useEffect(() => {
    fetchDashboardMe().then(d => {
      if (d) {
        setMe(d);
        setPublicDashboard(d.public_dashboard || false);
        setAutoApprove(d.auto_approve_tools || []);
      }
    });
  }, []);

  const handleTogglePublic = async () => {
    setSaving(true);
    const newVal = !publicDashboard;
    const result = await updateSettings({ public_dashboard: newVal });
    if (result) {
      setPublicDashboard(newVal);
      setMsg(newVal ? 'Public dashboard enabled' : 'Public dashboard disabled');
    }
    setSaving(false);
    setTimeout(() => setMsg(''), 3000);
  };

  const handleRotate = async () => {
    if (!confirm('This will immediately invalidate your current API key. Continue?')) return;
    setRotating(true);
    const result = await rotateApiKey();
    if (result && result.api_key) {
      setNewKey(result.api_key);
      setMsg('API key rotated successfully');
      fetchDashboardMe().then(setMe);
    } else {
      setMsg('Failed to rotate API key');
    }
    setRotating(false);
    setTimeout(() => setMsg(''), 5000);
  };

  const handleAddAutoApprove = async (toolMethod) => {
    if (autoApprove.includes(toolMethod)) return;
    const newList = [...autoApprove, toolMethod];
    const result = await updateSettings({ auto_approve_tools: newList });
    if (result) {
      setAutoApprove(newList);
      setMsg(`Auto-approve enabled for ${toolMethod}`);
    }
    setAddingRule(false);
    setTimeout(() => setMsg(''), 3000);
  };

  const handleRemoveAutoApprove = async (toolMethod) => {
    const newList = autoApprove.filter(t => t !== toolMethod);
    const result = await updateSettings({ auto_approve_tools: newList });
    if (result) {
      setAutoApprove(newList);
      setMsg(`Auto-approve disabled for ${toolMethod}`);
    }
    setTimeout(() => setMsg(''), 3000);
  };

  if (!me) return <div style={{ color: 'rgba(255,255,255,0.4)', padding: '40px', textAlign: 'center' }}>Loading...</div>;

  const cardStyle = {
    padding: '20px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px',
    border: '1px solid rgba(255,255,255,0.06)', marginBottom: '16px',
  };
  const labelStyle = { fontSize: '13px', fontWeight: 600, color: 'rgba(255,255,255,0.5)', marginBottom: '8px' };
  const valueStyle = { fontSize: '14px', color: '#e2e8f0' };

  const availableToAdd = APPROVABLE_TOOLS.filter(t => !autoApprove.includes(t));

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto', padding: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
        <button onClick={onBack} style={{ background: 'none', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#e2e8f0', padding: '6px 12px', cursor: 'pointer', fontSize: '13px' }}>Back</button>
        <div style={{ fontSize: '20px', fontWeight: 600 }}>Settings</div>
      </div>

      {msg && (
        <div style={{ padding: '12px 16px', background: 'rgba(16,185,129,0.1)', borderRadius: '8px', color: '#10b981', fontSize: '13px', marginBottom: '16px' }}>{msg}</div>
      )}

      {/* Account info */}
      <div style={cardStyle}>
        <div style={labelStyle}>Account</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.3)' }}>Tenant ID</div>
            <div style={valueStyle}>{me.tenant_id}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.3)' }}>Email</div>
            <div style={valueStyle}>{me.email || '—'}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.3)' }}>Organization</div>
            <div style={valueStyle}>{me.name}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.3)' }}>GitHub</div>
            <div style={valueStyle}>{me.github_login || '—'}</div>
          </div>
        </div>
      </div>

      {/* API Key */}
      <div style={cardStyle}>
        <div style={labelStyle}>API Key</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
          <code style={{ flex: 1, padding: '10px 14px', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px', color: '#10b981' }}>
            {newKey || me.api_key_prefix}
          </code>
          {newKey && (
            <button onClick={() => { navigator.clipboard.writeText(newKey); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
              style={{ background: 'none', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', color: '#818cf8', padding: '8px 14px', cursor: 'pointer', fontSize: '12px', whiteSpace: 'nowrap' }}>
              {copied ? 'Copied!' : 'Copy Key'}
            </button>
          )}
        </div>
        {newKey && (
          <div style={{ fontSize: '12px', color: '#f59e0b', marginBottom: '12px' }}>
            Save this key now — it won't be shown again.
          </div>
        )}
        <button onClick={handleRotate} disabled={rotating}
          style={{ padding: '10px 20px', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.1)', color: '#ef4444', cursor: rotating ? 'not-allowed' : 'pointer', fontSize: '13px', fontWeight: 500 }}>
          {rotating ? 'Rotating...' : 'Rotate API Key'}
        </button>
      </div>

      {/* Auto-Approve Rules */}
      <div style={cardStyle}>
        <div style={labelStyle}>Auto-Approve Rules</div>
        <div style={{ fontSize: '13px', color: 'rgba(255,255,255,0.4)', marginBottom: '12px' }}>
          Skip the approval queue for trusted tool/method combinations. OPA policy violations still block regardless.
        </div>

        {autoApprove.length > 0 ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
            {autoApprove.map(tm => (
              <span key={tm} style={{
                display: 'inline-flex', alignItems: 'center', gap: '6px',
                padding: '5px 10px', borderRadius: '100px', fontSize: '12px', fontWeight: 500,
                background: 'rgba(129,140,248,0.1)', color: '#818cf8',
                border: '1px solid rgba(129,140,248,0.2)',
              }}>
                <code style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '11px' }}>{tm}</code>
                <button
                  onClick={() => handleRemoveAutoApprove(tm)}
                  style={{
                    background: 'none', border: 'none', color: 'rgba(255,255,255,0.4)',
                    cursor: 'pointer', padding: '0 2px', fontSize: '14px', lineHeight: 1,
                  }}
                  title={`Remove auto-approve for ${tm}`}
                >
                  x
                </button>
              </span>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.25)', marginBottom: '12px', fontStyle: 'italic' }}>
            No auto-approve rules configured. All governed actions require manual approval.
          </div>
        )}

        {addingRule ? (
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <select
              className="select"
              onChange={e => { if (e.target.value) handleAddAutoApprove(e.target.value); }}
              defaultValue=""
              style={{ fontSize: '12px' }}
            >
              <option value="">Select tool/method...</option>
              {availableToAdd.map(tm => (
                <option key={tm} value={tm}>{tm}</option>
              ))}
            </select>
            <button
              onClick={() => setAddingRule(false)}
              style={{ background: 'none', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: 'rgba(255,255,255,0.4)', padding: '6px 12px', cursor: 'pointer', fontSize: '12px' }}
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            onClick={() => setAddingRule(true)}
            disabled={availableToAdd.length === 0}
            style={{
              padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(129,140,248,0.3)',
              background: 'rgba(129,140,248,0.1)', color: '#818cf8',
              cursor: availableToAdd.length === 0 ? 'not-allowed' : 'pointer',
              fontSize: '13px', fontWeight: 500,
            }}
          >
            + Add Rule
          </button>
        )}
      </div>

      {/* Public Dashboard */}
      <div style={cardStyle}>
        <div style={labelStyle}>Public Dashboard</div>
        <div style={{ fontSize: '13px', color: 'rgba(255,255,255,0.4)', marginBottom: '12px' }}>
          Share a read-only view of your audit stats. No PII or params are exposed.
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button onClick={handleTogglePublic} disabled={saving}
            style={{
              padding: '10px 20px', borderRadius: '8px', border: 'none', fontSize: '13px', fontWeight: 500, cursor: 'pointer',
              background: publicDashboard ? '#ef4444' : '#10b981',
              color: 'white',
            }}>
            {saving ? 'Saving...' : publicDashboard ? 'Disable' : 'Enable'}
          </button>
          {publicDashboard && me.slug && (
            <code style={{ fontSize: '12px', color: '#818cf8' }}>
              {window.location.origin}/dashboard/{me.slug}
            </code>
          )}
        </div>
      </div>

      {/* Usage stats */}
      <div style={cardStyle}>
        <div style={labelStyle}>Usage</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', textAlign: 'center' }}>
          <div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#818cf8' }}>{me.stats.total_actions}</div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.3)' }}>Total</div>
          </div>
          <div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#10b981' }}>{me.stats.allowed}</div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.3)' }}>Allowed</div>
          </div>
          <div>
            <div style={{ fontSize: '24px', fontWeight: 700, color: '#ef4444' }}>{me.stats.denied}</div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.3)' }}>Denied</div>
          </div>
        </div>
      </div>
    </div>
  );
}
