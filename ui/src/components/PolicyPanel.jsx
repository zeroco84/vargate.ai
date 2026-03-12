import React from 'react';
import { parseBundleRevision, timeAgo } from '../api';

export default function PolicyPanel({ policy }) {
  if (!policy) return (
    <div className="panel">
      <div className="panel-header"><span className="panel-title">Policy Rules</span></div>
      <div className="panel-body" style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>Loading…</div>
    </div>
  );

  const rev = parseBundleRevision(policy.revision);
  const competitors = policy.competitor_domains || [];
  const threshold = policy.high_value_threshold || 5000;

  // Generate human-readable policy rules
  const rules = [
    { allowed: true, text: 'CRM reads and updates — allowed' },
    { allowed: true, text: 'Email to approved domains — allowed' },
    { allowed: false, text: `Transactions over £${threshold.toLocaleString()} — require approval` },
    { allowed: false, text: `Email to competitor domains — blocked (critical)` },
    { allowed: false, text: 'Actions outside business hours over £1,000 — blocked' },
    { allowed: false, text: 'Anomaly score above 0.7 — blocked' },
    { allowed: false, text: 'Uncredentialed tool calls — blocked' },
    { allowed: false, text: '3+ violations in 24h — further actions blocked' },
  ];

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Active Policy</span>
      </div>
      <div className="panel-body">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          {rules.map((rule, i) => (
            <div key={i} className={`policy-rule ${rule.allowed ? 'allowed' : 'blocked'}`}>
              <span className="policy-rule-icon">{rule.allowed ? '✓' : '✗'}</span>
              <span className="policy-rule-text">{rule.text}</span>
            </div>
          ))}
        </div>

        {competitors.length > 0 && (
          <div style={{ marginTop: 'var(--space-md)', paddingTop: 'var(--space-md)', borderTop: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-xs)' }}>
              Restricted Domains
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {competitors.map((d, i) => (
                <span key={i} style={{
                  fontSize: '0.68rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--accent-red)',
                  background: 'var(--accent-red-bg)',
                  padding: '1px 6px',
                  borderRadius: '3px',
                  border: '1px solid var(--accent-red-border)',
                }}>
                  {d}
                </span>
              ))}
            </div>
          </div>
        )}

        <div style={{ marginTop: 'var(--space-md)', fontSize: '0.7rem', color: 'var(--text-faint)' }}>
          {rev.version} · updated {rev.since}
        </div>
      </div>
    </div>
  );
}
