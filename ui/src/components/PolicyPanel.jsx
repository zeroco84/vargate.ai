import React, { useState, useEffect } from 'react';
import { parseBundleRevision, fetchPolicyRules } from '../api';

export default function PolicyPanel({ policy }) {
  const [rules, setRules] = useState(null);

  useEffect(() => {
    fetchPolicyRules().then(data => {
      if (data?.rules) setRules(data.rules);
    });
  }, []);

  if (!policy) return (
    <div className="panel">
      <div className="panel-header"><span className="panel-title">Active Policy</span></div>
      <div className="panel-body" style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>Loading…</div>
    </div>
  );

  const rev = parseBundleRevision(policy.revision);

  // Group rules by type
  const denyRules = rules ? rules.filter(r => r.type === 'deny') : [];
  const approvalRules = rules ? rules.filter(r => r.type === 'approval') : [];
  const autoApprovedRules = rules ? rules.filter(r => r.type === 'auto_approved') : [];

  // Fallback while loading
  const loading = !rules;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Active Policy</span>
        {rules && (
          <span style={{ fontSize: '0.65rem', color: 'var(--text-faint)', fontWeight: 400 }}>
            {rules.length} rules from {[...new Set(rules.map(r => r.source))].length} file{[...new Set(rules.map(r => r.source))].length !== 1 ? 's' : ''}
          </span>
        )}
      </div>
      <div className="panel-body">
        {loading ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>Loading policy rules…</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
            {denyRules.map((rule, i) => (
              <div key={`d-${i}`} className="policy-rule blocked">
                <span className="policy-rule-icon">✗</span>
                <span className="policy-rule-text">{rule.description}</span>
              </div>
            ))}
            {approvalRules.map((rule, i) => (
              <div key={`a-${i}`} className="policy-rule blocked" style={{ borderLeftColor: 'var(--accent-amber)' }}>
                <span className="policy-rule-icon" style={{ color: 'var(--accent-amber)' }}>⏳</span>
                <span className="policy-rule-text">
                  {rule.description}
                  {rule.tools?.length === 1 && (
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-faint)', fontWeight: 400, marginLeft: '6px', fontFamily: 'var(--font-mono)' }}>
                      {rule.tools[0]}
                    </span>
                  )}
                </span>
              </div>
            ))}
            {autoApprovedRules.map((rule, i) => (
              <div
                key={`aa-${i}`}
                className="policy-rule blocked"
                style={{ borderLeftColor: 'var(--accent-green)' }}
                title="Policy gate lifted by tenant — action auto-approved (policy violations still block)"
              >
                <span className="policy-rule-icon" style={{ color: 'var(--accent-green)' }}>✓</span>
                <span className="policy-rule-text">
                  {rule.description}
                  {rule.tools?.length === 1 && (
                    <span style={{ fontSize: '0.65rem', color: 'var(--text-faint)', fontWeight: 400, marginLeft: '6px', fontFamily: 'var(--font-mono)' }}>
                      {rule.tools[0]}
                    </span>
                  )}
                  <span style={{ fontSize: '0.65rem', color: 'var(--accent-green)', fontWeight: 400, marginLeft: '6px' }}>
                    · auto-approved
                  </span>
                </span>
              </div>
            ))}
          </div>
        )}

        <div style={{ marginTop: 'var(--space-md)', fontSize: '0.7rem', color: 'var(--text-faint)' }}>
          {rev.version} · updated {rev.since}
        </div>
      </div>
    </div>
  );
}
