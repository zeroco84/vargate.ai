import React, { useState } from 'react';
import { getViolation, severityPillClass } from '../violations';
import { formatTime, truncate } from '../api';

export default function ActivityCard({ rec, isNew }) {
  const [expanded, setExpanded] = useState(false);
  const isBlocked = rec.decision === 'deny';
  const isBrokered = rec.execution_mode === 'vargate_brokered';

  // Translate violations to plain English
  const violations = (rec.violations || []).map(v => getViolation(v));
  const primaryViolation = violations[0];

  return (
    <div
      className={`activity-card ${isBlocked ? 'blocked' : 'allowed'} ${isNew ? 'card-enter' : ''}`}
      onClick={() => setExpanded(!expanded)}
    >
      {/* Card header */}
      <div className="card-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className={`pill ${isBlocked ? 'pill-blocked' : 'pill-allowed'}`}>
            {isBlocked ? '✗ Blocked' : '✓ Allowed'}
          </span>
          {isBlocked && rec.severity && rec.severity !== 'none' && (
            <span className={`pill ${severityPillClass(rec.severity)}`}>
              {rec.severity}
            </span>
          )}
          {!isBlocked && isBrokered && (
            <span className="pill pill-brokered">🔒 Brokered</span>
          )}
          {!isBlocked && !isBrokered && (
            <span className="pill pill-direct">Direct</span>
          )}
        </div>
        <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          {formatTime(rec.created_at)}
        </span>
      </div>

      {/* Flow line */}
      <div className="card-flow">
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
          {truncate(rec.agent_id, 24)}
        </span>
        <span className="card-flow-arrow">→</span>
        <span style={{ fontWeight: 600 }}>{rec.tool}</span>
        <span className="card-flow-arrow">→</span>
        <span style={{ color: 'var(--text-secondary)' }}>{rec.method}</span>
      </div>

      {/* Body - violation description or brokered status */}
      <div className="card-body">
        {isBlocked && primaryViolation && (
          <>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
              <span>{primaryViolation.icon}</span>
              <div>
                <div style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.82rem' }}>
                  {primaryViolation.title}
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '2px' }}>
                  {primaryViolation.description}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 'var(--space-sm)', fontSize: '0.72rem', color: 'var(--text-faint)' }}>
              Execution engine never called · No credential used
            </div>
          </>
        )}
        {!isBlocked && isBrokered && (
          <>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
              🔒 Credential fetched from vault · Result returned
            </div>
            <div style={{ color: 'var(--accent-green)', fontSize: '0.72rem', fontWeight: 600, marginTop: '2px' }}>
              Agent never saw the API key
            </div>
            {rec.execution_result?.simulated && (
              <div style={{ marginTop: '4px', fontSize: '0.68rem', color: 'var(--text-faint)', fontStyle: 'italic' }}>
                simulated: true
              </div>
            )}
          </>
        )}
        {!isBlocked && !isBrokered && (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
            Direct execution — no credential brokering
          </div>
        )}
      </div>

      {/* Latency breakdown (allowed only) */}
      {!isBlocked && rec.latency && (
        <div className="card-latency">
          {rec.latency?.opa_eval_ms != null && <span>OPA {rec.latency.opa_eval_ms}ms</span>}
          {rec.latency?.hsm_fetch_ms != null && rec.latency.hsm_fetch_ms > 0 && <span>HSM {rec.latency.hsm_fetch_ms}ms</span>}
          {rec.execution_latency_ms != null && <span>Exec {rec.execution_latency_ms}ms</span>}
          <span style={{ color: 'var(--text-secondary)' }}>
            Chain ✓ · Pass {rec.evaluation_pass || 1}
          </span>
        </div>
      )}

      {!isBlocked && !rec.latency && (
        <div className="card-latency">
          <span>Chain ✓ · Pass {rec.evaluation_pass || 1}</span>
        </div>
      )}

      {isBlocked && (
        <div className="card-latency">
          <span>Chain ✓ · Pass {rec.evaluation_pass || 1}</span>
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="card-expand">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-md)', fontSize: '0.72rem' }}>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Action ID</span>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.68rem', marginTop: '2px' }}>
                {rec.action_id}
              </div>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Bundle</span>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.68rem', marginTop: '2px' }}>
                {truncate(rec.bundle_revision, 30)}
              </div>
            </div>
            {rec.credential_accessed && (
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Credential</span>
                <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-green)', fontSize: '0.68rem', marginTop: '2px' }}>
                  {rec.credential_accessed}
                </div>
              </div>
            )}
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Hashes</span>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-faint)', fontSize: '0.62rem', marginTop: '2px' }}>
                prev: {rec.prev_hash?.slice(0, 20)}…
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-faint)', fontSize: '0.62rem' }}>
                this: {rec.record_hash?.slice(0, 20)}…
              </div>
            </div>
          </div>

          {isBlocked && rec.violations?.length > 0 && (
            <div style={{ marginTop: 'var(--space-md)' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.68rem' }}>Violation codes</span>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--accent-red)', marginTop: '2px' }}>
                {rec.violations.join(', ')}
              </div>
            </div>
          )}

          {rec.params && (
            <div style={{ marginTop: 'var(--space-md)' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.68rem' }}>Parameters</span>
              <pre>{JSON.stringify(rec.params, null, 2)}</pre>
            </div>
          )}

          {rec.execution_result && (
            <div style={{ marginTop: 'var(--space-md)' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.68rem' }}>Execution Result</span>
              <pre>{JSON.stringify(rec.execution_result, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
