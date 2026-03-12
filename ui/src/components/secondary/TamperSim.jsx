import React, { useState } from 'react';
import { tamperSimulate, tamperRestore } from '../../api';

export default function TamperSim({ onRefresh }) {
  const [recordNum, setRecordNum] = useState(2);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleTamper = async () => {
    setLoading(true);
    const result = await tamperSimulate(recordNum);
    setStatus({ type: 'tampered', result });
    setLoading(false);
    if (onRefresh) onRefresh();
  };

  const handleRestore = async () => {
    setLoading(true);
    const result = await tamperRestore();
    setStatus({ type: 'restored', result });
    setLoading(false);
    if (onRefresh) onRefresh();
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Tamper Simulation</span>
        <span style={{
          fontSize: '0.62rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          color: 'var(--accent-amber)',
          background: 'var(--accent-amber-bg)',
          padding: '2px 8px',
          borderRadius: '100px',
          border: '1px solid var(--accent-amber-border)',
        }}>
          Demo Mode Only
        </span>
      </div>
      <div className="panel-body">
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 'var(--space-lg)' }}>
          Simulate tampering by modifying a record's stored hash. This will break the chain integrity verification and demonstrate the tamper detection capabilities.
        </p>

        <div style={{ display: 'flex', alignItems: 'end', gap: 'var(--space-md)', marginBottom: 'var(--space-lg)' }}>
          <div>
            <label className="label">Record Number</label>
            <input
              type="number"
              className="input"
              value={recordNum}
              onChange={e => setRecordNum(parseInt(e.target.value) || 1)}
              style={{ width: '100px' }}
              min={1}
            />
          </div>
          <button className="btn btn-danger" onClick={handleTamper} disabled={loading}>
            {loading ? 'Working…' : '⚡ Tamper Record'}
          </button>
          <button className="btn btn-success" onClick={handleRestore} disabled={loading}>
            🔧 Restore Chain
          </button>
        </div>

        {status && (
          <div style={{
            padding: 'var(--space-md)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.78rem',
            background: status.type === 'tampered' ? 'var(--accent-red-bg)' : 'var(--accent-green-bg)',
            border: `1px solid ${status.type === 'tampered' ? 'var(--accent-red-border)' : 'var(--accent-green-border)'}`,
            color: status.type === 'tampered' ? 'var(--accent-red)' : 'var(--accent-green)',
          }}>
            {status.type === 'tampered'
              ? `Chain tampered at record #${recordNum}. Check chain integrity panel.`
              : 'Chain restored. All records re-linked.'}
          </div>
        )}
      </div>
    </div>
  );
}
