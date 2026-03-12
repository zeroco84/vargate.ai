import React from 'react';
import { formatTime } from '../api';

export default function VaultPanel({ credentials, accessLog }) {
  const creds = credentials || [];
  const log = accessLog || [];

  const lastAccess = log.length > 0 ? log[0] : null;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Credential Vault</span>
      </div>
      <div className="panel-body">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)', marginBottom: 'var(--space-md)' }}>
          <span style={{ fontSize: '1rem' }}>🔒</span>
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
          }}>
            {creds.length} tools provisioned
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {creds.map((c, i) => (
            <div key={i} className="vault-tool">
              <span className="vault-tool-name">{c.tool_id}</span>
              <div className="vault-tool-status">
                <div className="vault-dot" />
                <span style={{ fontSize: '0.68rem', color: 'var(--accent-green)' }}>Active</span>
              </div>
            </div>
          ))}
          {creds.length === 0 && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-faint)', padding: 'var(--space-sm) 0' }}>
              No credentials registered
            </div>
          )}
        </div>

        {lastAccess && (
          <div style={{
            marginTop: 'var(--space-md)',
            paddingTop: 'var(--space-md)',
            borderTop: '1px solid var(--border-subtle)',
          }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-faint)', marginBottom: '2px' }}>
              Last accessed
            </div>
            <div style={{
              fontSize: '0.75rem',
              color: 'var(--text-secondary)',
              fontWeight: 500,
            }}>
              {lastAccess.tool_id}
            </div>
            <div style={{
              fontSize: '0.68rem',
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-muted)',
            }}>
              {formatTime(lastAccess.accessed_at)} · {lastAccess.action_id?.slice(0, 8)}…
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
