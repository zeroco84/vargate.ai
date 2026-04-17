import React from 'react';
import { formatTime } from '../api';

// Agents we publicly surface. IDs not in this allowlist are filtered out
// of the panel regardless of whether they appear in the audit stream —
// keeps smoke-test artefacts, deprecated IDs, and system-internal agents
// (human-reviewer, media-upload, admin-cleanup) off the public dashboard.
const PUBLIC_AGENTS = {
  'sera-cmo-001': {
    name: 'Sera',
    title: 'CMO (AI)',
    avatar: '/sera-avatar.png',
    profileUrl: 'https://www.instagram.com/am.i.sera/',
  },
};

export default function AgentPanel({ agents = [] }) {
  // `agents` comes from the dedicated /audit/agents endpoint, which
  // aggregates across the full tenant history — independent of the
  // paginated activity-feed window.
  //
  // Normalise to the shape this panel expects, then restrict to the
  // public allowlist.
  const agentList = agents
    .filter((a) => PUBLIC_AGENTS[a.agent_id])
    .map((a) => ({
      id: a.agent_id,
      tools: a.tools || [],
      total: a.total || 0,
      blocked: a.blocked || 0,
      lastAction: a.last_action,
      anomalyScore: a.anomaly_score || 0,
    }))
    .sort((a, b) => b.total - a.total);

  const getAgent = (id) => PUBLIC_AGENTS[id] || { name: id.slice(0, 20) };

  const anomalyBarColor = (score) => {
    if (score >= 0.7) return 'var(--accent-red)';
    if (score >= 0.4) return 'var(--accent-amber)';
    return 'var(--accent-green)';
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Supervised Agents</span>
        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {agentList.length}
        </span>
      </div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-lg)' }}>
        {agentList.length === 0 && (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem', textAlign: 'center', padding: 'var(--space-lg) 0' }}>
            No agent activity yet
          </div>
        )}
        {agentList.slice(0, 5).map((agent) => {
          const display = getAgent(agent.id);
          const avatarInner = display.avatar ? (
            <img src={display.avatar} alt={display.name} style={{
              width: '100%', height: '100%', borderRadius: '50%', objectFit: 'cover',
            }} />
          ) : display.icon;
          const avatar = display.profileUrl ? (
            <a
              href={display.profileUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="agent-avatar"
              title={`Visit ${display.name} on Instagram`}
              style={{ display: 'inline-block', cursor: 'pointer' }}
            >
              {avatarInner}
            </a>
          ) : (
            <div className="agent-avatar">{avatarInner}</div>
          );
          return (
            <div key={agent.id}>
              <div className="agent-card">
                {avatar}
                <div className="agent-info">
                  <div className="agent-name">{display.name}</div>
                  {display.title && (
                    <div className="agent-id" style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
                      {display.title}
                    </div>
                  )}
                  <div className="agent-id">{agent.id}</div>
                </div>
              </div>

              <div style={{ marginTop: 'var(--space-md)' }}>
                <div className="agent-stat">
                  <span className="agent-stat-label">Tools</span>
                  <span className="agent-stat-value">{(agent.tools || []).join(', ')}</span>
                </div>
                <div className="agent-stat">
                  <span className="agent-stat-label">Actions</span>
                  <span className="agent-stat-value">
                    {agent.total}
                    {agent.blocked > 0 && (
                      <span style={{ color: 'var(--accent-red)', marginLeft: '6px' }}>
                        · {agent.blocked} blocked
                      </span>
                    )}
                  </span>
                </div>
                <div className="agent-stat">
                  <span className="agent-stat-label">Anomaly</span>
                  <span className="agent-stat-value">{agent.anomalyScore.toFixed(4)}</span>
                </div>
                <div className="anomaly-bar-track">
                  <div
                    className="anomaly-bar-fill"
                    style={{
                      width: `${Math.min(agent.anomalyScore * 100, 100)}%`,
                      background: anomalyBarColor(agent.anomalyScore),
                    }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
