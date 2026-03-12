import React from 'react';
import { formatTime } from '../api';

export default function AgentPanel({ records }) {
  // Derive agent data from audit records
  const agents = {};
  for (const rec of records) {
    if (!agents[rec.agent_id]) {
      agents[rec.agent_id] = {
        id: rec.agent_id,
        tools: new Set(),
        total: 0,
        blocked: 0,
        lastAction: rec.created_at,
        anomalyScore: rec.anomaly_score_at_eval || 0,
      };
    }
    const a = agents[rec.agent_id];
    a.tools.add(rec.tool);
    a.total++;
    if (rec.decision === 'deny') a.blocked++;
    if (rec.anomaly_score_at_eval > a.anomalyScore) {
      a.anomalyScore = rec.anomaly_score_at_eval;
    }
  }

  const agentList = Object.values(agents).sort((a, b) => b.total - a.total);

  // Agent display names
  const agentNames = {
    'agent-sales-eu-007': { name: 'Sales Agent EU', icon: '🦞' },
    'agent-sales-001': { name: 'Sales Agent', icon: '💼' },
    'agent-comms-001': { name: 'Comms Agent', icon: '📧' },
    'agent-billing-001': { name: 'Billing Agent', icon: '💳' },
    'agent-billing-002': { name: 'Billing Agent 2', icon: '💳' },
    'agent-notify-001': { name: 'Notify Agent', icon: '🔔' },
    'agent-bad-001': { name: 'Test Agent', icon: '🤖' },
  };

  const getAgent = (id) => agentNames[id] || { name: id.slice(0, 20), icon: '🤖' };

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
          return (
            <div key={agent.id}>
              <div className="agent-card">
                <div className="agent-avatar">{display.icon}</div>
                <div className="agent-info">
                  <div className="agent-name">{display.name}</div>
                  <div className="agent-id">{agent.id}</div>
                </div>
              </div>

              <div style={{ marginTop: 'var(--space-md)' }}>
                <div className="agent-stat">
                  <span className="agent-stat-label">Tools</span>
                  <span className="agent-stat-value">{[...agent.tools].join(', ')}</span>
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
