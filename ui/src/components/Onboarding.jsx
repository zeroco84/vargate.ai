import React, { useState, useEffect } from 'react';
import { fetchDashboardMe } from '../api';

export default function Onboarding({ onDismiss }) {
  const [me, setMe] = useState(null);
  const [step, setStep] = useState(0);
  const [copied, setCopied] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    fetchDashboardMe().then(setMe);
  }, []);

  if (!me) return null;

  const apiKeyDisplay = me.api_key_prefix || 'vg-...';

  const steps = [
    {
      title: 'Your API Key',
      content: (
        <div>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '13px', marginBottom: '16px' }}>
            Use this key in the <code style={{ color: '#818cf8' }}>X-API-Key</code> header to authenticate your agent's requests.
          </p>
          <div style={{
            padding: '14px 16px', background: 'rgba(0,0,0,0.3)', borderRadius: '8px',
            fontFamily: 'JetBrains Mono, monospace', fontSize: '13px', color: '#10b981',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span>{apiKeyDisplay}</span>
            <button onClick={() => { navigator.clipboard.writeText(apiKeyDisplay); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
              style={{ background: 'none', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', color: '#818cf8', padding: '4px 10px', cursor: 'pointer', fontSize: '12px' }}>
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: '12px', marginTop: '8px' }}>
            Your full API key was shown when you signed up. If lost, rotate it in Settings.
          </p>
        </div>
      ),
    },
    {
      title: 'Send Your First Action',
      content: (
        <div>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '13px', marginBottom: '16px' }}>
            Send a tool call to the gateway. Here's a quick example:
          </p>
          <pre style={{
            padding: '14px', background: 'rgba(0,0,0,0.3)', borderRadius: '8px',
            fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: '#e2e8f0',
            overflow: 'auto', lineHeight: 1.6,
          }}>{`curl -X POST ${window.location.origin}/api/mcp/tools/call \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -d '{
    "agent_id": "my-agent-001",
    "tool": "salesforce",
    "method": "update_record",
    "params": {"object": "Lead", "amount": 500}
  }'`}</pre>
        </div>
      ),
    },
    {
      title: 'Check Status',
      content: (
        <div>
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '13px', marginBottom: '16px' }}>
            Verify your setup by checking if any actions have been recorded.
          </p>
          <button onClick={async () => {
            setTesting(true);
            const data = await fetchDashboardMe();
            setTestResult(data);
            setTesting(false);
          }}
            style={{
              padding: '12px 24px', borderRadius: '10px', border: 'none',
              background: '#6366f1', color: 'white', fontSize: '14px', fontWeight: 500,
              cursor: 'pointer', width: '100%',
            }}>
            {testing ? 'Checking...' : 'Check My Status'}
          </button>
          {testResult && (
            <div style={{
              marginTop: '16px', padding: '14px', background: 'rgba(0,0,0,0.3)',
              borderRadius: '8px', fontSize: '13px',
            }}>
              <div style={{ color: testResult.activated ? '#10b981' : '#f59e0b', fontWeight: 600, marginBottom: '8px' }}>
                {testResult.activated ? 'Activated! Your first action has been recorded.' : 'Not yet activated. Send your first tool call to activate.'}
              </div>
              <div style={{ color: 'rgba(255,255,255,0.4)' }}>
                Total actions: {testResult.stats.total_actions} | Allowed: {testResult.stats.allowed} | Denied: {testResult.stats.denied}
              </div>
            </div>
          )}
        </div>
      ),
    },
  ];

  return (
    <div style={{
      padding: '24px', background: 'rgba(99,102,241,0.05)', borderRadius: '16px',
      border: '1px solid rgba(99,102,241,0.15)', marginBottom: '20px',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div style={{ fontSize: '16px', fontWeight: 600 }}>Getting Started</div>
        <button onClick={onDismiss} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)', cursor: 'pointer', fontSize: '18px' }}>x</button>
      </div>

      {/* Step indicators */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
        {steps.map((s, i) => (
          <div key={i} onClick={() => setStep(i)} style={{
            flex: 1, height: '3px', borderRadius: '2px', cursor: 'pointer',
            background: i <= step ? '#6366f1' : 'rgba(255,255,255,0.1)',
            transition: 'background 0.3s',
          }} />
        ))}
      </div>

      <div style={{ fontSize: '15px', fontWeight: 600, marginBottom: '16px' }}>
        Step {step + 1}: {steps[step].title}
      </div>

      {steps[step].content}

      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '20px' }}>
        <button onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0}
          style={{ padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', background: 'transparent', color: step === 0 ? 'rgba(255,255,255,0.2)' : '#e2e8f0', cursor: step === 0 ? 'default' : 'pointer', fontSize: '13px' }}>
          Back
        </button>
        {step < steps.length - 1 ? (
          <button onClick={() => setStep(step + 1)}
            style={{ padding: '8px 16px', borderRadius: '8px', border: 'none', background: '#6366f1', color: 'white', cursor: 'pointer', fontSize: '13px', fontWeight: 500 }}>
            Next
          </button>
        ) : (
          <button onClick={onDismiss}
            style={{ padding: '8px 16px', borderRadius: '8px', border: 'none', background: '#10b981', color: 'white', cursor: 'pointer', fontSize: '13px', fontWeight: 500 }}>
            Done
          </button>
        )}
      </div>
    </div>
  );
}
