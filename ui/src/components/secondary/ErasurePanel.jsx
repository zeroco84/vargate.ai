import React, { useState, useEffect } from 'react';
import { fetchAuditSubjects, fetchSubjectKeyStatus, eraseSubject, verifyErasure } from '../../api';

export default function ErasurePanel() {
  const [subjects, setSubjects] = useState([]);
  const [selectedSubject, setSelectedSubject] = useState('');
  const [keyStatus, setKeyStatus] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchAuditSubjects().then(data => {
      if (data?.subjects) setSubjects(data.subjects);
    });
  }, []);

  const handleCheckKey = async () => {
    if (!selectedSubject) return;
    const data = await fetchSubjectKeyStatus(selectedSubject);
    setKeyStatus(data);
  };

  const handleErase = async () => {
    if (!selectedSubject) return;
    setLoading(true);
    const data = await eraseSubject(selectedSubject);
    setResult({ type: 'erased', data });
    setLoading(false);
  };

  const handleVerify = async () => {
    if (!selectedSubject) return;
    setLoading(true);
    const data = await verifyErasure(selectedSubject);
    setResult({ type: 'verified', data });
    setLoading(false);
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">GDPR Crypto-Shredding</span>
      </div>
      <div className="panel-body">
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 'var(--space-lg)' }}>
          Erase a data subject's PII by destroying their encryption key. The audit chain remains intact — only the encrypted fields become unreadable.
        </p>

        <div style={{ marginBottom: 'var(--space-lg)' }}>
          <label className="label">Data Subject</label>
          <select
            className="select"
            value={selectedSubject}
            onChange={e => { setSelectedSubject(e.target.value); setKeyStatus(null); setResult(null); }}
          >
            <option value="">Select subject…</option>
            {subjects.map((s, i) => {
              const id = typeof s === 'string' ? s : s.subject_id;
              return <option key={id || i} value={id}>{id}</option>;
            })}
          </select>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-sm)', marginBottom: 'var(--space-lg)' }}>
          <button className="btn btn-ghost" onClick={handleCheckKey} disabled={!selectedSubject}>
            🔑 Check Key Status
          </button>
          <button className="btn btn-danger" onClick={handleErase} disabled={!selectedSubject || loading}>
            🗑 Erase Subject
          </button>
          <button className="btn btn-ghost" onClick={handleVerify} disabled={!selectedSubject || loading}>
            ✓ Verify Erasure
          </button>
        </div>

        {keyStatus && (
          <div style={{
            padding: 'var(--space-md)',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--bg-base)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.78rem',
            marginBottom: 'var(--space-md)',
          }}>
            <span style={{ color: 'var(--text-muted)' }}>Key status: </span>
            <span style={{ color: keyStatus.exists ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 600 }}>
              {keyStatus.exists ? '● Active' : '● Destroyed'}
            </span>
          </div>
        )}

        {result && (
          <div style={{
            padding: 'var(--space-md)',
            borderRadius: 'var(--radius-sm)',
            background: result.type === 'erased' ? 'var(--accent-red-bg)' : 'var(--accent-green-bg)',
            border: `1px solid ${result.type === 'erased' ? 'var(--accent-red-border)' : 'var(--accent-green-border)'}`,
            color: result.type === 'erased' ? 'var(--accent-red)' : 'var(--accent-green)',
            fontSize: '0.78rem',
          }}>
            {result.type === 'erased'
              ? `Subject "${selectedSubject}" erased — encryption key destroyed.`
              : result.data?.verified
                ? `✓ Erasure verified — all PII fields are unreadable.`
                : `⚠ Verification inconclusive.`}
          </div>
        )}
      </div>
    </div>
  );
}
