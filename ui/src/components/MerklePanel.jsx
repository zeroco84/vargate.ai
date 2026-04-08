import React, { useState, useEffect } from 'react';
import { fetchMerkleRoots, fetchMerkleProof, fetchMerkleVerify, truncate, formatTime } from '../api';

export default function MerklePanel({ records }) {
  const [trees, setTrees] = useState([]);
  const [verify, setVerify] = useState(null);
  const [selectedProof, setSelectedProof] = useState(null);
  const [proofLoading, setProofLoading] = useState(false);
  const [showTrees, setShowTrees] = useState(false);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    const [rootsData, verifyData] = await Promise.all([
      fetchMerkleRoots(),
      fetchMerkleVerify(),
    ]);
    if (rootsData?.trees) setTrees(rootsData.trees);
    if (verifyData) setVerify(verifyData);
  }

  async function handleProof(record) {
    if (!record?.record_hash) return;
    setProofLoading(true);
    setSelectedProof(null);
    const proof = await fetchMerkleProof(record.record_hash);
    setSelectedProof(proof);
    setProofLoading(false);
  }

  const chainValid = verify?.valid;
  const treeCount = verify?.tree_count || 0;
  const recordCount = verify?.record_count || 0;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Merkle Trees</span>
        <span style={{
          fontSize: '0.62rem',
          padding: '1px 6px',
          borderRadius: '3px',
          background: chainValid ? 'var(--accent-green-bg)' : 'var(--accent-red-bg)',
          color: chainValid ? 'var(--accent-green)' : 'var(--accent-red)',
        }}>
          {chainValid ? 'VALID' : verify ? 'INVALID' : '...'}
        </span>
      </div>
      <div className="panel-body">
        {/* Summary */}
        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>
          {treeCount} hourly tree{treeCount !== 1 ? 's' : ''} covering {recordCount} record{recordCount !== 1 ? 's' : ''}
        </div>

        {verify?.first_period && (
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 'var(--space-md)' }}>
            {verify.first_period.slice(0, 16)} &rarr; {verify.last_period.slice(0, 16)}
          </div>
        )}

        {verify?.issues?.length > 0 && (
          <div style={{
            fontSize: '0.68rem',
            color: 'var(--accent-red)',
            marginBottom: 'var(--space-md)',
            padding: '4px 8px',
            background: 'var(--accent-red-bg)',
            borderRadius: '4px',
          }}>
            {verify.issues.length} integrity issue{verify.issues.length > 1 ? 's' : ''} detected
          </div>
        )}

        {/* Tree visualization */}
        <div style={{ display: 'flex', gap: 'var(--space-sm)', marginBottom: 'var(--space-md)', flexWrap: 'wrap' }}>
          {trees.slice(0, 24).map((t) => (
            <div
              key={t.tree_index}
              title={`Tree ${t.tree_index}: ${t.record_count} records\n${t.period_start}\nRoot: ${t.merkle_root.slice(0, 16)}...`}
              style={{
                width: '24px',
                height: '24px',
                borderRadius: '3px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '0.58rem',
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
                background: t.anchored ? 'var(--accent-green-bg)' : 'var(--bg-tertiary)',
                color: t.anchored ? 'var(--accent-green)' : 'var(--text-muted)',
                border: `1px solid ${t.anchored ? 'var(--accent-green)' : 'var(--border-subtle)'}`,
              }}
              onClick={() => setShowTrees(!showTrees)}
            >
              {t.record_count}
            </div>
          ))}
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 'var(--space-sm)', marginBottom: 'var(--space-md)' }}>
          <button className="btn btn-ghost" onClick={() => setShowTrees(!showTrees)}>
            {showTrees ? 'Hide Trees' : 'View Trees'}
          </button>
        </div>

        {/* Tree detail table */}
        {showTrees && trees.length > 0 && (
          <div style={{ maxHeight: '240px', overflowY: 'auto', marginBottom: 'var(--space-md)' }}>
            <table style={{ width: '100%', fontSize: '0.62rem', fontFamily: 'var(--font-mono)' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>#</th>
                  <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Period</th>
                  <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Records</th>
                  <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Root</th>
                  <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Anchor</th>
                </tr>
              </thead>
              <tbody>
                {trees.map((t) => (
                  <tr key={t.tree_index} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '4px', color: 'var(--text-muted)' }}>{t.tree_index}</td>
                    <td style={{ padding: '4px', color: 'var(--text-muted)' }}>
                      {t.period_start.slice(11, 16)}
                    </td>
                    <td style={{ padding: '4px', color: 'var(--text-secondary)' }}>{t.record_count}</td>
                    <td style={{ padding: '4px', color: 'var(--text-faint)' }}>{t.merkle_root.slice(0, 10)}...</td>
                    <td style={{ padding: '4px' }}>
                      {t.anchor_tx_hash ? (
                        <a
                          href={`https://${t.anchor_chain === 'polygon' ? 'polygonscan.com' :
                            t.anchor_chain === 'polygon_amoy' ? 'amoy.polygonscan.com' :
                            t.anchor_chain === 'ethereum' ? 'etherscan.io' :
                            'sepolia.etherscan.io'}/tx/${t.anchor_tx_hash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ color: 'var(--accent-green)', textDecoration: 'none', fontSize: '0.6rem' }}
                        >
                          {t.anchor_chain} tx
                        </a>
                      ) : (
                        <span style={{ color: 'var(--text-faint)' }}>pending</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Proof viewer */}
        {records && records.length > 0 && (
          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 'var(--space-sm)' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 'var(--space-xs)' }}>
              Inclusion Proof
            </div>
            <select
              onChange={(e) => {
                const rec = records.find(r => r.record_hash === e.target.value);
                if (rec) handleProof(rec);
              }}
              style={{
                width: '100%',
                fontSize: '0.68rem',
                padding: '4px',
                background: 'var(--bg-tertiary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '4px',
                fontFamily: 'var(--font-mono)',
                marginBottom: 'var(--space-sm)',
              }}
              defaultValue=""
            >
              <option value="" disabled>Select a record to verify...</option>
              {records.slice(0, 50).map((r) => (
                <option key={r.action_id} value={r.record_hash}>
                  {r.action_id.slice(0, 8)} ({r.decision}) {r.tool}.{r.method}
                </option>
              ))}
            </select>

            {proofLoading && (
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Loading proof...</div>
            )}

            {selectedProof && !proofLoading && (
              <div style={{
                background: 'var(--bg-tertiary)',
                borderRadius: '4px',
                padding: '8px',
                fontSize: '0.62rem',
                fontFamily: 'var(--font-mono)',
              }}>
                <div style={{ color: selectedProof.verified ? 'var(--accent-green)' : 'var(--accent-red)', marginBottom: '4px' }}>
                  {selectedProof.verified ? 'VERIFIED' : 'FAILED'} in Tree #{selectedProof.tree_index}
                </div>
                <div style={{ color: 'var(--text-muted)' }}>
                  Leaf: {selectedProof.leaf_index} / {selectedProof.tree_size}
                </div>
                <div style={{ color: 'var(--text-muted)' }}>
                  Period: {selectedProof.period_start?.slice(11, 16)} - {selectedProof.period_end?.slice(11, 16)}
                </div>
                <div style={{ color: 'var(--text-muted)' }}>
                  Depth: {selectedProof.proof_depth} step{selectedProof.proof_depth !== 1 ? 's' : ''}
                </div>

                {/* Proof path visualization */}
                <div style={{ marginTop: '6px', borderTop: '1px solid var(--border-subtle)', paddingTop: '4px' }}>
                  <div style={{ color: 'var(--text-faint)', marginBottom: '2px' }}>Proof path:</div>
                  {selectedProof.proof?.map((step, i) => (
                    <div key={i} style={{ color: 'var(--text-muted)', paddingLeft: `${i * 8}px` }}>
                      {step.position === 'left' ? '\u2190' : '\u2192'} {step.sibling.slice(0, 12)}...
                    </div>
                  ))}
                  <div style={{
                    color: 'var(--accent-green)',
                    paddingLeft: `${(selectedProof.proof?.length || 0) * 8}px`,
                    marginTop: '2px',
                  }}>
                    = {selectedProof.tree_root?.slice(0, 16)}... (root)
                  </div>
                </div>

                {selectedProof.anchor_tx_hash && (
                  <div style={{ marginTop: '4px', color: 'var(--accent-green)' }}>
                    Anchored: {selectedProof.anchor_chain} tx {selectedProof.anchor_tx_hash.slice(0, 12)}...
                  </div>
                )}
              </div>
            )}

            {selectedProof === null && !proofLoading && (
              <div style={{ fontSize: '0.62rem', color: 'var(--text-faint)' }}>
                Select a record to generate its Merkle inclusion proof
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
