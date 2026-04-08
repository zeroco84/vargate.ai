import React, { useState } from 'react';
import { timeAgo, truncate, formatTime } from '../api';
import { triggerAnchor } from '../api';

const EXPLORER_URLS = {
  polygon: 'https://polygonscan.com',
  polygon_amoy: 'https://amoy.polygonscan.com',
  sepolia: 'https://sepolia.etherscan.io',
  ethereum: 'https://etherscan.io',
};

function explorerLink(chain, txHash) {
  const base = EXPLORER_URLS[chain];
  if (base && txHash) return `${base}/tx/${txHash}`;
  return null;
}

export default function AnchorPanel({ anchorStatus, anchorLog, anchorVerify }) {
  const [showHistory, setShowHistory] = useState(false);
  const [anchoring, setAnchoring] = useState(false);

  const connected = anchorStatus?.blockchain_connected;
  const contract = anchorStatus?.contract_address;
  const connectedChains = anchorStatus?.connected_chains || [];
  const merkleTreeStats = anchorStatus?.merkle_trees;

  const lastAnchor = anchorLog?.[0];

  const handleAnchorNow = async () => {
    setAnchoring(true);
    await triggerAnchor();
    setAnchoring(false);
  };

  const networkLabel = connectedChains.length > 0
    ? connectedChains.join(', ')
    : anchorStatus?.network || 'local';

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Blockchain Anchor</span>
        <span style={{
          fontSize: '0.62rem',
          padding: '1px 6px',
          borderRadius: '3px',
          background: connected ? 'var(--accent-green-bg)' : 'var(--accent-red-bg)',
          color: connected ? 'var(--accent-green)' : 'var(--accent-red)',
        }}>
          {connected ? networkLabel.toUpperCase() : 'OFFLINE'}
        </span>
      </div>
      <div className="panel-body">
        {!connected ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>Not connected</div>
        ) : (
          <>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-faint)', marginBottom: 'var(--space-md)' }}>
              Contract: {contract ? truncate(contract, 14) : '\u2014'}
            </div>

            {/* Multi-chain status */}
            {connectedChains.length > 0 && (
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 'var(--space-sm)' }}>
                Chains: {connectedChains.map(c => (
                  <span key={c} style={{
                    display: 'inline-block',
                    padding: '0 4px',
                    margin: '0 2px',
                    borderRadius: '3px',
                    background: 'var(--bg-tertiary)',
                    color: 'var(--text-secondary)',
                    fontSize: '0.62rem',
                  }}>{c}</span>
                ))}
              </div>
            )}

            {/* Merkle tree anchor stats */}
            {merkleTreeStats && (
              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 'var(--space-sm)' }}>
                Trees anchored: {merkleTreeStats.anchored}/{merkleTreeStats.total}
              </div>
            )}

            {lastAnchor && (
              <>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Last anchored: {timeAgo(lastAnchor.anchored_at || lastAnchor.timestamp)}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Block #{lastAnchor.block_number} {'\u00B7'} {lastAnchor.record_count || lastAnchor.records_covered || '\u2014'} records
                </div>
                {lastAnchor.tx_hash && lastAnchor.source !== 'hardhat_legacy' && (
                  <a
                    href={explorerLink(lastAnchor.source === 'sepolia_merkle' ? 'sepolia' : (lastAnchor.anchor_chain || 'sepolia'), lastAnchor.tx_hash)}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontSize: '0.68rem', color: 'var(--accent-green)', textDecoration: 'none' }}
                  >
                    View on explorer &rarr;
                  </a>
                )}
              </>
            )}

            {anchorVerify?.match && (
              <div style={{
                marginTop: 'var(--space-md)',
                fontSize: '0.72rem',
                color: 'var(--accent-green)',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
              }}>
                Chain tip matches on-chain anchor
              </div>
            )}

            <div style={{ display: 'flex', gap: 'var(--space-sm)', marginTop: 'var(--space-md)' }}>
              <button className="btn btn-ghost" onClick={handleAnchorNow} disabled={anchoring}>
                {anchoring ? 'Anchoring\u2026' : 'Anchor Now'}
              </button>
              <button className="btn btn-ghost" onClick={() => setShowHistory(!showHistory)}>
                {showHistory ? 'Hide' : 'View History'}
              </button>
            </div>

            {showHistory && anchorLog && (
              <div style={{ marginTop: 'var(--space-md)', maxHeight: '200px', overflowY: 'auto' }}>
                <table style={{ width: '100%', fontSize: '0.62rem', fontFamily: 'var(--font-mono)' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Block</th>
                      <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Root</th>
                      <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Tx</th>
                      <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {anchorLog.map((a, i) => {
                      const chain = a.source === 'sepolia_merkle' ? 'sepolia' : (a.anchor_chain || 'hardhat');
                      const link = explorerLink(chain, a.tx_hash);
                      return (
                        <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                          <td style={{ padding: '4px', color: 'var(--text-muted)' }}>#{a.block_number}</td>
                          <td style={{ padding: '4px', color: 'var(--text-faint)' }}>
                            {(a.merkle_root || a.chain_tip_hash || '').slice(0, 10)}...
                          </td>
                          <td style={{ padding: '4px' }}>
                            {link ? (
                              <a href={link} target="_blank" rel="noopener noreferrer"
                                style={{ color: 'var(--accent-green)', textDecoration: 'none' }}>
                                {chain}
                              </a>
                            ) : (
                              <span style={{ color: 'var(--text-faint)' }}>local</span>
                            )}
                          </td>
                          <td style={{ padding: '4px', color: 'var(--text-muted)' }}>
                            {formatTime(a.anchored_at || a.timestamp)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
