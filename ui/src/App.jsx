import React, { useState, useEffect, useCallback, useRef } from 'react';
import './index.css';

// Components
import Header from './components/Header';
import AgentPanel from './components/AgentPanel';
import PolicyPanel from './components/PolicyPanel';
import ActivityFeed from './components/ActivityFeed';
import ChainPanel from './components/ChainPanel';
import AnchorPanel from './components/AnchorPanel';
import MerklePanel from './components/MerklePanel';
import VaultPanel from './components/VaultPanel';

// Secondary views
import TamperSim from './components/secondary/TamperSim';
import PolicyReplay from './components/secondary/PolicyReplay';
import ErasurePanel from './components/secondary/ErasurePanel';
import VaultManage from './components/secondary/VaultManage';

// Sprint 3
import Onboarding from './components/Onboarding';
import SettingsPage from './components/Settings';

// Sprint 4
import ApprovalQueue from './components/ApprovalQueue';

// Sprint 12 — Managed Agent Sessions
import ManagedSessionList from './components/ManagedSessionList';
import ManagedSessionDetail from './components/ManagedSessionDetail';

// API helpers
import {
  fetchAuditLog,
  fetchChainVerify,
  fetchBundleStatus,
  fetchAnchorStatus,
  fetchAnchorLog,
  fetchAnchorVerify,
  fetchCredentials,
  fetchCredentialAccessLog,
} from './api';

export default function App({ session, onLogout }) {
  const isPublic = session?.isPublic || false;

  // ── State ──────────────────────────────────────────────────────────────────

  const [view, setView] = useState('dashboard');       // 'dashboard' | 'settings' | 'account' | 'sessions'
  const [selectedSession, setSelectedSession] = useState(null);
  const [liveMode, setLiveMode] = useState(true);
  const [showOnboarding, setShowOnboarding] = useState(() => !isPublic && !localStorage.getItem('vargate_onboarding_done'));

  // Data
  const [records, setRecords] = useState([]);
  const [chain, setChain] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [anchorStatus, setAnchorStatus] = useState(null);
  const [anchorLog, setAnchorLog] = useState([]);
  const [anchorVerify, setAnchorVerify] = useState(null);
  const [credentials, setCredentials] = useState([]);
  const [accessLog, setAccessLog] = useState([]);

  // Track new records for animation
  const [newIds, setNewIds] = useState(new Set());
  const knownIdsRef = useRef(new Set());

  // ── Fetch Data ─────────────────────────────────────────────────────────────

  const refreshAll = useCallback(async () => {
    const [auditData, chainData, policyData, anchorStat, anchorLogData, anchorVerifyData, credData, credLogData] =
      await Promise.all([
        fetchAuditLog(200),
        fetchChainVerify(),
        fetchBundleStatus(),
        fetchAnchorStatus(),
        fetchAnchorLog(),
        fetchAnchorVerify(),
        fetchCredentials(),
        fetchCredentialAccessLog(),
      ]);

    if (auditData?.records) {
      const newSet = new Set();
      for (const rec of auditData.records) {
        if (!knownIdsRef.current.has(rec.action_id)) {
          newSet.add(rec.action_id);
          knownIdsRef.current.add(rec.action_id);
        }
      }
      setNewIds(newSet);
      // Clear animation flags after delay
      if (newSet.size > 0) {
        setTimeout(() => setNewIds(new Set()), 1000);
      }
      setRecords(auditData.records);
    }

    if (chainData) setChain(chainData);
    if (policyData) setPolicy(policyData);
    if (anchorStat) setAnchorStatus(anchorStat);
    if (anchorLogData?.anchors) setAnchorLog(anchorLogData.anchors);
    if (anchorVerifyData) setAnchorVerify(anchorVerifyData);
    if (credData?.credentials) setCredentials(credData.credentials);
    if (credLogData?.entries) setAccessLog(credLogData.entries);
  }, []);

  // ── Polling ────────────────────────────────────────────────────────────────

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  useEffect(() => {
    if (!liveMode) return;
    const interval = setInterval(refreshAll, 3000);
    return () => clearInterval(interval);
  }, [liveMode, refreshAll]);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="app-layout">
      <Header
        chain={chain}
        liveMode={liveMode}
        setLiveMode={setLiveMode}
        anchorStatus={anchorStatus}
        policy={policy}
        view={view}
        setView={isPublic ? () => {} : setView}
        onLogout={isPublic ? null : onLogout}
        session={session}
        onTenantSwitch={isPublic ? null : () => window.location.reload()}
        isPublic={isPublic}
      />

      {view === 'account' ? (
        <SettingsPage onBack={() => setView('dashboard')} />
      ) : view === 'approvals' ? (
        <div className="settings-layout">
          <button className="settings-back" onClick={() => setView('dashboard')}>
            &larr; Back to Dashboard
          </button>
          <ApprovalQueue />
        </div>
      ) : view === 'sessions' ? (
        <div className="settings-layout">
          {selectedSession ? (
            <ManagedSessionDetail
              sessionId={selectedSession}
              onBack={() => setSelectedSession(null)}
            />
          ) : (
            <>
              <button className="settings-back" onClick={() => setView('dashboard')}>
                &larr; Back to Dashboard
              </button>
              <ManagedSessionList
                onSelectSession={(id) => setSelectedSession(id)}
              />
            </>
          )}
        </div>
      ) : view === 'dashboard' ? (
        <div className="main-content">
          {/* Onboarding wizard (Sprint 3) */}
          {showOnboarding && (
            <div style={{ gridColumn: '1 / -1', padding: '0 20px' }}>
              <Onboarding onDismiss={() => { setShowOnboarding(false); localStorage.setItem('vargate_onboarding_done', '1'); }} />
            </div>
          )}

          {/* Left Column — Agent & Policy */}
          <div className="col-left">
            <AgentPanel records={records} />
            <PolicyPanel policy={policy} />
          </div>

          {/* Centre Column — Live Activity Feed */}
          <div className="col-center">
            <ActivityFeed records={records} newIds={newIds} />
          </div>

          {/* Right Column — Trust Indicators */}
          <div className="col-right">
            <ChainPanel chain={chain} />
            <MerklePanel records={records} />
            <AnchorPanel
              anchorStatus={anchorStatus}
              anchorLog={anchorLog}
              anchorVerify={anchorVerify}
              isPublic={isPublic}
            />
            <VaultPanel credentials={credentials} accessLog={accessLog} />
          </div>
        </div>
      ) : (
        <div className="settings-layout">
          <button className="settings-back" onClick={() => setView('dashboard')}>
            ← Back to Dashboard
          </button>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-xl)' }}>
            <TamperSim onRefresh={refreshAll} />
            <PolicyReplay />
            <ErasurePanel />
            <VaultManage />
          </div>
        </div>
      )}
    </div>
  );
}
