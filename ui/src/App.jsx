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
  fetchAuditAgents,
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
  const [totalRecords, setTotalRecords] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);
  const [agents, setAgents] = useState([]);
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

  // Server-side pagination: fetch first 10 on init / each poll, merge new
  // records at the top so the user's expanded view stays intact. More records
  // are pulled on demand via loadMoreRecords().
  const INITIAL_RECORDS = 10;
  const PAGE_SIZE = 20;

  const refreshAll = useCallback(async () => {
    const [auditData, agentsData, chainData, policyData, anchorStat, anchorLogData, anchorVerifyData, credData, credLogData] =
      await Promise.all([
        fetchAuditLog(INITIAL_RECORDS),
        fetchAuditAgents(20),
        fetchChainVerify(),
        fetchBundleStatus(),
        fetchAnchorStatus(),
        fetchAnchorLog(),
        fetchAnchorVerify(),
        fetchCredentials(),
        fetchCredentialAccessLog(),
      ]);

    if (agentsData?.agents) setAgents(agentsData.agents);

    if (auditData?.records) {
      const newSet = new Set();
      for (const rec of auditData.records) {
        if (!knownIdsRef.current.has(rec.action_id)) {
          newSet.add(rec.action_id);
          knownIdsRef.current.add(rec.action_id);
        }
      }
      setNewIds(newSet);
      if (newSet.size > 0) {
        setTimeout(() => setNewIds(new Set()), 1000);
      }
      // Merge: add only not-yet-seen records to the top, preserving any
      // older ones the user has revealed via loadMoreRecords().
      setRecords(prev => {
        if (prev.length === 0) return auditData.records;
        const existing = new Set(prev.map(r => r.action_id));
        const incoming = auditData.records.filter(r => !existing.has(r.action_id));
        return incoming.length > 0 ? [...incoming, ...prev] : prev;
      });
      if (typeof auditData.total === 'number') setTotalRecords(auditData.total);
    }

    if (chainData) setChain(chainData);
    if (policyData) setPolicy(policyData);
    if (anchorStat) setAnchorStatus(anchorStat);
    if (anchorLogData?.anchors) setAnchorLog(anchorLogData.anchors);
    if (anchorVerifyData) setAnchorVerify(anchorVerifyData);
    if (credData?.credentials) setCredentials(credData.credentials);
    if (credLogData?.entries) setAccessLog(credLogData.entries);
  }, []);

  const loadMoreRecords = useCallback(async () => {
    setLoadingMore(true);
    try {
      const data = await fetchAuditLog(PAGE_SIZE, records.length);
      if (data?.records?.length) {
        setRecords(prev => {
          const existing = new Set(prev.map(r => r.action_id));
          const older = data.records.filter(r => !existing.has(r.action_id));
          return [...prev, ...older];
        });
      }
      if (typeof data?.total === 'number') setTotalRecords(data.total);
    } finally {
      setLoadingMore(false);
    }
  }, [records.length]);

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
            <AgentPanel agents={agents} />
            <PolicyPanel policy={policy} />
          </div>

          {/* Centre Column — Live Activity Feed */}
          <div className="col-center">
            <ActivityFeed
              records={records}
              newIds={newIds}
              total={totalRecords}
              onLoadMore={loadMoreRecords}
              loadingMore={loadingMore}
            />
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
