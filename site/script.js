/* ═══════════════════════════════════════════════════════════════════════════
   VARGATE.AI — Marketing Site JavaScript
   Navigation, scroll reveals, workflow animation
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Navigation ────────────────────────────────────────────────────────────

const nav = document.getElementById('nav');
const hamburger = document.getElementById('navHamburger');
const mobileOverlay = document.getElementById('mobileOverlay');

// Scroll-based nav background
let ticking = false;
window.addEventListener('scroll', () => {
  if (!ticking) {
    requestAnimationFrame(() => {
      nav.classList.toggle('scrolled', window.scrollY > 40);
      ticking = false;
    });
    ticking = true;
  }
});

// Mobile menu
hamburger.addEventListener('click', () => {
  hamburger.classList.toggle('open');
  mobileOverlay.classList.toggle('open');
  document.body.style.overflow = hamburger.classList.contains('open') ? 'hidden' : '';
  hamburger.setAttribute('aria-expanded', hamburger.classList.contains('open'));
});

function closeMobileNav() {
  hamburger.classList.remove('open');
  mobileOverlay.classList.remove('open');
  document.body.style.overflow = '';
  hamburger.setAttribute('aria-expanded', 'false');
}

// ── Scroll Reveal ─────────────────────────────────────────────────────────

const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

// ── Workflow Animation ────────────────────────────────────────────────────

const scenarios = {
  allowed: {
    request: {
      agent_id: 'sales-agent-01',
      tool: 'salesforce',
      method: 'read_contact',
      params: {
        record_id: 'CONT-4821',
        fields: ['name', 'email', 'stage']
      }
    },
    decision: 'ALLOW',
    icon: '✅',
    severity: 'none',
    violations: [],
    message: 'Action ALLOWED — Low-risk CRM read. No violations detected.',
    logEntries: [
      { idx: '#041', hash: 'a3f8c2...9e1b', decision: 'allow', prevHash: '7d2e1a...4f8c' },
      { idx: '#042', hash: 'e7b4d1...2c6a', decision: 'allow', prevHash: 'a3f8c2...9e1b' },
      { idx: '#043', hash: '1f9e3b...8d5c', decision: 'allow', prevHash: 'e7b4d1...2c6a' },
    ]
  },
  blocked: {
    request: {
      agent_id: 'finance-agent-03',
      tool: 'stripe',
      method: 'create_transfer',
      params: {
        amount: 75000,
        currency: 'GBP',
        destination: 'acct_ext_9281'
      }
    },
    decision: 'DENY',
    icon: '🚫',
    severity: 'high',
    violations: ['high_value_transaction_unapproved'],
    message: 'Action BLOCKED — £75,000 transfer without approval. Violation: high_value_transaction_unapproved.',
    logEntries: [
      { idx: '#041', hash: 'a3f8c2...9e1b', decision: 'allow', prevHash: '7d2e1a...4f8c' },
      { idx: '#042', hash: 'e7b4d1...2c6a', decision: 'allow', prevHash: 'a3f8c2...9e1b' },
      { idx: '#043', hash: 'c4a2f8...3e7d', decision: 'deny',  prevHash: 'e7b4d1...2c6a' },
    ]
  }
};

const steps = ['step-agent', 'step-gateway', 'step-policy', 'step-decision', 'step-audit', 'step-chain'];
const arrows = ['arrow-0', 'arrow-1', 'arrow-2', 'arrow-3', 'arrow-4'];
let currentScenario = 'allowed';
let animationTimer = null;
let isAnimating = false;

// Tab switching
document.querySelectorAll('.workflow-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    if (isAnimating) return;
    document.querySelectorAll('.workflow-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    currentScenario = tab.dataset.scenario;
    runWorkflowAnimation(currentScenario);
  });
});

function resetPipeline() {
  steps.forEach(id => document.getElementById(id)?.classList.remove('active'));
  arrows.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('lit');
  });

  const decisionBox = document.getElementById('decisionBox');
  const decisionIcon = document.getElementById('decisionIcon');
  const decisionLabel = document.getElementById('decisionLabel');
  if (decisionBox) {
    decisionBox.style.borderColor = '';
    decisionBox.style.boxShadow = '';
  }
  if (decisionIcon) decisionIcon.textContent = '⏳';
  if (decisionLabel) decisionLabel.textContent = 'Decision';

  const result = document.getElementById('workflowResult');
  if (result) {
    result.classList.remove('show', 'allowed', 'blocked');
    result.textContent = '';
  }

  const log = document.getElementById('workflowLog');
  if (log) log.innerHTML = '';
}

function formatJson(obj, indent) {
  indent = indent || 0;
  const pad = '  '.repeat(indent);
  const lines = [];

  if (Array.isArray(obj)) {
    if (obj.length === 0) return '<span class="key">[</span><span class="key">]</span>';
    lines.push('[');
    obj.forEach((item, i) => {
      const comma = i < obj.length - 1 ? ',' : '';
      if (typeof item === 'string') {
        lines.push(pad + '  <span class="string">"' + item + '"</span>' + comma);
      } else {
        lines.push(pad + '  ' + formatJson(item, indent + 1) + comma);
      }
    });
    lines.push(pad + ']');
    return lines.join('\n');
  }

  if (typeof obj === 'object' && obj !== null) {
    lines.push('{');
    const keys = Object.keys(obj);
    keys.forEach((key, i) => {
      const comma = i < keys.length - 1 ? ',' : '';
      const val = obj[key];
      let valStr;
      if (typeof val === 'string') {
        valStr = '<span class="string">"' + val + '"</span>';
      } else if (typeof val === 'number') {
        valStr = '<span class="number">' + val + '</span>';
      } else if (typeof val === 'boolean') {
        valStr = '<span class="boolean">' + val + '</span>';
      } else if (Array.isArray(val) || typeof val === 'object') {
        valStr = formatJson(val, indent + 1);
      } else {
        valStr = String(val);
      }
      lines.push(pad + '  <span class="key">"' + key + '"</span>: ' + valStr + comma);
    });
    lines.push(pad + '}');
    return lines.join('\n');
  }

  return String(obj);
}

function runWorkflowAnimation(scenarioKey) {
  if (isAnimating) return;
  isAnimating = true;
  resetPipeline();

  const scenario = scenarios[scenarioKey];
  const json = document.getElementById('workflowJson');
  const detailTitle = document.getElementById('detailTitle');

  // Show request JSON
  detailTitle.textContent = 'Incoming Tool Call';
  json.innerHTML = formatJson(scenario.request);

  let stepIdx = 0;
  const stepDelay = 700;

  function animateStep() {
    if (stepIdx >= steps.length) {
      // Show log entries
      showLogEntries(scenario.logEntries);
      isAnimating = false;
      return;
    }

    const stepEl = document.getElementById(steps[stepIdx]);
    if (stepEl) stepEl.classList.add('active');

    // Light up the arrow leading to this step
    if (stepIdx > 0) {
      const arrowEl = document.getElementById(arrows[stepIdx - 1]);
      if (arrowEl) arrowEl.classList.add('lit');
    }

    // Special handling per step
    if (stepIdx === 2) {
      // Policy evaluation
      detailTitle.textContent = 'Policy Evaluation';
      json.innerHTML = formatJson({
        evaluation_mode: scenario.decision === 'ALLOW' ? 'fast' : 'enriched',
        policy_revision: 'v1.0.0-1711003200',
        violations: scenario.violations,
        severity: scenario.severity,
        decision: scenario.decision.toLowerCase()
      });
    }

    if (stepIdx === 3) {
      // Decision
      const decisionBox = document.getElementById('decisionBox');
      const decisionIcon = document.getElementById('decisionIcon');
      const decisionLabel = document.getElementById('decisionLabel');

      if (scenario.decision === 'ALLOW') {
        decisionIcon.textContent = '✅';
        decisionLabel.textContent = 'ALLOWED';
        decisionBox.style.borderColor = '#10b981';
        decisionBox.style.boxShadow = '0 0 20px rgba(16,185,129,0.15)';
      } else {
        decisionIcon.textContent = '🚫';
        decisionLabel.textContent = 'BLOCKED';
        decisionBox.style.borderColor = '#ef4444';
        decisionBox.style.boxShadow = '0 0 20px rgba(239,68,68,0.15)';
      }

      // Show result banner
      const result = document.getElementById('workflowResult');
      result.textContent = scenario.message;
      result.className = 'workflow-result ' + (scenario.decision === 'ALLOW' ? 'allowed' : 'blocked');
      setTimeout(() => result.classList.add('show'), 100);
    }

    if (stepIdx === 4) {
      detailTitle.textContent = 'Audit Record Created';
      json.innerHTML = formatJson({
        action_id: 'a7f3e2b1-...',
        agent_id: scenario.request.agent_id,
        tool: scenario.request.tool,
        method: scenario.request.method,
        decision: scenario.decision.toLowerCase(),
        record_hash: 'sha256:' + (scenario.decision === 'ALLOW' ? '1f9e3b...8d5c' : 'c4a2f8...3e7d'),
        prev_hash: 'sha256:e7b4d1...2c6a',
        chain_intact: true
      });
    }

    if (stepIdx === 5) {
      detailTitle.textContent = 'Blockchain Anchor';
      json.innerHTML = formatJson({
        anchor_type: 'merkle_root',
        merkle_root: '0x8a4f2c1e...d7b9',
        record_count: 43,
        network: 'ethereum_sepolia',
        tx_hash: '0x3e7d...a1c4',
        status: 'confirmed'
      });
    }

    stepIdx++;
    animationTimer = setTimeout(animateStep, stepDelay);
  }

  // Start animation
  setTimeout(animateStep, 200);
}

function showLogEntries(entries) {
  const log = document.getElementById('workflowLog');
  log.innerHTML = '';

  entries.forEach((entry, i) => {
    const row = document.createElement('div');
    row.className = 'workflow-log-entry';
    row.innerHTML = `
      <span class="idx">${entry.idx}</span>
      <span class="hash">${entry.hash}</span>
      <span class="decision-pill ${entry.decision}">${entry.decision.toUpperCase()}</span>
      <span class="chain-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
        ← ${entry.prevHash}
      </span>
    `;
    log.appendChild(row);
    setTimeout(() => row.classList.add('show'), 200 * (i + 1));
  });
}

// Auto-run on scroll into view
const workflowSection = document.getElementById('how-it-works');
let workflowHasRun = false;

const workflowObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting && !workflowHasRun) {
      workflowHasRun = true;
      setTimeout(() => runWorkflowAnimation('allowed'), 500);
    }
  });
}, { threshold: 0.3 });

if (workflowSection) workflowObserver.observe(workflowSection);

// ── Smooth scroll for nav links ──────────────────────────────────────────

document.querySelectorAll('a[href^="#"]').forEach(link => {
  link.addEventListener('click', (e) => {
    const href = link.getAttribute('href');
    if (href === '#' || href === '#whitepaper') return;
    const target = document.querySelector(href);
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth' });
    }
  });
});
