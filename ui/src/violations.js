/**
 * Violation Code → Plain English Mapping
 * Single source of truth for how violations are displayed in the dashboard.
 */

const VIOLATIONS = {
  high_value_transaction_unapproved: {
    title: 'Transaction over £5,000 requires human approval',
    description: 'This transaction exceeds the automatic approval threshold and needs manual sign-off.',
    severity: 'high',
    icon: '⛔',
  },
  competitor_contact_attempt: {
    title: 'Email to a restricted competitor domain',
    description: 'The agent attempted to contact a domain on the restricted competitor list.',
    severity: 'critical',
    icon: '🚫',
  },
  gdpr_pii_residency_violation: {
    title: 'Personal data cannot leave the EU',
    description: 'This action would transfer personally identifiable information outside the permitted jurisdiction.',
    severity: 'critical',
    icon: '🛡',
  },
  anomaly_score_threshold_exceeded: {
    title: 'Agent behaviour score exceeds risk threshold',
    description: 'The agent\'s cumulative anomaly score has crossed the safety threshold.',
    severity: 'high',
    icon: '📊',
  },
  high_value_out_of_hours: {
    title: 'High-value action outside permitted business hours',
    description: 'Transactions above £1,000 are restricted outside standard operating hours.',
    severity: 'medium',
    icon: '🕐',
  },
  repeated_violations_today: {
    title: 'Agent has exceeded daily violation limit',
    description: 'This agent has triggered 3 or more policy violations in the past 24 hours.',
    severity: 'high',
    icon: '⚠',
  },
  high_value_frequency_limit_exceeded: {
    title: 'Too many high-value transactions today',
    description: 'The agent has processed too many high-value transactions in a short period.',
    severity: 'high',
    icon: '📈',
  },
  no_credential_registered_for_tool: {
    title: 'No credential registered for this tool',
    description: 'The credential vault has no API key registered for this tool. Register one before the agent can execute.',
    severity: 'high',
    icon: '🔑',
  },
};

/**
 * Translate a violation code to a human-readable object.
 * Returns a default if the code is unknown.
 */
export function getViolation(code) {
  return VIOLATIONS[code] || {
    title: code.replace(/_/g, ' '),
    description: 'Policy violation detected.',
    severity: 'medium',
    icon: '⚠',
  };
}

/**
 * Get the CSS colour variable for a severity level.
 */
export function severityColor(severity) {
  switch (severity) {
    case 'critical': return 'var(--accent-red)';
    case 'high': return 'var(--accent-amber)';
    case 'medium': return 'var(--accent-amber)';
    default: return 'var(--text-muted)';
  }
}

/**
 * Get the pill class for a severity level.
 */
export function severityPillClass(severity) {
  switch (severity) {
    case 'critical': return 'pill-severity-critical';
    case 'high': return 'pill-severity-high';
    case 'medium': return 'pill-severity-medium';
    default: return 'pill-direct';
  }
}

export default VIOLATIONS;
