// Mock data generators for AO-SOC dashboard
// All data is deterministic at startup; System Health values jitter on poll
// to simulate live telemetry.

const NOW = () => new Date();

// ---------- INCIDENTS ----------

export const incidents = [
  {
    id: 'INC-2041',
    title: 'Possible Ransomware Activity on FIN-WIN-04',
    severity: 'CRITICAL',
    risk_score: 97,
    confidence: 94,
    status: 'ACTIVE',
    affected_assets: ['FIN-WIN-04', 'FIN-WIN-05', 'FIN-FS-01'],
    owner: 'unassigned',
    first_seen: '08:01:12',
    last_seen: '08:17:44',
    timeline: [
      { time: '08:01', label: 'User Login', detail: 'jdoe@corp from 10.4.21.18', mitre: 'T1078' },
      { time: '08:04', label: 'PowerShell', detail: 'Encoded command via WINWORD', mitre: 'T1059.001' },
      { time: '08:06', label: 'Credential Dump', detail: 'LSASS memory read (comsvcs.dll)', mitre: 'T1003.001' },
      { time: '08:09', label: 'Lateral Movement', detail: 'SMB session to FIN-WIN-05', mitre: 'T1021.002' },
      { time: '08:13', label: 'Command & Control', detail: 'Beacon to 185.220.101.7:443', mitre: 'T1071.001' },
      { time: '08:17', label: 'Exfiltration', detail: 'Shadow copy + 4.2GB upload', mitre: 'T1567' }
    ],
    evidence: [
      { id: 'EV-9001', type: 'process', src: 'FIN-WIN-04', signal: 'rundll32.exe -> comsvcs.dll miniDump', weight: 0.91 },
      { id: 'EV-9002', type: 'network', src: 'FIN-WIN-04', signal: 'TLS to known C2 ASN AS9009', weight: 0.88 },
      { id: 'EV-9003', type: 'auth',   src: 'jdoe@corp',  signal: 'Token impersonation of DOMAIN ADMIN', weight: 0.95 },
      { id: 'EV-9004', type: 'file',   src: 'FIN-FS-01',  signal: 'vssadmin delete shadows /all', weight: 0.93 }
    ],
    mitre_techniques: [
      { id: 'T1078',     tactic: 'Initial Access',       name: 'Valid Accounts' },
      { id: 'T1059.001', tactic: 'Execution',            name: 'PowerShell' },
      { id: 'T1003.001', tactic: 'Credential Access',    name: 'LSASS Memory' },
      { id: 'T1021.002', tactic: 'Lateral Movement',     name: 'SMB/Windows Admin Shares' },
      { id: 'T1071.001', tactic: 'Command and Control',  name: 'Application Layer Protocol' },
      { id: 'T1567',     tactic: 'Exfiltration',         name: 'Exfiltration to Cloud Storage' },
      { id: 'T1490',     tactic: 'Impact',               name: 'Inhibit System Recovery' }
    ],
    recommended_actions: [
      { id: 'A1', action: 'Isolate Host',           target: 'FIN-WIN-04', reason: 'Active C2 + credential theft observed', confidence: 96, impact: 'Stops ongoing exfil & lateral spread' },
      { id: 'A2', action: 'Disable Account',        target: 'jdoe@corp',  reason: 'Compromised credentials',                   confidence: 92, impact: 'Removes attacker foothold' },
      { id: 'A3', action: 'Block IP',               target: '185.220.101.7', reason: 'Known malicious C2',                    confidence: 99, impact: 'Egress cut for affected segment' },
      { id: 'A4', action: 'Open Ticket',            target: 'IR-2026-0611', reason: 'Critical incident workflow',           confidence: 100, impact: 'Triggers IR runbook' },
      { id: 'A5', action: 'Escalate Tier-2',        target: 'IR Lead',     reason: 'Active ransomware indicator',             confidence: 95, impact: 'Human-led containment' }
    ],
    ai_explanation: {
      summary: 'High-confidence credential theft activity observed on FIN-WIN-04, consistent with pre-ransomware staging.',
      bullets: [
        'Encoded PowerShell spawned by Office process',
        'LSASS memory access via comsvcs.dll miniDump',
        'Privileged token usage by jdoe@corp (DOMAIN ADMIN)',
        'SMB lateral movement to FIN-WIN-05 within 3 minutes',
        'C2 beacon matches known threat-actor ASN',
        'Shadow copy deletion indicates ransomware prep'
      ],
      likelihood: 94,
      recommendation: 'Immediate containment. Isolate host, disable account, block C2 IP, escalate to Tier-2.'
    }
  },
  {
    id: 'INC-2040',
    title: 'Brute Force Campaign against VPN Gateway',
    severity: 'HIGH',
    risk_score: 78,
    confidence: 88,
    status: 'INVESTIGATING',
    affected_assets: ['vpn-edge-01', 'vpn-edge-02'],
    owner: 'tier1-soc',
    first_seen: '07:32:00',
    last_seen: '08:12:55',
    timeline: [
      { time: '07:32', label: 'Login Spike', detail: '420 failed logins / 5 min', mitre: 'T1110' },
      { time: '07:46', label: 'Distributed', detail: '47 unique source IPs', mitre: 'T1110.003' },
      { time: '07:58', label: 'User Success', detail: '1 account compromised (asmith)', mitre: 'T1078' },
      { time: '08:12', label: 'Persistence', detail: 'MFA fatigue push spam', mitre: 'T1621' }
    ],
    evidence: [
      { id: 'EV-8810', type: 'auth',    src: 'vpn-edge-01', signal: 'Geo-impossible travel: RU -> US in 2s', weight: 0.82 },
      { id: 'EV-8811', type: 'network', src: 'vpn-edge-01', signal: 'Distributed source IPs (botnet signature)', weight: 0.78 },
      { id: 'EV-8812', type: 'auth',    src: 'asmith',      signal: 'MFA push accepted after 11 denials', weight: 0.86 }
    ],
    mitre_techniques: [
      { id: 'T1110',     tactic: 'Credential Access',  name: 'Brute Force' },
      { id: 'T1110.003', tactic: 'Credential Access',  name: 'Password Spraying' },
      { id: 'T1078',     tactic: 'Initial Access',     name: 'Valid Accounts' },
      { id: 'T1621',     tactic: 'Credential Access',  name: 'Multi-Factor Authentication Request Generation' }
    ],
    recommended_actions: [
      { id: 'A1', action: 'Disable Account', target: 'asmith', reason: 'MFA fatigue accepted', confidence: 90, impact: 'Stops active session' },
      { id: 'A2', action: 'Block IP',        target: '47 IPs (CIDR list)', reason: 'Distributed brute force', confidence: 88, impact: 'Cuts attack surface' },
      { id: 'A3', action: 'Force MFA Reset', target: 'asmith', reason: 'Possible session theft', confidence: 85, impact: 'Restores trust' }
    ],
    ai_explanation: {
      summary: 'Distributed credential brute force against VPN edge, with one account (asmith) likely compromised via MFA fatigue.',
      bullets: [
        '47 distributed source IPs — botnet signature',
        'One account accepted MFA push after 11 denials',
        'Geo-impossible travel: RU -> US in 2 seconds',
        'No data egress detected yet, but session is live'
      ],
      likelihood: 88,
      recommendation: 'Disable compromised account, force MFA reset, block source IP ranges, audit recent VPN sessions.'
    }
  },
  {
    id: 'INC-2039',
    title: 'Suspicious Cloud IAM Role Assumption',
    severity: 'MEDIUM',
    risk_score: 62,
    confidence: 71,
    status: 'OPEN',
    affected_assets: ['aws-prod-account-9921'],
    owner: 'cloud-sec',
    first_seen: '06:14:22',
    last_seen: '07:50:11',
    timeline: [
      { time: '06:14', label: 'AssumeRole',  detail: 'DevOps role from new IP',  mitre: 'T1078.004' },
      { time: '06:18', label: 'S3 Enumerate',detail: 'ListBuckets on prod-data', mitre: 'T1538' },
      { time: '06:42', label: 'S3 Get',      detail: 'Download 12 objects',       mitre: 'T1530' }
    ],
    evidence: [
      { id: 'EV-7701', type: 'cloud', src: 'aws-prod', signal: 'AssumeRole from new geolocation (BR)', weight: 0.74 },
      { id: 'EV-7702', type: 'cloud', src: 'aws-prod', signal: 'GetObject on 12 sensitive buckets', weight: 0.69 }
    ],
    mitre_techniques: [
      { id: 'T1078.004', tactic: 'Initial Access', name: 'Cloud Accounts' },
      { id: 'T1538',     tactic: 'Discovery',      name: 'Cloud Service Dashboard' },
      { id: 'T1530',     tactic: 'Collection',     name: 'Data from Cloud Storage' }
    ],
    recommended_actions: [
      { id: 'A1', action: 'Revoke Role',         target: 'DevOps-Role', reason: 'Anomalous geo',     confidence: 80, impact: 'Stops access' },
      { id: 'A2', action: 'Open Ticket',         target: 'Cloud IR',    reason: 'Possible data exposure', confidence: 75, impact: 'Triggers review' }
    ],
    ai_explanation: {
      summary: 'Service role assumed from atypical geography, with subsequent data access patterns that suggest reconnaissance and exfiltration.',
      bullets: [
        'New geolocation (BR) for DevOps role',
        'ListBuckets followed by GetObject on sensitive prefixes',
        'No prior baseline for this actor on the role'
      ],
      likelihood: 71,
      recommendation: 'Revoke session, rotate role credentials, audit all objects accessed, contact role owner for verification.'
    }
  },
  {
    id: 'INC-2038',
    title: 'Outdated TLS Handshake on External Endpoint',
    severity: 'LOW',
    risk_score: 31,
    confidence: 64,
    status: 'MONITORING',
    affected_assets: ['api-gateway-public-01'],
    owner: 'platform-eng',
    first_seen: '05:02:00',
    last_seen: '06:00:00',
    timeline: [
      { time: '05:02', label: 'Handshake', detail: 'TLS 1.0 from legacy client', mitre: 'T1573' }
    ],
    evidence: [
      { id: 'EV-6601', type: 'network', src: 'api-gateway-public-01', signal: 'TLS 1.0 from partner VPN', weight: 0.64 }
    ],
    mitre_techniques: [
      { id: 'T1573', tactic: 'Command and Control', name: 'Encrypted Channel' }
    ],
    recommended_actions: [
      { id: 'A1', action: 'Open Ticket', target: 'Platform', reason: 'Compliance gap', confidence: 70, impact: 'Tracks remediation' }
    ],
    ai_explanation: {
      summary: 'Legacy TLS 1.0 traffic observed from a known partner. Not malicious, but violates policy.',
      bullets: [
        'TLS 1.0 from a known partner VPN endpoint',
        'No payload anomalies detected'
      ],
      likelihood: 64,
      recommendation: 'Open a tracking ticket; coordinate with partner to upgrade to TLS 1.2+.'
    }
  }
];

// ---------- ENTITIES ----------

export const highRiskUsers = [
  { id: 'U1', type: 'user', name: 'jdoe@corp',  risk_score: 97, confidence: 94, reason: 'Token impersonation + LSASS dump', last_seen: '08:17' },
  { id: 'U2', type: 'user', name: 'asmith@corp',risk_score: 88, confidence: 86, reason: 'MFA fatigue accepted',             last_seen: '08:12' },
  { id: 'U3', type: 'user', name: 'klee@corp',  risk_score: 71, confidence: 70, reason: 'After-hours admin activity',       last_seen: '02:41' },
  { id: 'U4', type: 'user', name: 'svc_bak@corp',risk_score: 64, confidence: 68, reason: 'Unusual data volume access',      last_seen: '04:08' },
  { id: 'U5', type: 'user', name: 'rmohan@corp', risk_score: 58, confidence: 62, reason: 'Geo anomaly from new device',     last_seen: '07:55' }
];

export const highRiskHosts = [
  { id: 'H1', type: 'host', name: 'FIN-WIN-04',     risk_score: 97, confidence: 94, reason: 'Active C2 + credential theft', last_seen: '08:17' },
  { id: 'H2', type: 'host', name: 'FIN-WIN-05',     risk_score: 81, confidence: 83, reason: 'Lateral movement target',     last_seen: '08:11' },
  { id: 'H3', type: 'host', name: 'vpn-edge-01',    risk_score: 78, confidence: 88, reason: 'Brute force ingress',         last_seen: '08:13' },
  { id: 'H4', type: 'host', name: 'dev-laptop-219', risk_score: 66, confidence: 71, reason: 'Unsigned driver loaded',      last_seen: '07:02' },
  { id: 'H5', type: 'host', name: 'mail-relay-02',  risk_score: 52, confidence: 65, reason: 'Spam outbound burst',          last_seen: '06:48' }
];

export const highRiskIps = [
  { id: 'I1', type: 'ip', name: '185.220.101.7', risk_score: 99, confidence: 99, reason: 'Known C2 ASN AS9009',          last_seen: '08:13' },
  { id: 'I2', type: 'ip', name: '45.155.205.211',risk_score: 92, confidence: 94, reason: 'Brute force source',           last_seen: '08:11' },
  { id: 'I3', type: 'ip', name: '193.142.146.4', risk_score: 84, confidence: 81, reason: 'Credential stuffing pool',     last_seen: '08:09' },
  { id: 'I4', type: 'ip', name: '91.204.44.12',  risk_score: 72, confidence: 70, reason: 'Tor exit node',                last_seen: '07:58' },
  { id: 'I5', type: 'ip', name: '177.105.83.40', risk_score: 66, confidence: 67, reason: 'Atypical geo for service role',last_seen: '06:14' }
];

// ---------- MITRE TACTICS ----------

export const mitreTactics = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

// Map incidents to tactic intensity (count of techniques * severity weight)
export const mitreHeatmap = (() => {
  const weight = { CRITICAL: 5, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const counts = Object.fromEntries(mitreTactics.map(t => [t, 0]));
  for (const inc of incidents) {
    for (const tech of inc.mitre_techniques || []) {
      const t = tech.tactic;
      if (t in counts) counts[t] += (weight[inc.severity] || 1);
    }
  }
  // Normalize to 0..1
  const max = Math.max(...Object.values(counts), 1);
  return mitreTactics.map(tactic => ({
    tactic,
    intensity: counts[tactic] / max,
    techniques: incidents.flatMap(i => (i.mitre_techniques || []).filter(t => t.tactic === tactic))
                          .map(t => t.id)
                          .filter((v, i, a) => a.indexOf(v) === i)
  }));
})();

// ---------- EXECUTIVE SUMMARY ----------

export const summary = {
  overall_risk_score: 87,
  overall_risk_label: 'ELEVATED',
  critical_incidents: 1,
  high_incidents: 1,
  medium_incidents: 1,
  low_incidents: 1,
  ai_confidence_avg: 84,
  mttd_minutes: 6,   // Mean Time To Detect
  mttr_minutes: 22,  // Mean Time To Respond
  total_correlated_incidents: 4,
  automation_success_rate: 91
};

// ---------- SYSTEM HEALTH ----------
// Live, jitters each poll

export const baseHealth = {
  splunk: { status: 'ONLINE', events_per_sec: 12450, correlations_per_min: 38, queue_depth: 12 },
  broker: { status: 'ONLINE', queue_depth: 4,    correlations_per_min: 41, uptime_hours: 312 },
  llm:    { status: 'ONLINE', model: 'qwen2.5:14b-instruct-q5_K_M', inference_latency_ms: 240, tokens_per_sec: 38 },
  gpu:    { status: 'ONLINE', utilization_pct: 62, vram_used_gb: 9.4, vram_total_gb: 16, temperature_c: 68 },
  soar:   { status: 'ONLINE', playbooks_running: 3, playbooks_queued: 1, success_rate: 91 }
};

export function jitterHealth() {
  const j = (v, pct) => Math.max(0, v + (Math.random() * 2 - 1) * v * pct);
  return {
    splunk: { ...baseHealth.splunk,
              events_per_sec: Math.round(j(baseHealth.splunk.events_per_sec, 0.05)),
              correlations_per_min: Math.round(j(baseHealth.splunk.correlations_per_min, 0.10)),
              queue_depth: Math.max(0, Math.round(j(baseHealth.splunk.queue_depth, 0.30))) },
    broker: { ...baseHealth.broker,
              queue_depth: Math.max(0, Math.round(j(baseHealth.broker.queue_depth, 0.30))),
              correlations_per_min: Math.round(j(baseHealth.broker.correlations_per_min, 0.10)) },
    llm:    { ...baseHealth.llm,
              inference_latency_ms: Math.round(j(baseHealth.llm.inference_latency_ms, 0.15)),
              tokens_per_sec: Math.round(j(baseHealth.llm.tokens_per_sec, 0.10)) },
    gpu:    { ...baseHealth.gpu,
              utilization_pct: Math.min(100, Math.round(j(baseHealth.gpu.utilization_pct, 0.10))),
              vram_used_gb:    Number(j(baseHealth.gpu.vram_used_gb, 0.05).toFixed(2)),
              temperature_c:   Math.round(j(baseHealth.gpu.temperature_c, 0.04)) },
    soar:   { ...baseHealth.soar,
              playbooks_running: Math.max(0, Math.round(j(baseHealth.soar.playbooks_running, 0.20))),
              playbooks_queued:  Math.max(0, Math.round(j(baseHealth.soar.playbooks_queued, 0.40))) },
    generated_at: NOW().toISOString()
  };
}
