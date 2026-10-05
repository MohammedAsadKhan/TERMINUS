/** Synthetic Wazuh-shaped events for local console exploration. */
export const TEST_TOPICS = [
  { id: 'ssh', label: 'SSH password guessing', area: 'Identity / Scenario A', ruleId: 100101, level: 8, mitre: 'T1110', host: 'training-linux-01' },
  { id: 'application', label: 'Application exploit probe', area: 'Application & API / Scenario B concept', ruleId: 100102, level: 12, mitre: 'T1190', host: 'training-app-01' },
  { id: 'ransomware', label: 'Ransomware-like file changes', area: 'Endpoint', ruleId: 100103, level: 13, mitre: 'T1486', host: 'training-workstation-01' },
  { id: 'network', label: 'Suspicious remote access', area: 'Network', ruleId: 100104, level: 10, mitre: 'T1021', host: 'training-server-01' },
  { id: 'privilege', label: 'Unexpected admin account change', area: 'Identity', ruleId: 100105, level: 10, mitre: 'T1098', host: 'training-directory-01' },
  { id: 'exfiltration', label: 'Unusual outbound data transfer', area: 'Network / Evidence', ruleId: 100106, level: 12, mitre: 'T1041', host: 'training-app-01' },
] as const;

export type TestTopic = (typeof TEST_TOPICS)[number]['id'];

const sample = (limit: number) => Math.floor(Math.random() * limit);

export function randomTestTopic(): TestTopic {
  return TEST_TOPICS[sample(TEST_TOPICS.length)].id;
}

export function createTestAlert(topic: TestTopic) {
  const definition = TEST_TOPICS.find(item => item.id === topic)!;
  const sourceIp = `198.51.100.${1 + sample(253)}`; // RFC 5737 documentation range.
  const attemptCount = 5 + sample(45);
  const path = ['/api/search', '/login', '/admin/export'][sample(3)];
  const log: Record<TestTopic, string> = {
    ssh: `sshd: ${attemptCount} failed password attempts for test-user from ${sourceIp} port ${40000 + sample(20000)} ssh2`,
    application: `HTTP ${path}: suspicious input pattern from ${sourceIp}; blocked test request; no exploit execution observed`,
    ransomware: `File monitor: ${20 + sample(230)} synthetic files renamed to .locked in 10 seconds on ${definition.host}`,
    network: `Connection log: unexpected remote administration attempt from ${sourceIp} to ${definition.host}:22`,
    privilege: `Audit log: test-user added to administrators group on ${definition.host} after an unusual login from ${sourceIp}`,
    exfiltration: `Proxy log: ${1000000 + sample(9000000)} bytes sent from ${definition.host} to ${sourceIp}; content and intent unverified`,
  };
  return {
    id: `console-test-${crypto.randomUUID()}`,
    rule: { id: definition.ruleId, level: definition.level, description: `[SYNTHETIC] ${definition.label}`, mitre: { id: definition.mitre } },
    agent: { id: definition.host, name: definition.host },
    data: { srcip: sourceIp },
    full_log: `SYNTHETIC TEST EVENT: ${log[topic]}`,
    timestamp: new Date().toISOString(),
  };
}
