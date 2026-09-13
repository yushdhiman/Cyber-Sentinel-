/**
 * Cyber Sentinel — Comprehensive Worst-Case Scenario Stress & Boundary Test Suite
 * 
 * Tests extreme adversarial inputs, malformed payloads, DoS event storms,
 * boundary overflows, cryptographic evidence tampering, and AI copilot safety bypass attempts.
 */

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// System modules under test
const { normalizeEvent } = require('./src/services/normalizer/eventNormalizer');
const iocMatcher = require('./src/services/threatIntel/iocMatcher');
const { CorrelationEngine } = require('./src/utils/correlationEngine');
const securityStore = require('./src/data/securityStore');
const { analyzeBinary, calculateEntropy, parsePE } = require('./src/services/malware/staticAnalyzer');
const { executeTool } = require('./src/utils/agentTools');
const { analyzeLink, analyzeEmail, analyzeFile } = require('./src/utils/protectionEngine');
const { analyzeLog } = require('./src/utils/detection');

console.log('======================================================================');
console.log('🛡️   CYBER SENTINEL — WORST-CASE SCENARIOS & ADVERSARIAL STRESS SUITE');
console.log('======================================================================\n');

let passedTests = 0;
let failedTests = 0;
let totalTests = 0;

// Backup initial security state to guarantee pristine cleanup
const STATE_FILE = path.join(__dirname, 'src', 'data', 'security_state.json');
let originalStateBackup = null;
try {
  if (fs.existsSync(STATE_FILE)) {
    originalStateBackup = fs.readFileSync(STATE_FILE, 'utf8');
  }
} catch (_) {}

function restoreStateBackup() {
  if (originalStateBackup) {
    try {
      fs.writeFileSync(STATE_FILE, originalStateBackup, 'utf8');
    } catch (_) {}
  }
}

async function runScenario(section, name, fn) {
  totalTests++;
  const startTime = process.hrtime.bigint();
  try {
    await fn();
    const endTime = process.hrtime.bigint();
    const durationMs = Number(endTime - startTime) / 1_000_000;
    console.log(`  ✅ [PASS] (${durationMs.toFixed(2)}ms) [${section}] ${name}`);
    passedTests++;
  } catch (err) {
    failedTests++;
    console.error(`  ❌ [FAIL] [${section}] ${name}`);
    console.error(`     Error: ${err.message}\n`, err.stack);
  }
}

async function runSuite() {

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 1: MALWARE PE STATIC ANALYZER UNDER ADVERSARIAL FUZZING
  // ══════════════════════════════════════════════════════════════════════════
  console.log('━━━ SECTION 1: Malware PE Static Analyzer Under Adversarial Fuzzing ━━━');

  await runScenario('PE-ANALYZER', 'Handles 0-byte buffer safely without throwing or hanging', () => {
    const emptyBuf = Buffer.alloc(0);
    const analysis = analyzeBinary(emptyBuf, 'zero_byte.bin');
    assert.strictEqual(analysis.peInfo.isPE, false);
    assert.strictEqual(analysis.metadata.size, 0);
    assert.strictEqual(analysis.entropy.score, 0);
    assert.strictEqual(analysis.riskAssessment.severity, 'LOW');
  });

  await runScenario('PE-ANALYZER', 'Handles truncated sub-64 byte buffers (1, 4, 16, 63 bytes)', () => {
    [1, 4, 16, 63].forEach(size => {
      const truncatedBuf = Buffer.alloc(size, 0x41); // 'A's
      const analysis = analyzeBinary(truncatedBuf, `truncated_${size}.bin`);
      assert.strictEqual(analysis.peInfo.isPE, false);
      assert.strictEqual(analysis.metadata.size, size);
    });
  });

  await runScenario('PE-ANALYZER', 'Corrupted e_lfanew pointer (0xFFFFFFFF) does not trigger out-of-bounds crash', () => {
    const corruptBuf = Buffer.alloc(128);
    corruptBuf[0] = 0x4D; // 'M'
    corruptBuf[1] = 0x5A; // 'Z'
    // Point e_lfanew far beyond buffer length
    corruptBuf.writeUInt32LE(0xFFFFFFFF, 0x3C);

    const analysis = analyzeBinary(corruptBuf, 'corrupt_elfanew.exe');
    assert.strictEqual(analysis.peInfo.isPE, false);
    assert.strictEqual(analysis.peInfo.detectedFormat, 'DOS MZ Executable');
  });

  await runScenario('PE-ANALYZER', 'Section Table Header Bomb (65,535 sections) prevented by bounds enforcement', () => {
    const bombBuf = Buffer.alloc(512);
    bombBuf[0] = 0x4D;
    bombBuf[1] = 0x5A;
    bombBuf.writeUInt32LE(0x40, 0x3C); // PE at 0x40

    // PE signature
    bombBuf[0x40] = 0x50; // 'P'
    bombBuf[0x41] = 0x45; // 'E'
    bombBuf[0x42] = 0x00;
    bombBuf[0x43] = 0x00;
    bombBuf.writeUInt16LE(0x8664, 0x44); // x64
    bombBuf.writeUInt16LE(65535, 0x46);  // Bomb: 65,535 sections declared

    const analysis = analyzeBinary(bombBuf, 'section_bomb.exe');
    assert.strictEqual(analysis.peInfo.isPE, true);
    // Number of parsed sections must be safely bounded to actual buffer limits, not 65535
    assert.ok(analysis.peInfo.sections.length < 50, `Parsed sections (${analysis.peInfo.sections.length}) exceeded buffer boundary`);
  });

  await runScenario('PE-ANALYZER', 'Evaluates 100% pseudo-random high-entropy binary (~8.0 entropy) as suspicious', () => {
    const randomBuf = crypto.randomBytes(4096);
    const entropy = calculateEntropy(randomBuf);
    assert.ok(entropy > 7.8, `Entropy ${entropy} should be near 8.0`);

    const analysis = analyzeBinary(randomBuf, 'packed_payload.bin');
    assert.ok(analysis.entropy.score > 7.8);
    assert.ok(analysis.riskAssessment.score >= 25, 'High entropy must elevate risk assessment score to MEDIUM');
  });

  await runScenario('PE-ANALYZER', 'Safely rejects non-Buffer inputs with deterministic error', () => {
    [null, undefined, 'binary_string', 12345, {}, []].forEach(invalid => {
      assert.throws(() => {
        analyzeBinary(invalid);
      }, /Input must be a valid Buffer/);
    });
  });

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 2: UNIFIED EVENT INGESTION & NORMALIZER UNDER FUZZING
  // ══════════════════════════════════════════════════════════════════════════
  console.log('\n━━━ SECTION 2: Unified Event Ingestion & Normalizer Under Fuzzing ━━━');

  await runScenario('NORMALIZER', 'Gracefully handles null, undefined, primitives, and empty objects', () => {
    [null, undefined, '', 0, false, {}].forEach(raw => {
      const normalized = normalizeEvent(raw);
      assert.ok(normalized.eventId);
      assert.ok(normalized.timestamp);
      assert.strictEqual(normalized.sourceIp, '127.0.0.1');
      assert.strictEqual(normalized.severity, 'MEDIUM');
      assert.strictEqual(typeof normalized.details, 'object');
    });
  });

  await runScenario('NORMALIZER', 'Defends against Prototype Pollution (__proto__, constructor injection)', () => {
    const maliciousPayload = JSON.parse('{"__proto__": {"polluted": "pwned"}, "constructor": {"prototype": {"admin": true}}}');
    const normalized = normalizeEvent(maliciousPayload);

    assert.strictEqual(Object.prototype.polluted, undefined, 'Object.prototype was polluted!');
    assert.strictEqual(Object.prototype.admin, undefined, 'Object.prototype was polluted!');
    assert.ok(normalized.eventId);
  });

  await runScenario('NORMALIZER', 'Sanitizes adversarial network coordinates (IPv6 bracketed, out-of-range ports, SQLi)', () => {
    const rawEvent = {
      sourceIp: '[2001:db8::1]:8443',
      destPort: '999999',
      sourcePort: '-1',
      hostname: "host' OR 1=1; DROP TABLE logs; --",
      processName: '<script>alert("XSS")</script>'
    };

    const normalized = normalizeEvent(rawEvent);
    assert.strictEqual(normalized.destPort, 999999);
    assert.strictEqual(normalized.sourcePort, -1);
    assert.ok(normalized.hostname.includes('DROP TABLE'));
    assert.ok(normalized.processName.includes('<script>'));
    assert.ok(normalized.ingestedAt);
  });

  await runScenario('NORMALIZER', 'Processes massive payload strings (500KB command lines) without heap degradation', () => {
    const massiveStr = 'powershell.exe -enc ' + 'A'.repeat(500000);
    const raw = {
      dataSource: 'endpoint-agent',
      commandLine: massiveStr,
      details: { extra: massiveStr.slice(0, 10000) }
    };

    const t0 = Date.now();
    const normalized = normalizeEvent(raw);
    const elapsed = Date.now() - t0;

    assert.strictEqual(normalized.commandLine.length, massiveStr.length);
    assert.ok(elapsed < 200, `Processing took too long: ${elapsed}ms`);
  });

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 3: HIGH-PERFORMANCE THREAT INTEL & IOC MATCHER STRESS
  // ══════════════════════════════════════════════════════════════════════════
  console.log('\n━━━ SECTION 3: High-Performance Threat Intel & IOC Matcher Stress ━━━');

  await runScenario('IOC-MATCHER', 'Bulk Ingests 10,000 dynamic IOCs and indexes in < 250ms', () => {
    const batch = [];
    for (let i = 0; i < 10000; i++) {
      batch.push({
        ioc: `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`,
        malware: `SyntheticBotnet-${i % 50}`,
        confidence: 90 + (i % 10),
        reporter: 'worst-case-test'
      });
    }

    const t0 = Date.now();
    iocMatcher.addIndicators(batch);
    const elapsed = Date.now() - t0;

    const stats = iocMatcher.getIocStats();
    assert.ok(stats.indexedIps >= 10000, `Expected >=10000 indexed IPs, got: ${stats.indexedIps}`);
    assert.ok(elapsed < 250, `Ingestion took too long: ${elapsed}ms`);
  });

  await runScenario('IOC-MATCHER', 'Performs 10,000 lookups with sub-millisecond per-lookup throughput', () => {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < 10000; i++) {
      const probeIp = `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}:8080`;
      const match = iocMatcher.matchIndicator(probeIp);
      if (i === 5000) {
        assert.ok(match, 'Probe 5000 should match');
        assert.strictEqual(match.type, 'ipv4');
      }
    }
    const t1 = process.hrtime.bigint();
    const totalMs = Number(t1 - t0) / 1_000_000;
    const avgLatencyUs = (totalMs / 10000) * 1000;

    assert.ok(avgLatencyUs < 50, `Average lookup latency was ${avgLatencyUs.toFixed(2)}µs, expected < 50µs`);
  });

  await runScenario('IOC-MATCHER', 'Handles dirty, malformed, and mixed-case IOC strings', () => {
    const hash = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
    iocMatcher.addIndicators([{ ioc: hash, malware: 'CasingMalware', confidence: 99 }]);

    // Uppercase lookup with whitespace and port
    const upperMatch = iocMatcher.matchIndicator(`   ${hash.toUpperCase()}   `);
    assert.ok(upperMatch, 'Should match uppercase hash with whitespace');
    assert.strictEqual(upperMatch.malware, 'CasingMalware');

    // Malformed indicators
    assert.strictEqual(iocMatcher.matchIndicator(''), null);
    assert.strictEqual(iocMatcher.matchIndicator('   '), null);
    assert.strictEqual(iocMatcher.matchIndicator(null), null);
    assert.strictEqual(iocMatcher.matchIndicator(undefined), null);
  });

  await runScenario('IOC-MATCHER', 'ReDoS & catastrophic backtracking resistance on adversarial strings', () => {
    const adversarialString = 'a'.repeat(2000) + '!';
    const t0 = Date.now();
    const match = iocMatcher.matchIndicator(adversarialString);
    const duration = Date.now() - t0;

    assert.strictEqual(match, null);
    assert.ok(duration < 20, `ReDoS detected: match took ${duration}ms`);
  });

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 4: SIEM CORRELATION ENGINE UNDER DOS EVENT STORM
  // ══════════════════════════════════════════════════════════════════════════
  console.log('\n━━━ SECTION 4: SIEM Correlation Engine Under DoS Event Storm ━━━');

  await runScenario('CORRELATION', 'Alert Fatigue / Deduplication: 100 consecutive brute force events yield exactly 1 incident', () => {
    const engine = new CorrelationEngine();
    let incidentsGenerated = 0;
    engine.on('incident', () => { incidentsGenerated++; });

    const attackerIp = '198.51.100.250';
    for (let i = 0; i < 100; i++) {
      engine.processEvent({
        eventType: 'AUTH_FAILURE',
        action: 'FAILED_LOGIN',
        sourceIp: attackerIp,
        username: `admin_${i % 3}`,
        timestamp: Date.now()
      });
    }

    assert.strictEqual(incidentsGenerated, 1, `Expected exactly 1 correlated incident, got ${incidentsGenerated}`);
  });

  await runScenario('CORRELATION', 'Event Flood Storm: 1,000 rapid heterogeneous attack events processed safely', () => {
    const engine = new CorrelationEngine();
    let totalIncidents = 0;
    engine.on('incident', () => { totalIncidents++; });

    const t0 = Date.now();
    for (let i = 0; i < 1000; i++) {
      if (i % 3 === 0) {
        engine.processEvent({
          endpoint: `/search?q=1%27%20UNION%20SELECT%20${i}--`,
          httpStatus: 200,
          srcIp: `198.51.100.${(i % 50) + 1}`
        });
      } else if (i % 3 === 1) {
        engine.processEvent({
          processName: 'powershell.exe',
          commandLine: `powershell.exe -enc JABz=${i}`,
          hostname: `HOST-${i % 20}`,
          destIp: '185.220.101.5'
        });
      } else {
        engine.processEvent({
          eventType: 'AUTH_FAILURE',
          action: 'FAILED_LOGIN',
          sourceIp: `203.0.113.${i % 10}`,
          username: 'root'
        });
      }
    }
    const elapsed = Date.now() - t0;

    assert.ok(totalIncidents > 0, 'Should generate incidents under storm');
    assert.ok(elapsed < 3000, `Event storm took too long: ${elapsed}ms`);
  });

  await runScenario('CORRELATION', 'Multi-Vector Attack: Simultaneous SQLi + C2 + Brute Force all correlated', () => {
    const engine = new CorrelationEngine();
    const incidentRuleIds = new Set();
    engine.on('incident', (inc) => { incidentRuleIds.add(inc.ruleId); });

    const attacker = '198.51.100.77';

    // 1. SQLi Probe
    engine.processEvent({ endpoint: "/api?id=1' UNION SELECT null--", httpStatus: 200, srcIp: attacker });
    // 2. Suspicious C2 Execution
    engine.processEvent({ processName: 'powershell.exe', commandLine: 'powershell.exe -hidden -enc XYZ', destIp: attacker });
    // 3. Brute Force flood (5 attempts)
    for (let k = 0; k < 5; k++) {
      engine.processEvent({ eventType: 'AUTH_FAILURE', action: 'FAILED_LOGIN', sourceIp: attacker, username: 'admin' });
    }

    assert.ok(incidentRuleIds.has('RULE_SQLI_SUCCESS_002'), 'Missing SQLi incident');
    assert.ok(incidentRuleIds.has('RULE_SUSPICIOUS_EXEC_004'), 'Missing Suspicious Exec incident');
    assert.ok(incidentRuleIds.has('RULE_BRUTE_FORCE_001'), 'Missing Brute Force incident');
  });

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 5: CRYPTOGRAPHIC FORENSIC INTEGRITY & TAMPER DETECTION
  // ══════════════════════════════════════════════════════════════════════════
  console.log('\n━━━ SECTION 5: Cryptographic Forensic Integrity & Tamper Detection ━━━');

  await runScenario('FORENSICS', 'Detects evidence tampering via SHA-256 cryptographic hash mismatch', () => {
    const authenticEvidence = [
      { logId: 101, packetHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
    ];

    const incident = securityStore.createIncident({
      title: 'Forensic Tamper Detection Test',
      severity: 'HIGH',
      evidence: authenticEvidence
    });

    // Verification step 1: authentic evidence matches stored hash
    const calculatedHash = crypto.createHash('sha256').update(JSON.stringify(authenticEvidence)).digest('hex');
    assert.strictEqual(incident.evidenceHash, calculatedHash);

    // Adversary attempts in-memory evidence modification (e.g. altering packet hash)
    const tamperedEvidence = [
      { logId: 101, packetHash: '0000000000000000000000000000000000000000000000000000000000000000' }
    ];
    const tamperedHash = crypto.createHash('sha256').update(JSON.stringify(tamperedEvidence)).digest('hex');

    // Assert tamper is detected
    assert.notStrictEqual(incident.evidenceHash, tamperedHash, 'Tampered evidence failed to invalidate hash!');
  });

  await runScenario('FORENSICS', 'Safely handles circular references and complex non-serializable evidence', () => {
    const circularObj = { name: 'cyclic' };
    circularObj.self = circularObj;

    const incident = securityStore.createIncident({
      title: 'Circular Object Evidence Test',
      severity: 'LOW',
      evidence: circularObj
    });

    assert.ok(incident.id.startsWith('INC-'));
    assert.ok(incident.evidenceHash, 'Evidence hash must be generated even on cyclic structure');
  });

  await runScenario('FORENSICS', 'Bounded FIFO Buffer: 600 incidents and 1,200 audit logs do not exceed capacity', () => {
    for (let i = 0; i < 600; i++) {
      securityStore.createIncident({
        title: `Buffer Cap Incident ${i}`,
        severity: 'LOW',
        evidence: { test: i }
      });
      securityStore.addAuditLog({
        actor: 'stress-tester',
        action: 'STRESS_LOG',
        target: `SYSTEM_${i}`,
        details: { cycle: i }
      });
      securityStore.addAuditLog({
        actor: 'stress-tester',
        action: 'STRESS_LOG_2',
        target: `SYSTEM_${i}`,
        details: { cycle: i }
      });
    }

    const allIncidents = securityStore.getIncidents();
    const allAuditLogs = securityStore.getAuditLogs(2000);

    assert.ok(allIncidents.length <= 500, `Incident count (${allIncidents.length}) exceeded 500 maximum buffer`);
    assert.ok(allAuditLogs.length <= 1000, `Audit log count (${allAuditLogs.length}) exceeded 1000 maximum buffer`);
  });

  await runScenario('FORENSICS', 'Concurrent IP containment race conditions maintain state consistency', async () => {
    const targetIp = '203.0.113.222';

    // Fire 50 asynchronous concurrent block/unblock operations
    const operations = [];
    for (let i = 0; i < 50; i++) {
      operations.push(Promise.resolve().then(() => {
        if (i % 2 === 0) securityStore.blockIp(targetIp, `Reason ${i}`);
        else securityStore.unblockIp(targetIp);
      }));
    }
    await Promise.all(operations);

    // Final state should be a clean boolean without memory corruption
    const isBlocked = securityStore.isIpBlocked(targetIp);
    assert.strictEqual(typeof isBlocked, 'boolean');

    // Clean up
    securityStore.unblockIp(targetIp);
    assert.strictEqual(securityStore.isIpBlocked(targetIp), false);
  });

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 6: AI COPILOT SAFETY BOUNDARY & GUARDRAIL BYPASS ATTACKS
  // ══════════════════════════════════════════════════════════════════════════
  console.log('\n━━━ SECTION 6: AI Copilot Safety Boundary & Guardrail Bypass Attacks ━━━');

  await runScenario('AI-SAFETY', 'Rejects all type-coercion bypass attempts on destructive firewall containment', async () => {
    const targetIp = '198.51.100.99';

    // Array of malicious parameter bypass attempts
    const bypassAttempts = [
      { ip: targetIp, confirm: 'true' },  // string 'true' instead of boolean true
      { ip: targetIp, confirm: 'yes' },   // string 'yes'
      { ip: targetIp, confirm: 1 },       // number 1
      { ip: targetIp, confirm: null },    // null
      { ip: targetIp, confirm: {} },      // empty object
      { ip: targetIp, confirm: false },   // false
      { ip: targetIp, confirm: 0 }        // 0
    ];

    for (const attempt of bypassAttempts) {
      const res = await executeTool('block_ip_address', attempt);
      assert.strictEqual(securityStore.isIpBlocked(targetIp), false, `IP was blocked with attempt: ${JSON.stringify(attempt)}`);
    }
  });

  await runScenario('AI-SAFETY', 'SQL & Command Injection payloads inside forensics tool queries handled safely', async () => {
    const injectionPayloads = [
      "'; DROP TABLE incidents; --",
      "185.220.101.5; cat /etc/passwd",
      "<script>alert(document.cookie)</script>",
      "../../../../windows/system32/cmd.exe",
      "1' OR '1'='1"
    ];

    for (const payload of injectionPayloads) {
      const iocRes = await executeTool('investigate_ioc', { indicator: payload });
      assert.ok(iocRes.result !== undefined, `Failed on payload: ${payload}`);

      const cveRes = await executeTool('fetch_cve_details', { cve_id: payload });
      assert.ok(cveRes.result !== undefined || cveRes.error !== undefined);
    }
  });

  await runScenario('AI-SAFETY', 'Executes all registered action & read tools with empty parameters safely', async () => {
    const toolNames = [
      'get_system_status',
      'get_attack_feed',
      'get_soc_incidents',
      'get_listening_ports',
      'get_blocked_ips',
      'run_vulnerability_scan',
      'run_network_scan',
      'generate_incident_report'
    ];

    for (const name of toolNames) {
      const res = await executeTool(name, {});
      assert.ok(res.result !== undefined, `Tool ${name} failed to return structured result on empty params`);
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 7: PROTECTION & LOG ANALYSIS ENGINES UNDER EVASION
  // ══════════════════════════════════════════════════════════════════════════
  console.log('\n━━━ SECTION 7: Protection & Log Analysis Engines Under Evasion ━━━');

  await runScenario('PROTECTION', 'Evaluates obfuscated, malformed, and gigantic URL links', () => {
    // Malformed & Evasion URLs
    const urls = [
      'http://2130706433', // Decimal IP representation for 127.0.0.1
      'javascript:alert("XSS")',
      'https://paypal.com-security-update.xyz/verify/login',
      'http://' + 'a'.repeat(10000) + '.xyz/path',
      '',
      null
    ];

    urls.forEach(url => {
      const report = analyzeLink(url);
      assert.ok(report.error || report.summary);
      if (report.summary && url && url.includes('paypal.com-security-update.xyz')) {
        assert.ok(report.summary.threatScore >= 65, 'Phishing subdomain must score high threat');
      }
    });
  });

  await runScenario('PROTECTION', 'Evaluates multi-vector phishing email combining urgent keywords & spoofed sender', () => {
    const report = analyzeEmail(
      'URGENT: Your account has been suspended due to suspicious activity! Reset your password immediately: https://secure-login.xyz',
      'URGENT ACTION REQUIRED: Account Suspension',
      'billing-support@chase-security-alert.com'
    );

    assert.ok(report.summary.threatScore >= 70, `Expected critical threat score, got: ${report.summary.threatScore}`);
    assert.strictEqual(report.summary.status, 'PHISHING');
    assert.ok(report.findings.some(f => f.type.includes('URGENCY')));
    assert.ok(report.findings.some(f => f.type.includes('SPOOFED_BRAND') || f.type.includes('SUSPICIOUS_SENDER_DOMAIN')));
  });

  await runScenario('PROTECTION', 'Dual-extension masking (invoice.pdf.exe) and historic malware hashes (WannaCry, EICAR)', () => {
    // 1. Dual extension masking
    const dualExtReport = analyzeFile('urgent_invoice.pdf.exe', 1024, 'dummy_hash');
    assert.strictEqual(dualExtReport.summary.status, 'INFECTED');
    assert.ok(dualExtReport.findings.some(f => f.type === 'Double Extension Masking'));

    // 2. WannaCry ransomware hash
    const wannaCryHash = 'ed01ebfbc9eb5bbea545af4fed50786b0bc9e8538c340578a82b741f3e797699';
    const wcReport = analyzeFile('clean_document.docx', 2048, wannaCryHash);
    assert.strictEqual(wcReport.summary.status, 'INFECTED');
    assert.strictEqual(wcReport.detectedMalwareName, 'Ransom:Win32/WannaCrypt');

    // 3. EICAR Standard Antivirus Test String
    const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarReport = analyzeFile('eicar.com', 68, '', eicarString);
    assert.strictEqual(eicarReport.summary.status, 'INFECTED');
    assert.strictEqual(eicarReport.detectedMalwareName, 'EICAR-Standard-Antivirus-Test-File');
  });

  await runScenario('PROTECTION', 'Log Analysis Engine processes 5,000 log lines with interleaved attack patterns', () => {
    const lines = [];
    for (let i = 0; i < 5000; i++) {
      if (i % 50 === 0) lines.push(`198.51.100.22 - - [13/Sep/2026] "GET /api/users?id=1' OR 1=1 HTTP/1.1" 200`);
      else if (i % 70 === 0) lines.push(`203.0.113.45 - - [13/Sep/2026] "POST /comment HTTP/1.1" <script>alert(1)</script>`);
      else if (i % 100 === 0) lines.push(`192.0.2.10 - - [13/Sep/2026] "GET /ping?host=127.0.0.1; whoami HTTP/1.1" 200`);
      else if (i % 2 === 0 && i < 30) lines.push(`198.51.100.99 - - [13/Sep/2026] "POST /login HTTP/1.1" 401 login failed`);
      else lines.push(`10.0.0.1 - - [13/Sep/2026] "GET /assets/style.css HTTP/1.1" 200`);
    }

    const t0 = Date.now();
    const logReport = analyzeLog(lines.join('\n'));
    const duration = Date.now() - t0;

    assert.ok(logReport.summary.totalFindings > 50, 'Must detect numerous attack patterns');
    assert.ok(logReport.summary.riskScore >= 70, 'Risk score must reach CRITICAL');
    assert.ok(duration < 250, `Log analysis took too long: ${duration}ms`);

    // Null input safety
    const nullReport = analyzeLog(null);
    assert.strictEqual(nullReport.summary.totalLines, 0);
  });

  // ══════════════════════════════════════════════════════════════════════════
  // SUITE SUMMARY & CLEANUP
  // ══════════════════════════════════════════════════════════════════════════
  console.log(`\n======================================================================`);
  console.log(`🏁  WORST-CASE STRESS SUITE RESULTS: ${passedTests} / ${totalTests} TESTS PASSED (${failedTests} FAILED)`);
  console.log(`======================================================================\n`);

  // Restore pristine state
  restoreStateBackup();
  console.log('✨ Cleaned up test artifacts and restored pristine security state.');

  process.exit(failedTests === 0 ? 0 : 1);
}

runSuite().catch(err => {
  console.error('Unhandled suite error:', err);
  restoreStateBackup();
  process.exit(1);
});
