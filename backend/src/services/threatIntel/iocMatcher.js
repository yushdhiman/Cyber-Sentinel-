/**
 * iocMatcher.js
 * High-performance indexed IOC engine providing deduplicated indicator matching
 * against ThreatFox, CISA KEV, and local signature stores.
 */
const { liveThreatPool, fallbackThreats } = require('../../utils/liveThreatFetcher');

// In-memory indexed IOC caches
const ipIndex = new Map();
const domainIndex = new Map();
const hashIndex = new Map();

function reindexIocs() {
  const pool = (Array.isArray(liveThreatPool) && liveThreatPool.length > 0) 
    ? liveThreatPool 
    : (Array.isArray(fallbackThreats) ? fallbackThreats : []);

  ipIndex.clear();
  domainIndex.clear();
  hashIndex.clear();

  pool.forEach(item => {
    if (item.sourceIp) {
      ipIndex.set(item.sourceIp.trim(), {
        iocType: 'ipv4',
        value: item.sourceIp.trim(),
        malware: item.malware || item.type || 'Generic Threat',
        threatType: item.threatType,
        severity: item.severity || 'HIGH',
        confidence: item.confidence || 90,
        mitreTechnique: item.mitreTechnique || 'T1071',
        source: 'ThreatFox',
      });
    }

    if (item.hash) {
      hashIndex.set(item.hash.toLowerCase().trim(), {
        iocType: 'sha256',
        value: item.hash.toLowerCase().trim(),
        malware: item.malware || 'Generic Malware',
        severity: item.severity || 'CRITICAL',
        confidence: item.confidence || 95,
        source: 'ThreatFox Malware Hash',
      });
    }
  });
}

/**
 * Dynamically register additional IOCs (e.g. from tests or dynamic feeds)
 */
function addIndicators(items = []) {
  if (!Array.isArray(items)) return;
  items.forEach(item => {
    const ioc = item.ioc || item.sourceIp || item.value;
    if (!ioc) return;
    const cleanIoc = ioc.trim();
    const isHash = /^[a-fA-F0-9]{32,64}$/.test(cleanIoc);
    const isIp = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(cleanIoc);

    const record = {
      value: cleanIoc,
      malware: item.malware || 'Unknown Malware',
      confidence: item.confidence || 90,
      reporter: item.reporter || 'internal',
      severity: item.severity || 'HIGH',
      firstSeen: item.firstSeen || new Date().toISOString(),
      reference: item.reference || 'threatfox'
    };

    if (isHash) {
      hashIndex.set(cleanIoc.toLowerCase(), { iocType: 'sha256', ...record });
    } else if (isIp) {
      const ipOnly = cleanIoc.split(':')[0];
      ipIndex.set(ipOnly, { iocType: 'ipv4', ...record });
    } else {
      domainIndex.set(cleanIoc.toLowerCase(), { iocType: 'domain', ...record });
    }
  });
}

// Initial index build
try {
  reindexIocs();
} catch (_) {}

/**
 * Match a target value (IP, domain, or file hash) against indexed IOC databases.
 * Returns { matched: true, ... } or { matched: false }
 */
function matchIoc(value, typeHint = null) {
  if (!value || typeof value !== 'string') return { matched: false };
  const clean = value.trim();

  // 1. IP check (with port stripping support)
  const ipOnly = clean.split(':')[0];
  if (ipIndex.has(ipOnly)) {
    return { matched: true, ...ipIndex.get(ipOnly) };
  }

  // 2. Hash check (SHA256 / MD5 / SHA1)
  const lower = clean.toLowerCase();
  if (hashIndex.has(lower)) {
    return { matched: true, ...hashIndex.get(lower) };
  }

  // 3. Domain / Host check
  if (domainIndex.has(lower)) {
    return { matched: true, ...domainIndex.get(lower) };
  }

  return { matched: false };
}

/**
 * Convenient match helper returning indicator detail object or null
 */
function matchIndicator(value) {
  const result = matchIoc(value);
  if (result.matched) {
    return {
      indicator: value,
      type: result.iocType,
      malware: result.malware,
      confidence: result.confidence,
      reporter: result.source || result.reporter || 'threat-intel',
      firstSeen: result.firstSeen || 'Active',
      reference: result.reference || 'ThreatFox / CISA KEV'
    };
  }
  return null;
}

function getIocStats() {
  return {
    indexedIps: ipIndex.size,
    indexedHashes: hashIndex.size,
    indexedDomains: domainIndex.size,
    totalIndicators: ipIndex.size + hashIndex.size + domainIndex.size,
  };
}

module.exports = {
  matchIoc,
  matchIndicator,
  addIndicators,
  reindexIocs,
  getIocStats,
};
