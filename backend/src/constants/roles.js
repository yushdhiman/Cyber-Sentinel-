/**
 * Canonical RBAC Role Definitions
 * 
 * Standardized uppercase roles across all authentication and authorization layers:
 * - ADMIN: Full privileges (system configuration, user management, containment, audit logs)
 * - SENIOR_ANALYST: Triage, incident closure, IP containment, audit logs, attack simulations
 * - ANALYST: Read-only alerts, run scans, inspect telemetry, view intel
 * - VIEWER: Read-only dashboard telemetry
 */

const ROLES = {
  ADMIN: 'ADMIN',
  SENIOR_ANALYST: 'SENIOR_ANALYST',
  ANALYST: 'ANALYST',
  VIEWER: 'VIEWER',
};

/**
 * Normalizes any legacy or arbitrary case role string to canonical uppercase format.
 * Examples: 'administrator' -> 'ADMIN', 'admin' -> 'ADMIN', 'analyst' -> 'ANALYST'
 */
function normalizeRole(role) {
  if (!role || typeof role !== 'string') return ROLES.ANALYST;
  const upper = role.trim().toUpperCase();
  if (upper === 'ADMINISTRATOR' || upper === 'ADMIN') return ROLES.ADMIN;
  if (upper === 'SENIOR_ANALYST' || upper === 'SENIOR' || upper === 'SENIORANALYST') return ROLES.SENIOR_ANALYST;
  if (upper === 'ANALYST' || upper === 'OPERATOR') return ROLES.ANALYST;
  if (upper === 'VIEWER' || upper === 'READONLY') return ROLES.VIEWER;
  return ROLES.ANALYST;
}

module.exports = {
  ROLES,
  normalizeRole,
};
