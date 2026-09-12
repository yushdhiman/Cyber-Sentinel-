/**
 * Centralized JWT Configuration & Secrets Management
 * 
 * Strict Production Enforcement:
 * In production (NODE_ENV === 'production'), a valid JWT_SECRET MUST be provided
 * in the environment. The server will deliberately fail fast rather than running
 * with an insecure, known, or fallback key.
 */

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.trim() === '') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'FATAL DEPLOYMENT ERROR: JWT_SECRET environment variable is missing in production. ' +
        'Refusing to initialize with fallback secrets.'
      );
    }
    // Development-only fallback warning
    console.warn('[JWT] WARNING: JWT_SECRET not provided. Using local development secret.');
    return 'cyber-sentinel-dev-only-secret-do-not-use-in-production';
  }
  return secret.trim();
}

function getJwtExpiresIn() {
  return process.env.JWT_EXPIRES_IN || '1h';
}

module.exports = {
  getJwtSecret,
  getJwtExpiresIn,
};
