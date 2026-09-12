/**
 * totp.js
 * Pure Node.js RFC 6238 Time-Based One-Time Password (TOTP) implementation.
 * Zero external dependencies. Compatible with Google Authenticator, Microsoft Authenticator, Authy.
 */

const crypto = require('crypto');

// Standard RFC 4648 Base32 alphabet
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodes a base32 string into a Buffer
 */
function base32Decode(base32Str) {
  const cleaned = base32Str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_CHARS.indexOf(cleaned[i]);
    if (idx === -1) {
      continue; // Skip unrecognized characters
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Encodes a buffer into a base32 string
 */
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Generates a random Base32 secret key (160-bit entropy = 20 bytes)
 */
function generateSecret(length = 20) {
  const randomBytes = crypto.randomBytes(length);
  return base32Encode(randomBytes);
}

/**
 * Computes an RFC 4226 HOTP code for a given secret and counter
 */
function generateHOTP(secretBase32, counter, digits = 6) {
  const key = base32Decode(secretBase32);

  // Counter as 8-byte buffer (Big-Endian)
  const counterBuffer = Buffer.alloc(8);
  let temp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBuffer[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }

  const hmac = crypto.createHmac('sha1', key);
  hmac.update(counterBuffer);
  const digest = hmac.digest();

  // Dynamic truncation (RFC 4226 section 5.4)
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Generates an RFC 6238 TOTP code for the current time
 * @param {string} secretBase32
 * @param {number} time - Unix epoch timestamp in milliseconds (defaults to Date.now())
 * @param {number} stepSeconds - Time step in seconds (default: 30)
 * @param {number} digits - Number of digits (default: 6)
 */
function generateTOTP(secretBase32, time = Date.now(), stepSeconds = 30, digits = 6) {
  const counter = Math.floor(time / 1000 / stepSeconds);
  return generateHOTP(secretBase32, counter, digits);
}

/**
 * Verifies a TOTP code against a secret with time-drift window support
 * @param {string} token - The 6-digit code supplied by user
 * @param {string} secretBase32 - The user's TOTP secret key
 * @param {number} window - Allow +/- window steps (window=1 checks -30s, 0s, +30s)
 * @param {number} time - Current time in ms
 * @returns {boolean} true if valid
 */
function verifyTOTP(token, secretBase32, window = 1, time = Date.now()) {
  if (!token || !secretBase32) return false;
  const cleanToken = token.trim().replace(/\s+/g, '');
  if (cleanToken.length !== 6 || !/^\d{6}$/.test(cleanToken)) return false;

  const stepSeconds = 30;
  const currentCounter = Math.floor(time / 1000 / stepSeconds);

  for (let i = -window; i <= window; i++) {
    const generated = generateHOTP(secretBase32, currentCounter + i, 6);
    if (crypto.timingSafeEqual(Buffer.from(generated), Buffer.from(cleanToken))) {
      return true;
    }
  }

  return false;
}

/**
 * Generates an otpauth:// URL for QR code generation
 */
function generateOtpAuthUri(account, issuer, secretBase32) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer: issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30'
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = {
  generateSecret,
  generateTOTP,
  verifyTOTP,
  generateOtpAuthUri
};
