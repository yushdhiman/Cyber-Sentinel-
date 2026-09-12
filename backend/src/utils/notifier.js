let nodemailer;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  nodemailer = null;
}

/**
 * Sends an email containing verification code, MFA OTP, or Password Reset link.
 */
async function sendEmail({ to, subject, body, html }) {
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = process.env.SMTP_PORT || 587;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const smtpFrom = process.env.SMTP_FROM || smtpUser || 'Cyber Sentinel <no-reply@sentinel.local>';

  if (!smtpHost || !smtpUser || !smtpPass || !nodemailer) {
    console.log(`\n======================================================`);
    console.log(`[SMTP TRANSMISSION DISPATCH]`);
    console.log(`To: ${to}`);
    console.log(`Subject: ${subject}`);
    console.log(`Body:\n${body}`);
    console.log(`======================================================\n`);
    return { simulated: true };
  }

  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: parseInt(smtpPort, 10),
    secure: parseInt(smtpPort, 10) === 465,
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
  });

  const mailOptions = {
    from: smtpFrom,
    to,
    subject,
    text: body,
    html: html || body.replace(/\n/g, '<br/>'),
  };

  const info = await transporter.sendMail(mailOptions);
  console.log(`[SMTP] Live email dispatched to ${to}. MessageID: ${info.messageId}`);
  return { simulated: false, messageId: info.messageId };
}

/**
 * Sends an SMS containing the OTP via Fast2SMS (India +91) or Twilio (Global).
 */
async function sendSMS({ to, body, otp }) {
  const cleanPhone = to.replace(/[^\d+]/g, '');

  // ── 1. Fast2SMS (Preferred for India +91) ─────────────────────────────────
  const fast2smsKey = process.env.FAST2SMS_API_KEY;
  if (fast2smsKey && (cleanPhone.startsWith('+91') || cleanPhone.length === 10)) {
    try {
      const numbers = cleanPhone.replace('+91', '').trim();
      const otpVal = otp || body.match(/\d{6}/)?.[0] || '';
      if (!otpVal) {
        console.warn(`[Fast2SMS] Missing OTP code for dispatch to ${to}`);
        return { simulated: false, error: 'Missing OTP code' };
      }
      const response = await fetch('https://www.fast2sms.com/dev/bulkV2', {
        method: 'POST',
        headers: {
          'authorization': fast2smsKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          route: 'otp',
          variables_values: otpVal,
          numbers: numbers,
        }),
      });

      const data = await response.json();
      if (data.return) {
        console.log(`[Fast2SMS] Live OTP successfully delivered to ${to}. RequestID: ${data.request_id}`);
        return { simulated: false, provider: 'fast2sms', requestId: data.request_id };
      } else {
        console.warn(`[Fast2SMS] Gateway warning:`, data.message);
      }
    } catch (err) {
      console.error(`[Fast2SMS] Error transmitting SMS:`, err.message);
    }
  }

  // ── 2. Twilio (Global / US / International) ───────────────────────────────
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const fromPhone = process.env.TWILIO_PHONE_NUMBER;

  if (accountSid && authToken && fromPhone) {
    try {
      const url = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;
      const authHeader = 'Basic ' + Buffer.from(`${accountSid}:${authToken}`).toString('base64');

      const params = new URLSearchParams();
      params.append('To', to);
      params.append('From', fromPhone);
      params.append('Body', body);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': authHeader,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`[Twilio] Live SMS dispatched to ${to}. SID: ${data.sid}`);
        return { simulated: false, provider: 'twilio', sid: data.sid };
      } else {
        const errorText = await response.text();
        console.warn(`[Twilio] Gateway response: ${errorText}`);
      }
    } catch (err) {
      console.error(`[Twilio] Transmission error:`, err.message);
    }
  }

  // ── 3. Console Dispatch (When gateway credentials are not yet configured) ───
  console.log(`\n======================================================`);
  console.log(`[AUTHENTIC SMS DISPATCH]`);
  console.log(`Destination: ${to}`);
  console.log(`Message: ${body}`);
  console.log(`To enable live cellular SMS: Add FAST2SMS_API_KEY or TWILIO credentials to .env`);
  console.log(`======================================================\n`);
  return { simulated: true, provider: 'console' };
}

/**
 * Dispatches verification code via email or SMS.
 */
async function sendVerificationCode({ type, target, code }) {
  const subject = `[Cyber Sentinel] Verification Key: ${code}`;
  const body = `Your Cyber Sentinel verification passcode is: ${code}\nThis code is valid for 5 minutes.`;

  if (type === 'email') {
    return sendEmail({ to: target, subject, body });
  } else {
    return sendSMS({ to: target, body, otp: code });
  }
}

/**
 * Dispatches MFA login OTP.
 */
async function sendMFACode({ type, target, code }) {
  const subject = `[Cyber Sentinel] Login MFA Security Key: ${code}`;
  const body = `Your Cyber Sentinel login MFA code is: ${code}\nDo not share this passcode with anyone. Valid for 5 minutes.`;

  if (type === 'email') {
    return sendEmail({ to: target, subject, body });
  } else {
    return sendSMS({ to: target, body, otp: code });
  }
}

/**
 * Dispatches Password Reset Email with link.
 */
async function sendPasswordResetEmail({ to, name, resetUrl }) {
  const subject = `[Cyber Sentinel] Password Reset Authorization`;
  const body = `Hello ${name || 'Operator'},\n\nA password reset request was initiated for your Cyber Sentinel account.\n\nClick the link below to securely reset your access passcode (valid for 15 minutes):\n${resetUrl}\n\nIf you did not request this, please disregard this email.`;
  return sendEmail({ to, subject, body });
}

/**
 * Dispatches Password Reset OTP to mobile.
 */
async function sendPasswordResetOTP({ to, otp }) {
  const body = `[Cyber Sentinel] Your password reset OTP is: ${otp}. Valid for 5 minutes. Do NOT share this code with anyone.`;
  return sendSMS({ to, body, otp });
}

module.exports = {
  sendEmail,
  sendSMS,
  sendVerificationCode,
  sendMFACode,
  sendPasswordResetEmail,
  sendPasswordResetOTP,
};
