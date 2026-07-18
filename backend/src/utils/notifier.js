const nodemailer = require('nodemailer');

/**
 * Sends an email containing the verification or MFA code.
 */
async function sendEmail({ to, subject, body }) {
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = process.env.SMTP_PORT || 587;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const smtpFrom = process.env.SMTP_FROM || smtpUser;

  if (!smtpHost || !smtpUser || !smtpPass) {
    console.log(`\n==========================================`);
    console.log(`[SMTP SIMULATION] No SMTP credentials set.`);
    console.log(`[SMTP SIMULATION] To: ${to}`);
    console.log(`[SMTP SIMULATION] Subject: ${subject}`);
    console.log(`[SMTP SIMULATION] Body: ${body}`);
    console.log(`==========================================\n`);
    return { simulated: true };
  }

  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: parseInt(smtpPort, 10),
    secure: parseInt(smtpPort, 10) === 465, // true for 465, false for other ports
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
  };

  const info = await transporter.sendMail(mailOptions);
  console.log(`[SMTP] Email successfully sent to ${to}. Message ID: ${info.messageId}`);
  return { simulated: false, messageId: info.messageId };
}

/**
 * Sends an SMS containing the verification or MFA code via Twilio.
 */
async function sendSMS({ to, body }) {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const fromPhone = process.env.TWILIO_PHONE_NUMBER;

  if (!accountSid || !authToken || !fromPhone) {
    console.log(`\n==========================================`);
    console.log(`[SMS SIMULATION] No Twilio credentials set.`);
    console.log(`[SMS SIMULATION] To: ${to}`);
    console.log(`[SMS SIMULATION] Body: ${body}`);
    console.log(`==========================================\n`);
    return { simulated: true };
  }

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

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Twilio API error (Status ${response.status}): ${errorText}`);
  }

  const data = await response.json();
  console.log(`[SMS] SMS successfully sent to ${to}. SID: ${data.sid}`);
  return { simulated: false, sid: data.sid };
}

/**
 * Helper to dispatch code via email or SMS depending on verification type.
 */
async function sendVerificationCode({ type, target, code }) {
  const subject = `[Cyber Sentinel] Verification Key: ${code}`;
  const body = `Your Cyber Sentinel verification passcode is: ${code}\nThis code is valid for 5 minutes.`;

  if (type === 'email') {
    return sendEmail({ to: target, subject, body });
  } else {
    return sendSMS({ to: target, body });
  }
}

/**
 * Helper to dispatch MFA login code.
 */
async function sendMFACode({ type, target, code }) {
  const subject = `[Cyber Sentinel] MFA Access Key: ${code}`;
  const body = `Your Cyber Sentinel login MFA code is: ${code}\nDo not share this passcode with anyone. Valid for 5 minutes.`;

  if (type === 'email') {
    return sendEmail({ to: target, subject, body });
  } else {
    return sendSMS({ to: target, body });
  }
}

module.exports = {
  sendEmail,
  sendSMS,
  sendVerificationCode,
  sendMFACode,
};
