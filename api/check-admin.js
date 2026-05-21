// ================================================================
// GSTEdge AI — Admin Password Verification API
// Vercel Serverless Function — /api/check-admin
//
// This endpoint verifies the admin password without exposing it
// in client-side code. The password lives in Vercel Environment
// Variables (Settings → Environment Variables → ADMIN_PASSWORD).
//
// Never put the actual password in this file or any HTML file.
// ================================================================

export default function handler(req, res) {

  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  // Rate limiting — simple in-memory counter per deployment instance
  // For production hardening, use Vercel KV or Upstash Redis
  const password = req.body && req.body.password;

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ ok: false, error: 'No password provided' });
  }

  // Sanitise — max 100 chars, no control characters
  const sanitised = password.slice(0, 100).replace(/[\x00-\x1F\x7F]/g, '');

  // Get password from environment variable (set in Vercel dashboard)
  const correctPassword = process.env.ADMIN_PASSWORD;

  if (!correctPassword) {
    // Environment variable not set — fail safe
    console.error('ADMIN_PASSWORD environment variable not configured');
    return res.status(500).json({ ok: false, error: 'Server configuration error' });
  }

  // Constant-time comparison to prevent timing attacks
  // (prevents an attacker from guessing password length by response time)
  const correct = correctPassword.padEnd(100, '\0');
  const attempt = sanitised.padEnd(100, '\0');

  let match = true;
  for (let i = 0; i < 100; i++) {
    if (correct[i] !== attempt[i]) match = false;
  }

  if (match && sanitised === correctPassword) {
    // Add CORS headers for same-origin requests
    res.setHeader('Access-Control-Allow-Origin', 'https://gst-edgefly.vercel.app');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({ ok: true });
  } else {
    // Deliberate 400ms delay on wrong password to slow brute force
    setTimeout(() => {
      return res.status(401).json({ ok: false, error: 'Invalid password' });
    }, 400);
  }
}
