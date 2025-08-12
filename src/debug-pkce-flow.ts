import crypto from 'crypto';
import express, { Request, Response } from 'express';
import axios from 'axios';

const router = express.Router();

// In-memory debug state store (expires after 10 min)
const debugCodeVerifiers: Record<string, { codeVerifier: string; expires: number }> = {};

// Helper: Generate PKCE code_verifier and code_challenge
function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(codeVerifier: string): string {
  return crypto.createHash('sha256').update(codeVerifier).digest('base64url');
}

// GET /debug/pkce-flow: Generates PKCE codes and authorization URL
router.get('/pkce-flow', (req: Request, res: Response) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Debug state prefix for isolation
  const debugState = `debug_${Date.now()}`;
  debugCodeVerifiers[debugState] = {
    codeVerifier,
    expires: Date.now() + 10 * 60 * 1000 // 10 min expiration
  };

  // Cleanup expired states
  Object.keys(debugCodeVerifiers).forEach((state) => {
    if (debugCodeVerifiers[state].expires < Date.now()) delete debugCodeVerifiers[state];
  });

  // Build MyAnimeList OAuth URL (replace with your client_id, redirect_uri)
  const client_id = process.env.CLIENT_ID || 'YOUR_CLIENT_ID';
  const redirect_uri = process.env.REDIRECT_URI || 'YOUR_REDIRECT_URI';
  const auth_url = `https://myanimelist.net/v1/oauth2/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&code_challenge=${codeChallenge}&code_challenge_method=S256&state=${debugState}`;

  res.json({
    message: 'PKCE OAuth Debug Flow - Copy the authorization URL below',
    debug_state: debugState,
    pkce_details: {
      code_verifier: codeVerifier,
      code_verifier_length: codeVerifier.length,
      code_challenge: codeChallenge,
      code_challenge_length: codeChallenge.length,
      method: 'S256'
    },
    authorization_url: auth_url,
    instructions: [
      '1. Copy the authorization_url above',
      '2. Open it in your browser to authorize with MyAnimeList',
      '3. After authorization, you will be redirected to the callback URL',
      '4. Use /debug/pkce-flow/callback?code=...&state=... to exchange for a token and view full debug output'
    ]
  });
});

// GET /debug/pkce-flow/callback: Handles OAuth callback and shows full exchange
router.get('/pkce-flow/callback', async (req: Request, res: Response) => {
  const { code, state } = req.query;
  if (!code || !state) {
    return res.status(400).json({ error: 'Missing code or state in query parameters.' });
  }
  if (!debugCodeVerifiers[state as string]) {
    return res.status(400).json({ error: 'Invalid or expired debug state.' });
  }

  const codeVerifier = debugCodeVerifiers[state as string].codeVerifier;
  const client_id = process.env.CLIENT_ID || 'YOUR_CLIENT_ID';
  const client_secret = process.env.CLIENT_SECRET || 'YOUR_CLIENT_SECRET';
  const redirect_uri = process.env.REDIRECT_URI || 'YOUR_REDIRECT_URI';

  const token_url = 'https://myanimelist.net/v1/oauth2/token';
  const postBody = {
    grant_type: 'authorization_code',
    code,
    code_verifier: codeVerifier,
    client_id,
    client_secret,
    redirect_uri
  };

  let malResponse;
  try {
    malResponse = await axios.post(token_url, postBody, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
  } catch (err: any) {
    return res.json({
      message: 'Token exchange failed',
      post_body: postBody,
      mal_response: err.response?.data || err.message
    });
  }

  res.json({
    message: 'Token exchange succeeded',
    post_body: postBody,
    mal_response: malResponse.data
  });
});

export default router;