import express, { Request, Response } from 'express';
import crypto from 'crypto';
import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// PKCE storage - in production, use Redis or database
interface PKCEData {
  codeVerifier: string;
  codeChallenge: string;
  timestamp: number;
}

const codeVerifiers: { [state: string]: PKCEData } = {};

// Debug PKCE storage - isolated from production OAuth state
const debugCodeVerifiers: { [state: string]: PKCEData } = {};

// Utility functions
function base64urlEscape(str: string): string {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateCodeVerifier(): string {
  return base64urlEscape(crypto.randomBytes(32).toString('base64'));
}

function generateCodeChallenge(codeVerifier: string): string {
  return base64urlEscape(
    crypto.createHash('sha256').update(codeVerifier).digest('base64')
  );
}

function cleanupExpiredStates(): void {
  const now = Date.now();
  const expiry = 10 * 60 * 1000; // 10 minutes
  
  for (const [state, data] of Object.entries(codeVerifiers)) {
    if (now - data.timestamp > expiry) {
      delete codeVerifiers[state];
      console.log(`🧹 Cleaned up expired state: ${state}`);
    }
  }
}

// Cleanup function specifically for debug states
function cleanupExpiredDebugStates(): void {
  const now = Date.now();
  const expiry = 10 * 60 * 1000; // 10 minutes
  
  for (const [state, data] of Object.entries(debugCodeVerifiers)) {
    if (now - data.timestamp > expiry) {
      delete debugCodeVerifiers[state];
      console.log(`🧹 Cleaned up expired debug state: ${state}`);
    }
  }
}

// Routes

// Enhanced debug endpoint
app.get('/debug/pkce', (req: Request, res: Response) => {
  cleanupExpiredStates();
  
  const detailedStates: any = {};
  const stateCount = Object.keys(codeVerifiers).length;
  
  for (const [state, data] of Object.entries(codeVerifiers)) {
    const ageMinutes = Math.round((Date.now() - data.timestamp) / (1000 * 60));
    
    detailedStates[state] = {
      codeVerifier: data.codeVerifier ? `${data.codeVerifier.substring(0, 15)}...` : 'missing',
      codeChallenge: data.codeChallenge ? `${data.codeChallenge.substring(0, 15)}...` : 'missing',
      timestamp: new Date(data.timestamp).toISOString(),
      age_minutes: ageMinutes,
      is_expired: ageMinutes > 10,
      verifier_length: data.codeVerifier?.length || 0,
      challenge_length: data.codeChallenge?.length || 0,
      verifier_valid: !!data.codeVerifier && data.codeVerifier.length >= 43,
      challenge_valid: !!data.codeChallenge && data.codeChallenge.length >= 43
    };
  }
  
  res.json({
    message: 'PKCE State Debug Information',
    timestamp: new Date().toISOString(),
    server_time_utc: new Date().toISOString().replace('T', ' ').substring(0, 19),
    total_states: stateCount,
    states: detailedStates,
    state_names: Object.keys(codeVerifiers),
    environment: {
      client_id: process.env.MAL_CLIENT_ID ? `${process.env.MAL_CLIENT_ID.substring(0, 8)}...` : 'missing',
      redirect_uri: process.env.MAL_REDIRECT_URI,
      has_client_secret: !!process.env.MAL_CLIENT_SECRET,
      node_version: process.version,
      port: process.env.PORT
    }
  });
});

// Environment debug endpoint
app.get('/debug/env', (req: Request, res: Response) => {
  res.json({
    message: 'Environment Configuration',
    timestamp: new Date().toISOString(),
    config: {
      MAL_CLIENT_ID: process.env.MAL_CLIENT_ID ? `${process.env.MAL_CLIENT_ID.substring(0, 8)}...` : 'missing',
      MAL_CLIENT_SECRET: process.env.MAL_CLIENT_SECRET ? 'present' : 'missing',
      MAL_REDIRECT_URI: process.env.MAL_REDIRECT_URI || 'missing',
      PORT: process.env.PORT || '3000',
      NODE_ENV: process.env.NODE_ENV || 'development'
    },
    urls: {
      auth_endpoint: '/auth/cjemorton',
      callback_endpoint: '/callback',
      debug_pkce: '/debug/pkce',
      debug_env: '/debug/env'
    }
  });
});

// Clear all PKCE states (for testing)
app.get('/debug/clear', (req: Request, res: Response) => {
  const clearedCount = Object.keys(codeVerifiers).length;
  Object.keys(codeVerifiers).forEach(key => delete codeVerifiers[key]);
  
  res.json({
    message: 'All PKCE states cleared',
    timestamp: new Date().toISOString(),
    cleared_states: clearedCount
  });
});

/**
 * Debug PKCE Flow Endpoint
 * Generates complete PKCE credentials and authorization URL for MyAnimeList OAuth debugging
 * Isolated from production OAuth state with 10-minute expiration
 */
app.get('/debug/pkce-flow', (req: Request, res: Response) => {
  cleanupExpiredDebugStates();
  
  // Generate unique debug state
  const timestamp = Date.now();
  const stateId = `debug_${timestamp}_${Math.random().toString(36).substr(2, 9)}`;
  
  // Generate PKCE credentials
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  
  // Store in debug storage
  debugCodeVerifiers[stateId] = {
    codeVerifier,
    codeChallenge,
    timestamp
  };
  
  // Generate full authorization URL
  const authUrl = new URL('https://myanimelist.net/v1/oauth2/authorize');
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', process.env.MAL_CLIENT_ID!);
  authUrl.searchParams.append('redirect_uri', process.env.MAL_REDIRECT_URI!);
  authUrl.searchParams.append('state', stateId);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');
  
  console.log(`🔧 Generated debug PKCE flow with state: ${stateId}`);
  
  res.json({
    message: 'Debug PKCE flow generated successfully',
    timestamp: new Date().toISOString(),
    debug_session: {
      state: stateId,
      expires_at: new Date(timestamp + 10 * 60 * 1000).toISOString(),
      expires_in_minutes: 10
    },
    pkce_credentials: {
      code_verifier: codeVerifier,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      verifier_length: codeVerifier.length,
      challenge_length: codeChallenge.length
    },
    authorization: {
      url: authUrl.toString(),
      method: 'GET'
    },
    oauth_parameters: {
      response_type: 'code',
      client_id: process.env.MAL_CLIENT_ID,
      redirect_uri: process.env.MAL_REDIRECT_URI,
      state: stateId,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    },
    instructions: {
      step_1: 'Copy the authorization URL above and open it in your browser',
      step_2: 'Login to MyAnimeList and authorize the application',
      step_3: 'You will be redirected to the callback URL with code and state parameters',
      step_4: `Use the callback endpoint: GET /debug/pkce-flow/callback?code=AUTH_CODE&state=${stateId}`,
      step_5: 'The callback will attempt token exchange and show detailed results'
    },
    troubleshooting: {
      if_authorization_fails: 'Check that MAL_CLIENT_ID and MAL_REDIRECT_URI are correctly configured',
      if_state_expires: 'Debug states expire after 10 minutes - generate a new one if needed',
      check_environment: 'GET /debug/env',
      manual_callback_url: `/debug/pkce-flow/callback?code=YOUR_AUTH_CODE&state=${stateId}`
    },
    debug_info: {
      total_debug_states: Object.keys(debugCodeVerifiers).length,
      storage_isolation: 'Debug states are isolated from production OAuth states',
      cleanup_interval: 'Expired states are cleaned up automatically'
    }
  });
});

/**
 * Debug PKCE Flow Callback Endpoint  
 * Receives authorization code and attempts token exchange with detailed debugging output
 * Shows complete POST body and response for troubleshooting OAuth issues
 */
app.get('/debug/pkce-flow/callback', async (req: Request, res: Response) => {
  const { code, state, error } = req.query;
  
  console.log('\n=== DEBUG PKCE CALLBACK ===');
  console.log('📅 Timestamp:', new Date().toISOString());
  console.log('📥 Received state:', state);
  console.log('📥 Received code:', code ? `${String(code).substring(0, 20)}...` : 'missing');
  console.log('❌ Received error:', error || 'none');
  
  cleanupExpiredDebugStates();
  
  // Handle OAuth errors
  if (error) {
    console.log('❌ OAuth error in debug callback:', error);
    return res.status(400).json({
      error: 'OAuth authorization failed',
      timestamp: new Date().toISOString(),
      oauth_error: error,
      received_parameters: { code: !!code, state: !!state, error: error },
      troubleshooting: {
        common_errors: {
          'access_denied': 'User denied authorization - try again',
          'invalid_request': 'Check OAuth parameters and redirect URI configuration',
          'unsupported_response_type': 'Ensure response_type=code is used'
        },
        restart_flow: 'GET /debug/pkce-flow',
        check_environment: 'GET /debug/env'
      }
    });
  }
  
  // Validate required parameters
  if (!code || !state) {
    console.log('❌ Missing required parameters in debug callback');
    return res.status(400).json({
      error: 'Missing required parameters',
      timestamp: new Date().toISOString(),
      received_parameters: { code: !!code, state: !!state },
      required_parameters: ['code', 'state'],
      troubleshooting: {
        issue: 'Authorization callback must include both code and state parameters',
        restart_flow: 'GET /debug/pkce-flow'
      }
    });
  }
  
  // Look up debug PKCE data
  const debugPkceData = debugCodeVerifiers[state as string];
  console.log('🔍 Debug PKCE data found:', debugPkceData ? 'YES' : 'NO');
  
  if (!debugPkceData) {
    console.log('❌ No debug PKCE data found for state:', state);
    console.log('🗂️  Available debug states:', Object.keys(debugCodeVerifiers));
    
    return res.status(400).json({
      error: 'Invalid or expired debug state',
      timestamp: new Date().toISOString(),
      received_state: state,
      available_debug_states: Object.keys(debugCodeVerifiers),
      state_info: {
        searched_in: 'debugCodeVerifiers (isolated debug storage)',
        expiry_time: '10 minutes from generation'
      },
      troubleshooting: {
        issue: 'Debug state not found - may have expired or been invalid',
        solution: 'Generate a new debug PKCE flow',
        restart_flow: 'GET /debug/pkce-flow',
        check_debug_states: Object.keys(debugCodeVerifiers).length > 0 ? Object.keys(debugCodeVerifiers) : 'No active debug states'
      }
    });
  }
  
  const stateAge = Math.round((Date.now() - debugPkceData.timestamp) / (1000 * 60));
  console.log('⏱️  Debug state age (minutes):', stateAge);
  console.log('🔐 Code verifier length:', debugPkceData.codeVerifier.length);
  console.log('🔗 Code challenge length:', debugPkceData.codeChallenge.length);
  
  // Prepare token exchange data
  const tokenExchangeData = {
    grant_type: 'authorization_code',
    code: code as string,
    redirect_uri: process.env.MAL_REDIRECT_URI!,
    client_id: process.env.MAL_CLIENT_ID!,
    client_secret: process.env.MAL_CLIENT_SECRET!,
    code_verifier: debugPkceData.codeVerifier
  };
  
  try {
    console.log('🔄 Starting debug token exchange...');
    
    const tokenResponse = await axios.post(
      'https://myanimelist.net/v1/oauth2/token',
      new URLSearchParams(tokenExchangeData),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    console.log('✅ Debug token exchange successful!');
    console.log('🎫 Access token received:', `${tokenResponse.data.access_token.substring(0, 20)}...`);
    
    // Clean up used debug state
    delete debugCodeVerifiers[state as string];
    console.log('🧹 Cleaned up used debug state:', state);
    
    res.json({
      message: 'Debug OAuth flow completed successfully!',
      timestamp: new Date().toISOString(),
      debug_session: {
        state: state,
        age_minutes: stateAge,
        storage_type: 'debugCodeVerifiers (isolated)'
      },
      token_exchange: {
        success: true,
        endpoint: 'https://myanimelist.net/v1/oauth2/token',
        method: 'POST',
        content_type: 'application/x-www-form-urlencoded'
      },
      request_details: {
        post_body: {
          grant_type: tokenExchangeData.grant_type,
          code: `${(code as string).substring(0, 20)}...`,
          redirect_uri: tokenExchangeData.redirect_uri,
          client_id: tokenExchangeData.client_id,
          client_secret: '***hidden***',
          code_verifier: `${debugPkceData.codeVerifier.substring(0, 15)}...`
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      },
      response_details: {
        status: tokenResponse.status,
        token_type: tokenResponse.data.token_type,
        expires_in: tokenResponse.data.expires_in,
        access_token: `${tokenResponse.data.access_token.substring(0, 20)}...`,
        refresh_token: tokenResponse.data.refresh_token ? `${tokenResponse.data.refresh_token.substring(0, 20)}...` : undefined,
        full_response_keys: Object.keys(tokenResponse.data)
      },
      pkce_verification: {
        code_verifier_used: `${debugPkceData.codeVerifier.substring(0, 15)}...`,
        code_challenge_original: `${debugPkceData.codeChallenge.substring(0, 15)}...`,
        verification_method: 'S256 (SHA256)',
        verifier_length: debugPkceData.codeVerifier.length,
        challenge_length: debugPkceData.codeChallenge.length
      },
      next_steps: {
        use_access_token: 'The access token can be used to make API calls to MyAnimeList',
        api_base_url: 'https://api.myanimelist.net/v2',
        example_request: 'GET https://api.myanimelist.net/v2/anime?q=naruto with Authorization: Bearer {access_token}'
      }
    });
    
  } catch (error: any) {
    console.log('❌ Debug token exchange failed');
    console.log('📋 Error details:', error.response?.data || error.message);
    
    res.status(400).json({
      error: 'Debug token exchange failed',
      timestamp: new Date().toISOString(),
      debug_session: {
        state: state,
        age_minutes: stateAge,
        storage_type: 'debugCodeVerifiers (isolated)'
      },
      token_exchange: {
        success: false,
        endpoint: 'https://myanimelist.net/v1/oauth2/token',
        method: 'POST',
        content_type: 'application/x-www-form-urlencoded'
      },
      request_details: {
        post_body: {
          grant_type: tokenExchangeData.grant_type,
          code: `${(code as string).substring(0, 20)}...`,
          redirect_uri: tokenExchangeData.redirect_uri,
          client_id: tokenExchangeData.client_id,
          client_secret: '***hidden***',
          code_verifier: `${debugPkceData.codeVerifier.substring(0, 15)}...`
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      },
      error_details: {
        http_status: error.response?.status,
        error_response: error.response?.data || error.message,
        error_type: error.code || 'unknown'
      },
      pkce_verification: {
        code_verifier_used: `${debugPkceData.codeVerifier.substring(0, 15)}...`,
        code_challenge_original: `${debugPkceData.codeChallenge.substring(0, 15)}...`,
        verification_method: 'S256 (SHA256)',
        verifier_length: debugPkceData.codeVerifier.length,
        challenge_length: debugPkceData.codeChallenge.length
      },
      troubleshooting: {
        common_issues: {
          'invalid_grant': 'Authorization code may be expired or already used',
          'invalid_client': 'Check CLIENT_ID and CLIENT_SECRET configuration',
          'invalid_request': 'Check redirect_uri matches exactly',
          'code_verifier_error': 'PKCE verification failed - code_verifier/challenge mismatch'
        },
        check_environment: 'GET /debug/env',
        restart_flow: 'GET /debug/pkce-flow',
        verify_config: 'Ensure MAL_CLIENT_ID, MAL_CLIENT_SECRET, and MAL_REDIRECT_URI are correct'
      }
    });
  }
});

// OAuth initiation - improved state management
app.get('/auth/:username', (req: Request, res: Response) => {
  const username = req.params.username;
  
  // Clean up expired states first
  cleanupExpiredStates();
  
  // Check if user already has an active, non-expired state
  let existingState = null;
  for (const [state, data] of Object.entries(codeVerifiers)) {
    if (state.startsWith(username) && (Date.now() - data.timestamp) < 5 * 60 * 1000) { // 5 min window
      existingState = state;
      break;
    }
  }
  
  // If no valid existing state, create new one
  if (!existingState) {
    // Generate unique state
    let stateCounter = 0;
    let state = username;
    
    while (codeVerifiers[state]) {
      stateCounter++;
      state = `${username}_${stateCounter}`;
    }
    
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    codeVerifiers[state] = {
      codeVerifier,
      codeChallenge,
      timestamp: Date.now()
    };
    
    console.log(`🔐 Created new PKCE state: ${state}`);
    console.log(`📊 Code verifier length: ${codeVerifier.length}`);
    console.log(`📊 Code challenge length: ${codeChallenge.length}`);
    
    existingState = state;
  } else {
    console.log(`♻️  Reusing existing state: ${existingState}`);
  }
  
  const authUrl = new URL('https://myanimelist.net/v1/oauth2/authorize');
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', process.env.MAL_CLIENT_ID!);
  authUrl.searchParams.append('redirect_uri', process.env.MAL_REDIRECT_URI!);
  authUrl.searchParams.append('state', existingState);
  authUrl.searchParams.append('code_challenge', codeVerifiers[existingState].codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');
  
  console.log(`🚀 Redirecting to MAL OAuth with state: ${existingState}`);
  res.redirect(authUrl.toString());
});

// OAuth callback - enhanced debugging
app.get('/callback', async (req: Request, res: Response) => {
  const { code, state, error } = req.query;
  
  console.log('\n=== OAUTH CALLBACK DEBUG ===');
  console.log('📅 Timestamp:', new Date().toISOString());
  console.log('📥 Received state:', state);
  console.log('📥 Received code:', code ? `${String(code).substring(0, 20)}...` : 'missing');
  console.log('❌ Received error:', error || 'none');
  
  if (error) {
    console.log('❌ OAuth error received:', error);
    return res.status(400).json({
      error: 'OAuth authorization failed',
      details: error,
      timestamp: new Date().toISOString()
    });
  }
  
  if (!code || !state) {
    console.log('❌ Missing required parameters');
    return res.status(400).json({
      error: 'Missing required parameters',
      received: { code: !!code, state: !!state },
      timestamp: new Date().toISOString()
    });
  }
  
  const pkceData = codeVerifiers[state as string];
  console.log('🔍 PKCE data found:', pkceData ? 'YES' : 'NO');
  
  if (!pkceData) {
    console.log('❌ No PKCE data found for state:', state);
    console.log('🗂️  Available states:', Object.keys(codeVerifiers));
    
    return res.status(400).json({
      error: 'Invalid or expired state',
      timestamp: new Date().toISOString(),
      received_state: state,
      available_states: Object.keys(codeVerifiers),
      troubleshooting: {
        check_pkce_states: '/debug/pkce',
        restart_auth: `/auth/cjemorton`
      }
    });
  }
  
  const stateAge = Math.round((Date.now() - pkceData.timestamp) / (1000 * 60));
  console.log('⏱️  State age (minutes):', stateAge);
  console.log('🔐 Code verifier length:', pkceData.codeVerifier.length);
  console.log('🔗 Code challenge length:', pkceData.codeChallenge.length);
  console.log('🔐 Code verifier preview:', `${pkceData.codeVerifier.substring(0, 15)}...`);
  console.log('🔗 Code challenge preview:', `${pkceData.codeChallenge.substring(0, 15)}...`);
  
  try {
    console.log('🔄 Starting token exchange...');
    
    const tokenResponse = await axios.post(
      'https://myanimelist.net/v1/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: process.env.MAL_REDIRECT_URI!,
        client_id: process.env.MAL_CLIENT_ID!,
        client_secret: process.env.MAL_CLIENT_SECRET!,
        code_verifier: pkceData.codeVerifier
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    console.log('✅ Token exchange successful!');
    console.log('🎫 Access token received:', `${tokenResponse.data.access_token.substring(0, 20)}...`);
    
    // Clean up used state
    delete codeVerifiers[state as string];
    console.log('🧹 Cleaned up used state:', state);
    
    res.json({
      message: 'OAuth flow completed successfully!',
      timestamp: new Date().toISOString(),
      token_type: tokenResponse.data.token_type,
      expires_in: tokenResponse.data.expires_in,
      access_token: `${tokenResponse.data.access_token.substring(0, 20)}...`,
      refresh_token: tokenResponse.data.refresh_token ? `${tokenResponse.data.refresh_token.substring(0, 20)}...` : undefined
    });
    
  } catch (error: any) {
    console.log('❌ Token exchange failed');
    console.log('📋 Error details:', error.response?.data || error.message);
    
    res.status(400).json({
      error: 'Failed to exchange authorization code for access token',
      timestamp: new Date().toISOString(),
      details: error.response?.data || error.message,
      troubleshooting: {
        check_pkce_states: '/debug/pkce',
        check_env: '/debug/env',
        restart_auth: `/auth/cjemorton`
      }
    });
  }
});

// Health check
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    server_time_utc: new Date().toISOString().replace('T', ' ').substring(0, 19),
    uptime_seconds: Math.floor(process.uptime()),
    active_pkce_states: Object.keys(codeVerifiers).length
  });
});

// Root endpoint
app.get('/', (req: Request, res: Response) => {
  res.json({
    message: 'MyAnimeList OAuth PKCE Server',
    timestamp: new Date().toISOString(),
    endpoints: {
      start_oauth: '/auth/cjemorton',
      oauth_callback: '/callback',
      debug_pkce: '/debug/pkce',
      debug_env: '/debug/env',
      debug_pkce_flow: '/debug/pkce-flow',
      debug_pkce_callback: '/debug/pkce-flow/callback',
      clear_states: '/debug/clear',
      health: '/health'
    },
    status: 'ready'
  });
});

app.listen(port, () => {
  console.log(`🚀 MyAnimeList OAuth server running on port ${port}`);
  console.log(`📍 Server URL: http://mal.mrnet.work:${port}`);
  console.log(`🔗 Start OAuth: http://mal.mrnet.work:${port}/auth/cjemorton`);
  console.log(`🐛 Debug PKCE: http://mal.mrnet.work:${port}/debug/pkce`);
  console.log(`🔧 Debug PKCE Flow: http://mal.mrnet.work:${port}/debug/pkce-flow`);
  console.log(`⚙️  Debug Env: http://mal.mrnet.work:${port}/debug/env`);
});
