import axios, { AxiosResponse } from 'axios';
import crypto from 'crypto';
import { MalTokenResponse, AnimeSearchResult } from './types';

const MAL_API_BASE = 'https://api.myanimelist.net/v2';
const MAL_AUTH_URL = 'https://myanimelist.net/v1/oauth2/authorize';
const MAL_TOKEN_URL = 'https://myanimelist.net/v1/oauth2/token';

// Store code verifiers with timestamp for cleanup
interface PKCEState {
  codeVerifier: string;
  timestamp: number;
}

const codeVerifiers: { [state: string]: PKCEState } = {};

function getEnvVars() {
  const CLIENT_ID = process.env.MAL_CLIENT_ID;
  const CLIENT_SECRET = process.env.MAL_CLIENT_SECRET;
  const REDIRECT_URI = process.env.MAL_REDIRECT_URI;

  if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
    throw new Error('Missing required environment variables: MAL_CLIENT_ID, MAL_CLIENT_SECRET, MAL_REDIRECT_URI');
  }

  return { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI };
}

function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Clean up old PKCE states (older than 10 minutes)
function cleanupOldStates(): void {
  const tenMinutesAgo = Date.now() - (10 * 60 * 1000);
  Object.keys(codeVerifiers).forEach(state => {
    if (codeVerifiers[state].timestamp < tenMinutesAgo) {
      delete codeVerifiers[state];
      console.log(`🧹 Cleaned up expired PKCE state: ${state}`);
    }
  });
}

export function generateAuthUrl(state: string = 'default_user'): string {
  const { CLIENT_ID, REDIRECT_URI } = getEnvVars();
  
  // Clean up old states first
  cleanupOldStates();
  
  // Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  
  // Create a unique state if one already exists
  let uniqueState = state;
  let counter = 1;
  while (codeVerifiers[uniqueState]) {
    uniqueState = `${state}_${counter}`;
    counter++;
  }
  
  // Store the code verifier for later use
  codeVerifiers[uniqueState] = {
    codeVerifier,
    timestamp: Date.now()
  };
  
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_challenge_method: 'S256',
    code_challenge: codeChallenge,
    state: uniqueState
  });

  console.log(`🔐 Generated PKCE for state ${uniqueState}:`);
  console.log(`   Code Verifier: ${codeVerifier.substring(0, 10)}...`);
  console.log(`   Code Challenge: ${codeChallenge.substring(0, 10)}...`);
  console.log(`   Stored states: ${Object.keys(codeVerifiers).join(', ')}`);

  return `${MAL_AUTH_URL}?${params.toString()}`;
}

export async function exchangeCodeForToken(code: string, state: string): Promise<MalTokenResponse> {
  try {
    const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI } = getEnvVars();
    
    console.log(`🔍 Looking for PKCE state: ${state}`);
    console.log(`📋 Available states: ${Object.keys(codeVerifiers).join(', ')}`);
    
    // Retrieve the code verifier for this state
    const pkceState = codeVerifiers[state];
    if (!pkceState) {
      console.log(`❌ Code verifier not found for state: ${state}`);
      console.log(`📋 Available states: ${Object.keys(codeVerifiers).join(', ')}`);
      throw new Error(`Code verifier not found for state: ${state}. Please start the auth flow again.`);
    }
    
    const codeVerifier = pkceState.codeVerifier;
    console.log(`✅ Found code verifier for state ${state}: ${codeVerifier.substring(0, 10)}...`);
    
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier
    });

    console.log(`🔄 Exchanging code for token with state: ${state}`);
    console.log(`📋 Using redirect_uri: ${REDIRECT_URI}`);

    const response: AxiosResponse<MalTokenResponse> = await axios.post(
      MAL_TOKEN_URL,
      params,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    // Clean up the stored code verifier
    delete codeVerifiers[state];
    
    console.log(`✅ Successfully exchanged code for token`);
    return response.data;
  } catch (error: any) {
    console.error('❌ Error exchanging code for token:', error.response?.data || error.message);
    
    // If it's a PKCE error, clean up all states to force fresh start
    if (error.response?.data?.hint?.includes('code_verifier')) {
      console.log('🧹 Clearing all PKCE states due to verifier error');
      Object.keys(codeVerifiers).forEach(key => delete codeVerifiers[key]);
    }
    
    throw new Error('Failed to exchange authorization code for access token');
  }
}

export async function searchAnime(query: string, accessToken: string): Promise<AnimeSearchResult> {
  try {
    const response: AxiosResponse<AnimeSearchResult> = await axios.get(
      `${MAL_API_BASE}/anime`,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        },
        params: {
          q: query,
          limit: 10
        }
      }
    );

    return response.data;
  } catch (error: any) {
    console.error('Error searching anime:', error.response?.data || error.message);
    throw new Error('Failed to search anime');
  }
}

export async function getUserAnimeList(accessToken: string): Promise<any> {
  try {
    const response = await axios.get(
      `${MAL_API_BASE}/users/@me/animelist`,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        },
        params: {
          status: 'watching',
          limit: 10
        }
      }
    );

    return response.data;
  } catch (error: any) {
    console.error('Error getting user anime list:', error.response?.data || error.message);
    throw new Error('Failed to get user anime list');
  }
}

// Export function to check stored states (for debugging)
export function getStoredStates(): string[] {
  return Object.keys(codeVerifiers);
}
