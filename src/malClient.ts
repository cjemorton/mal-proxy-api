import axios, { AxiosResponse } from 'axios';
import crypto from 'crypto';
import { MalTokenResponse, AnimeSearchResult } from './types';

const MAL_API_BASE = 'https://api.myanimelist.net/v2';
const MAL_AUTH_URL = 'https://myanimelist.net/v1/oauth2/authorize';
const MAL_TOKEN_URL = 'https://myanimelist.net/v1/oauth2/token';

// Store code verifiers temporarily (in production, use proper session management)
const codeVerifiers: { [state: string]: string } = {};

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

export function generateAuthUrl(state: string = 'default_user'): string {
  const { CLIENT_ID, REDIRECT_URI } = getEnvVars();
  
  // Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  
  // Store the code verifier for later use
  codeVerifiers[state] = codeVerifier;
  
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_challenge_method: 'S256',
    code_challenge: codeChallenge,
    state: state
  });

  console.log(`🔐 Generated PKCE for state ${state}:`);
  console.log(`   Code Verifier: ${codeVerifier.substring(0, 10)}...`);
  console.log(`   Code Challenge: ${codeChallenge.substring(0, 10)}...`);

  return `${MAL_AUTH_URL}?${params.toString()}`;
}

export async function exchangeCodeForToken(code: string, state: string): Promise<MalTokenResponse> {
  try {
    const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI } = getEnvVars();
    
    // Retrieve the code verifier for this state
    const codeVerifier = codeVerifiers[state];
    if (!codeVerifier) {
      throw new Error('Code verifier not found. Please start the auth flow again.');
    }
    
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier
    });

    console.log(`🔄 Exchanging code for token with state: ${state}`);

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
