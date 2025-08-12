import axios from "axios";

// MyAnimeList API endpoints
const MAL_API_BASE = "https://api.myanimelist.net/v2";
const MAL_AUTH_URL = "https://myanimelist.net/v1/oauth2/authorize";
const MAL_TOKEN_URL = "https://myanimelist.net/v1/oauth2/token";

// Credentials from .env
const CLIENT_ID = process.env.MAL_CLIENT_ID!;
const CLIENT_SECRET = process.env.MAL_CLIENT_SECRET!;
const REDIRECT_URI = process.env.MAL_REDIRECT_URI!;

export function malAuthUrl() {
  // For demo: PKCE is not implemented, so challenge/verifier is static ("challenge")
  return `${MAL_AUTH_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&code_challenge_method=plain&code_challenge=challenge`;
}

// Exchange code for access token
export async function handleOAuthCallback(code: string) {
  const params = new URLSearchParams();
  params.append("client_id", CLIENT_ID);
  params.append("client_secret", CLIENT_SECRET);
  params.append("grant_type", "authorization_code");
  params.append("code", code);
  params.append("redirect_uri", REDIRECT_URI);
  params.append("code_verifier", "challenge");

  const response = await axios.post(MAL_TOKEN_URL, params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });
  return response.data;
}

// Proxy requests to MAL API (requires access token)
export async function proxyMalRequest(endpoint: string, query: any) {
  // TODO: Replace 'YOUR_SAVED_ACCESS_TOKEN' with actual token logic
  const accessToken = process.env.MAL_ACCESS_TOKEN || "YOUR_SAVED_ACCESS_TOKEN";
  const url = `${MAL_API_BASE}/${endpoint}`;
  const response = await axios.get(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    },
    params: query
  });
  return response.data;
}
