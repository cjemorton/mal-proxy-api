import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { generateAuthUrl, exchangeCodeForToken, searchAnime, getUserAnimeList, getStoredStates } from './malClient';
import { TokenManager } from './tokenManager';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Initialize token manager
const tokenManager = new TokenManager();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req: Request, res: Response) => {
  const users = tokenManager.listUsers();
  const pkceStates = getStoredStates();
  res.json({
    message: 'MyAnimeList Proxy API',
    current_time: new Date().toISOString(),
    authorized_users: users,
    active_pkce_states: Object.keys(pkceStates),
    redirect_uri: process.env.MAL_REDIRECT_URI,
    node_version: process.version,
    endpoints: {
      '/auth': 'Start OAuth2 flow',
      '/auth/:userId': 'Start OAuth2 flow for specific user',
      '/callback': 'OAuth2 callback',
      '/search/:query': 'Search anime (requires token)',
      '/search/:userId/:query': 'Search anime for specific user',
      '/user/animelist': 'Get user anime list (requires token)',
      '/user/:userId/animelist': 'Get anime list for specific user',
      '/tokens': 'List all stored tokens',
      '/tokens/:userId': 'Remove token for specific user',
      '/debug/pkce': 'Show active PKCE states with details',
      '/debug/env': 'Show environment configuration'
    }
  });
});

app.get('/debug/pkce', (req: Request, res: Response) => {
  const pkceStates = getStoredStates();
  res.json({
    message: 'Active PKCE States',
    timestamp: new Date().toISOString(),
    states: pkceStates,
    count: Object.keys(pkceStates).length,
    node_version: process.version,
    environment: {
      client_id: process.env.MAL_CLIENT_ID,
      redirect_uri: process.env.MAL_REDIRECT_URI,
      has_client_secret: !!process.env.MAL_CLIENT_SECRET,
      port: process.env.PORT
    }
  });
});

app.get('/debug/env', (req: Request, res: Response) => {
  res.json({
    message: 'Environment Configuration',
    timestamp: new Date().toISOString(),
    config: {
      client_id: process.env.MAL_CLIENT_ID,
      redirect_uri: process.env.MAL_REDIRECT_URI,
      has_client_secret: !!process.env.MAL_CLIENT_SECRET,
      client_secret_length: process.env.MAL_CLIENT_SECRET?.length || 0,
      port: process.env.PORT,
      node_env: process.env.NODE_ENV,
      node_version: process.version
    },
    notes: [
      'Client secret is hidden for security',
      'Redirect URI must match MyAnimeList app configuration exactly',
      'Client ID must match MyAnimeList app configuration'
    ]
  });
});

app.get('/auth', (req: Request, res: Response) => {
  res.redirect(`/auth/${req.query.userId || 'default_user'}`);
});

app.get('/auth/:userId', (req: Request, res: Response) => {
  try {
    const authUrl = generateAuthUrl(req.params.userId);
    console.log(`🔗 Generated auth URL for ${req.params.userId}: ${authUrl}`);
    res.redirect(authUrl);
  } catch (error: any) {
    console.error(`❌ Error generating auth URL for ${req.params.userId}:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/callback', async (req: Request, res: Response) => {
  try {
    const { code, state, error } = req.query;

    console.log(`📥 Callback received at ${new Date().toISOString()}:`);
    console.log(`   State: ${state}`);
    console.log(`   Code: ${typeof code === 'string' ? code.substring(0, 20) + '...' : code}`);
    console.log(`   Error: ${error || 'none'}`);

    if (error) {
      return res.status(400).json({ 
        error: 'Authorization failed', 
        details: error,
        description: req.query.error_description 
      });
    }

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Authorization code is required' });
    }

    if (!state || typeof state !== 'string') {
      return res.status(400).json({ error: 'State parameter is required' });
    }

    console.log(`🔄 Starting token exchange for state: ${state}`);

    const tokens = await exchangeCodeForToken(code, state);
    
    // Use the base state (without counter) for token storage
    const baseState = state.split('_')[0];
    tokenManager.storeToken(baseState, tokens);

    console.log(`✅ Token exchange successful for user: ${baseState}`);

    res.json({
      message: 'Authorization successful! 🎉',
      timestamp: new Date().toISOString(),
      user_id: baseState,
      state_used: state,
      token_type: tokens.token_type,
      expires_in: tokens.expires_in,
      expires_at: new Date(Date.now() + tokens.expires_in * 1000).toISOString(),
      next_steps: {
        search: `/search/${baseState}/naruto`,
        animelist: `/user/${baseState}/animelist`,
        check_tokens: '/tokens'
      }
    });
  } catch (error: any) {
    console.error(`❌ Callback error:`, error.message);
    res.status(400).json({ 
      error: error.message,
      timestamp: new Date().toISOString(),
      troubleshooting: {
        check_pkce_states: '/debug/pkce',
        check_env: '/debug/env',
        restart_auth: `/auth/${req.query.state || 'cjemorton'}`
      }
    });
  }
});

// Default search (uses default_user)
app.get('/search/:query', async (req: Request, res: Response) => {
  res.redirect(`/search/default_user/${req.params.query}`);
});

// Search for specific user
app.get('/search/:userId/:query', async (req: Request, res: Response) => {
  try {
    const { userId, query } = req.params;
    
    console.log(`🔍 Search request for user: ${userId}, query: ${query}`);
    
    const accessToken = tokenManager.getToken(userId);
    if (!accessToken) {
      return res.status(401).json({ 
        error: 'No valid access token found', 
        action: `Visit /auth/${userId} to authorize`,
        user_id: userId
      });
    }

    const results = await searchAnime(query, accessToken);
    res.json({
      timestamp: new Date().toISOString(),
      user_id: userId,
      query: query,
      results: results
    });
  } catch (error: any) {
    console.error(`❌ Search error for ${req.params.userId}:`, error.message);
    res.status(500).json({ 
      error: error.message,
      user_id: req.params.userId,
      query: req.params.query
    });
  }
});

// Default user animelist
app.get('/user/animelist', async (req: Request, res: Response) => {
  res.redirect('/user/default_user/animelist');
});

// Specific user animelist
app.get('/user/:userId/animelist', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    
    console.log(`📋 Anime list request for user: ${userId}`);
    
    const accessToken = tokenManager.getToken(userId);
    if (!accessToken) {
      return res.status(401).json({ 
        error: 'No valid access token found', 
        action: `Visit /auth/${userId} to authorize`,
        user_id: userId
      });
    }

    const animeList = await getUserAnimeList(accessToken);
    res.json({
      timestamp: new Date().toISOString(),
      user_id: userId,
      anime_list: animeList
    });
  } catch (error: any) {
    console.error(`❌ Anime list error for ${req.params.userId}:`, error.message);
    res.status(500).json({ 
      error: error.message,
      user_id: req.params.userId
    });
  }
});

// Token management endpoints
app.get('/tokens', (req: Request, res: Response) => {
  const users = tokenManager.listUsers();
  res.json({
    message: 'Stored tokens',
    timestamp: new Date().toISOString(),
    users: users,
    count: users.length
  });
});

app.delete('/tokens/:userId', (req: Request, res: Response) => {
  const { userId } = req.params;
  tokenManager.removeToken(userId);
  console.log(`🗑️ Token removed for user: ${userId}`);
  res.json({
    message: `Token removed for user: ${userId}`,
    timestamp: new Date().toISOString(),
    user_id: userId
  });
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: any) => {
  console.error('💥 Unhandled error:', err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req: Request, res: Response) => {
  console.log(`❓ 404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ 
    error: 'Endpoint not found',
    method: req.method,
    path: req.originalUrl,
    timestamp: new Date().toISOString(),
    available_endpoints: [
      'GET /',
      'GET /auth/:userId',
      'GET /callback',
      'GET /search/:userId/:query',
      'GET /user/:userId/animelist',
      'GET /tokens',
      'DELETE /tokens/:userId',
      'GET /debug/pkce',
      'GET /debug/env'
    ]
  });
});

// Listen on all IP addresses (0.0.0.0)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MAL Proxy API running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Local: http://localhost:${PORT}`);
  console.log(`🌐 Network: http://0.0.0.0:${PORT}`);
  console.log(`📡 Available on all network interfaces`);
  console.log(`🔧 Node.js version: ${process.version}`);
  console.log(`\n🎯 Quick Start:`);
  console.log(`   1. Visit: http://mal.mrnet.work:${PORT}/auth/cjemorton`);
  console.log(`   2. Authorize on MyAnimeList`);
  console.log(`   3. Test: http://mal.mrnet.work:${PORT}/search/cjemorton/naruto`);
  console.log(`\n🐛 Debug endpoints:`);
  console.log(`   PKCE States: http://localhost:${PORT}/debug/pkce`);
  console.log(`   Environment: http://localhost:${PORT}/debug/env`);
});
