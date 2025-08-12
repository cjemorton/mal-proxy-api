import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { generateAuthUrl, exchangeCodeForToken, searchAnime, getUserAnimeList } from './malClient';
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
  res.json({
    message: 'MyAnimeList Proxy API',
    current_time: new Date().toISOString(),
    authorized_users: users,
    redirect_uri: process.env.MAL_REDIRECT_URI,
    endpoints: {
      '/auth': 'Start OAuth2 flow',
      '/auth/:userId': 'Start OAuth2 flow for specific user',
      '/callback': 'OAuth2 callback',
      '/search/:query': 'Search anime (requires token)',
      '/search/:userId/:query': 'Search anime for specific user',
      '/user/animelist': 'Get user anime list (requires token)',
      '/user/:userId/animelist': 'Get anime list for specific user',
      '/tokens': 'List all stored tokens',
      '/tokens/:userId': 'Remove token for specific user'
    }
  });
});

app.get('/auth', (req: Request, res: Response) => {
  res.redirect(`/auth/${req.query.userId || 'default_user'}`);
});

app.get('/auth/:userId', (req: Request, res: Response) => {
  try {
    const authUrl = generateAuthUrl(req.params.userId);
    res.redirect(authUrl);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/callback', async (req: Request, res: Response) => {
  try {
    const { code, state } = req.query;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Authorization code is required' });
    }

    if (!state || typeof state !== 'string') {
      return res.status(400).json({ error: 'State parameter is required' });
    }

    const tokens = await exchangeCodeForToken(code, state);
    
    tokenManager.storeToken(state, tokens);

    res.json({
      message: 'Authorization successful! 🎉',
      user_id: state,
      token_type: tokens.token_type,
      expires_in: tokens.expires_in,
      expires_at: new Date(Date.now() + tokens.expires_in * 1000).toISOString(),
      next_steps: {
        search: `/search/${state}/naruto`,
        animelist: `/user/${state}/animelist`
      }
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
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
    
    const accessToken = tokenManager.getToken(userId);
    if (!accessToken) {
      return res.status(401).json({ 
        error: 'No valid access token found', 
        action: `Visit /auth/${userId} to authorize`
      });
    }

    const results = await searchAnime(query, accessToken);
    res.json({
      user_id: userId,
      query: query,
      results: results
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
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
    
    const accessToken = tokenManager.getToken(userId);
    if (!accessToken) {
      return res.status(401).json({ 
        error: 'No valid access token found', 
        action: `Visit /auth/${userId} to authorize`
      });
    }

    const animeList = await getUserAnimeList(accessToken);
    res.json({
      user_id: userId,
      anime_list: animeList
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Token management endpoints
app.get('/tokens', (req: Request, res: Response) => {
  const users = tokenManager.listUsers();
  res.json({
    message: 'Stored tokens',
    users: users,
    count: users.length
  });
});

app.delete('/tokens/:userId', (req: Request, res: Response) => {
  const { userId } = req.params;
  tokenManager.removeToken(userId);
  res.json({
    message: `Token removed for user: ${userId}`
  });
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: any) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Listen on all IP addresses (0.0.0.0)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MAL Proxy API running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Local: http://localhost:${PORT}`);
  console.log(`🌐 Network: http://0.0.0.0:${PORT}`);
  console.log(`📡 Available on all network interfaces`);
  console.log(`\n🎯 Quick Start:`);
  console.log(`   1. Visit: http://localhost:${PORT}/auth/cjemorton`);
  console.log(`   2. Authorize on MyAnimeList`);
  console.log(`   3. Test: http://localhost:${PORT}/search/cjemorton/naruto`);
});
