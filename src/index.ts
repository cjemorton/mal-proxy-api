import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { generateAuthUrl, exchangeCodeForToken, searchAnime, getUserAnimeList } from './malClient';
import { MalTokenResponse } from './types';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory token storage (replace with database in production)
let userTokens: { [userId: string]: MalTokenResponse } = {};

// Routes
app.get('/', (req: Request, res: Response) => {
  res.json({
    message: 'MyAnimeList Proxy API',
    endpoints: {
      '/auth': 'Start OAuth2 flow',
      '/callback': 'OAuth2 callback',
      '/search/:query': 'Search anime (requires token)',
      '/user/animelist': 'Get user anime list (requires token)'
    }
  });
});

app.get('/auth', (req: Request, res: Response) => {
  try {
    const authUrl = generateAuthUrl();
    res.redirect(authUrl);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/callback', async (req: Request, res: Response) => {
  try {
    const { code } = req.query;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Authorization code is required' });
    }

    const tokens = await exchangeCodeForToken(code);
    
    // Store tokens (in production, use proper user identification and secure storage)
    const userId = 'default_user'; // Replace with actual user ID
    userTokens[userId] = tokens;

    res.json({
      message: 'Authorization successful',
      token_type: tokens.token_type,
      expires_in: tokens.expires_in,
      // Don't expose the actual tokens in the response for security
      access_token: '***STORED***',
      refresh_token: '***STORED***'
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/search/:query', async (req: Request, res: Response) => {
  try {
    const { query } = req.params;
    const userId = 'default_user'; // Replace with actual user ID
    
    const userToken = userTokens[userId];
    if (!userToken) {
      return res.status(401).json({ error: 'No access token found. Please authorize first via /auth' });
    }

    const results = await searchAnime(query, userToken.access_token);
    res.json(results);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/user/animelist', async (req: Request, res: Response) => {
  try {
    const userId = 'default_user'; // Replace with actual user ID
    
    const userToken = userTokens[userId];
    if (!userToken) {
      return res.status(401).json({ error: 'No access token found. Please authorize first via /auth' });
    }

    const animeList = await getUserAnimeList(userToken.access_token);
    res.json(animeList);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
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
  console.log(`🔗 Local: http://localhost:${PORT}/auth`);
  console.log(`🌐 Network: http://0.0.0.0:${PORT}/auth`);
  console.log(`📡 Available on all network interfaces`);
});
