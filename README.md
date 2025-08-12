# MyAnimeList Proxy API

A Node.js/TypeScript proxy API for the MyAnimeList API with OAuth2 authentication.

## Features

- OAuth2 flow for MyAnimeList authentication
- Anime search functionality
- User anime list retrieval
- TypeScript support
- CORS enabled
- Error handling

## Setup Instructions

### 1. Clone and Install

```bash
git clone <your-repo-url>
cd mal-proxy-api
npm install
```

### 2. Environment Configuration

Create a `.env` file with your MyAnimeList app credentials:

```env
MAL_CLIENT_ID=your_client_id
MAL_CLIENT_SECRET=your_client_secret
MAL_REDIRECT_URI=https://mal.mrnet.work/callback
PORT=3000
NODE_ENV=development
```

### 3. Run the Application

**Development:**
```bash
npm run dev
```

**Production:**
```bash
npm run build
npm start
```

## API Endpoints

### Authentication Flow

1. **Start OAuth2 Flow**
   ```
   GET /auth
   ```
   Redirects to MyAnimeList authorization page.

2. **OAuth2 Callback**
   ```
   GET /callback?code=AUTHORIZATION_CODE
   ```
   Exchanges authorization code for access token.

### API Endpoints (Require Authentication)

3. **Search Anime**
   ```
   GET /search/:query
   ```
   Example: `GET /search/naruto`

4. **Get User's Anime List**
   ```
   GET /user/animelist
   ```

## Usage Flow

1. Visit `http://localhost:3000/auth` to start authentication
2. Authorize the app on MyAnimeList
3. You'll be redirected to the callback URL with tokens stored
4. Use the search and user list endpoints

## Production Considerations

- Replace in-memory token storage with a database
- Implement proper user session management
- Add token refresh logic
- Add rate limiting
- Use HTTPS in production
- Implement proper logging

## Troubleshooting

- Ensure your MyAnimeList app is properly configured
- Check that your redirect URI matches exactly
- Verify environment variables are set correctly
