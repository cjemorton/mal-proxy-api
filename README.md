# MAL Proxy API

A simple Node.js proxy for the MyAnimeList API.

## Setup

1. Clone this repo and enter the directory.
2. Create a `.env` file with your MAL credentials:

    ```
    MAL_CLIENT_ID=your_client_id
    MAL_CLIENT_SECRET=your_client_secret
    MAL_REDIRECT_URI=https://mal.mrnet.work/callback
    PORT=3000
    ```

3. Install dependencies:

    ```
    npm install
    ```

4. Run in development:

    ```
    npm run dev
    ```

## Usage

- Visit `/auth` to start the OAuth2 flow.
- The callback endpoint `/callback` will exchange the code for tokens.
- Use `/mal/:endpoint` to proxy requests to MAL, e.g. `/mal/anime?q=naruto`

## To Do

- Store/retrieve tokens securely (database, file, etc.)
- Implement refresh token logic.
- Add more proxy endpoints as needed.
