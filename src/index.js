import express from "express";
import dotenv from "dotenv";
import { malAuthUrl, handleOAuthCallback, proxyMalRequest } from "./malClient";

dotenv.config();

const app = express();
app.use(express.json());

// Redirect to MyAnimeList OAuth2 authorization
app.get("/auth", (req, res) => {
  res.redirect(malAuthUrl());
});

// Handle OAuth2 callback
app.get("/callback", async (req, res) => {
  try {
    const code = req.query.code as string;
    const tokens = await handleOAuthCallback(code);
    // Save tokens securely in your production app
    res.json(tokens);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Example proxy endpoint: Forward request to MAL API
app.get("/mal/:endpoint", async (req, res) => {
  try {
    const endpoint = req.params.endpoint;
    const result = await proxyMalRequest(endpoint, req.query);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
