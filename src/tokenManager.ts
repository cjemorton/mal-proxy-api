import fs from 'fs';
import path from 'path';
import { MalTokenResponse } from './types';

const TOKEN_FILE = path.join(process.cwd(), 'tokens.json');

interface TokenStorage {
  [userId: string]: MalTokenResponse & {
    created_at: number;
    expires_at: number;
  };
}

export class TokenManager {
  private tokens: TokenStorage = {};

  constructor() {
    this.loadTokens();
  }

  private loadTokens(): void {
    try {
      if (fs.existsSync(TOKEN_FILE)) {
        const data = fs.readFileSync(TOKEN_FILE, 'utf8');
        this.tokens = JSON.parse(data);
        console.log('📁 Loaded existing tokens from file');
      }
    } catch (error) {
      console.log('⚠️ Could not load tokens file, starting fresh');
      this.tokens = {};
    }
  }

  private saveTokens(): void {
    try {
      fs.writeFileSync(TOKEN_FILE, JSON.stringify(this.tokens, null, 2));
      console.log('💾 Tokens saved to file');
    } catch (error) {
      console.error('❌ Error saving tokens:', error);
    }
  }

  storeToken(userId: string, tokens: MalTokenResponse): void {
    const now = Date.now();
    this.tokens[userId] = {
      ...tokens,
      created_at: now,
      expires_at: now + (tokens.expires_in * 1000)
    };
    this.saveTokens();
    console.log(`✅ Token stored for user: ${userId}`);
  }

  getToken(userId: string): string | null {
    const userToken = this.tokens[userId];
    if (!userToken) {
      console.log(`❌ No token found for user: ${userId}`);
      return null;
    }

    // Check if token is expired
    if (Date.now() > userToken.expires_at) {
      console.log(`⏰ Token expired for user: ${userId}`);
      delete this.tokens[userId];
      this.saveTokens();
      return null;
    }

    console.log(`✅ Valid token found for user: ${userId}`);
    return userToken.access_token;
  }

  listUsers(): string[] {
    return Object.keys(this.tokens);
  }

  removeToken(userId: string): void {
    delete this.tokens[userId];
    this.saveTokens();
    console.log(`🗑️ Token removed for user: ${userId}`);
  }
}
