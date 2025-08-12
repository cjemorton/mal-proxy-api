import crypto from 'crypto';

function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Test PKCE generation
const verifier = generateCodeVerifier();
const challenge = generateCodeChallenge(verifier);

console.log('🔧 PKCE Test:');
console.log(`Code Verifier: ${verifier}`);
console.log(`Code Verifier Length: ${verifier.length}`);
console.log(`Code Challenge: ${challenge}`);
console.log(`Code Challenge Length: ${challenge.length}`);

// Test if we can recreate the challenge from the verifier
const recreatedChallenge = generateCodeChallenge(verifier);
console.log(`Challenges Match: ${challenge === recreatedChallenge}`);
