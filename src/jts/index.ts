import { JTSAuthServer, JTSResourceServer, InMemorySessionStore } from '@engjts/auth';
import * as fs from 'fs';
import { config } from '../config';

// In-memory session store (use Redis/PostgreSQL for production)
const sessionStore = new InMemorySessionStore();

// Load signing key
function loadSigningKey() {
  try {
    const privateKey = fs.readFileSync(config.jts.privateKeyPath, 'utf-8');
    const publicKey = fs.readFileSync(config.jts.publicKeyPath, 'utf-8');
    
    return {
      kid: `jts-key-${new Date().getFullYear()}`,
      algorithm: config.jts.algorithm,
      privateKey,
      publicKey,
    };
  } catch (error) {
    console.error('❌ Failed to load signing keys. Run "npm run keygen" first.');
    process.exit(1);
  }
}

const signingKey = loadSigningKey();

// Create Auth Server
export const authServer = new JTSAuthServer({
  profile: config.jts.profile as 'JTS-L/v1' | 'JTS-S/v1' | 'JTS-C/v1',
  signingKey,
  bearerPassLifetime: config.jts.bearerPassLifetime,
  stateProofLifetime: config.jts.stateProofLifetime,
  sessionStore,
  audience: config.jts.audience,
});

// Create Resource Server
export const resourceServer = new JTSResourceServer({
  publicKeys: [signingKey],
  audience: config.jts.audience,
});

console.log('✅ JTS Auth Server initialized');
console.log(`   Profile: ${config.jts.profile}`);
console.log(`   Algorithm: ${config.jts.algorithm}`);
console.log(`   BearerPass Lifetime: ${config.jts.bearerPassLifetime}s`);
console.log(`   StateProof Lifetime: ${config.jts.stateProofLifetime}s`);
