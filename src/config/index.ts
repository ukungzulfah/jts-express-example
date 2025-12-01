import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config();

export const config = {
  // Server
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // JTS
  jts: {
    profile: process.env.JTS_PROFILE || 'JTS-S/v1',
    algorithm: (process.env.JTS_ALGORITHM || 'ES256') as 'ES256' | 'RS256' | 'RS384' | 'RS512' | 'ES384' | 'ES512',
    audience: process.env.JTS_AUDIENCE || 'http://localhost:3000',
    bearerPassLifetime: parseInt(process.env.JTS_BEARER_PASS_LIFETIME || '300', 10), // 5 minutes
    stateProofLifetime: parseInt(process.env.JTS_STATE_PROOF_LIFETIME || '604800', 10), // 7 days
    privateKeyPath: path.resolve(process.env.JTS_PRIVATE_KEY_PATH || './keys/signing-key.pem'),
    publicKeyPath: path.resolve(process.env.JTS_PUBLIC_KEY_PATH || './keys/signing-key.pub.pem'),
  },
};
