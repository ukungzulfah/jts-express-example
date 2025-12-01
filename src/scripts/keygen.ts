import { generateECKeyPair } from '@engjts/auth';
import * as fs from 'fs';
import * as path from 'path';

async function generateKeys() {
  const keysDir = path.join(process.cwd(), 'keys');
  
  // Create keys directory if not exists
  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
    console.log('📁 Created keys directory');
  }
  
  // Generate key pair
  const keyId = `jts-key-${new Date().getFullYear()}`;
  console.log(`🔑 Generating ES256 key pair with ID: ${keyId}...`);
  
  const keyPair = await generateECKeyPair(keyId, 'ES256');
  
  if (!keyPair.privateKey || !keyPair.publicKey) {
    throw new Error('Failed to generate key pair');
  }
  
  // Save private key
  const privateKeyPath = path.join(keysDir, 'signing-key.pem');
  fs.writeFileSync(privateKeyPath, keyPair.privateKey);
  console.log(`✅ Private key saved to: ${privateKeyPath}`);
  
  // Save public key
  const publicKeyPath = path.join(keysDir, 'signing-key.pub.pem');
  fs.writeFileSync(publicKeyPath, keyPair.publicKey);
  console.log(`✅ Public key saved to: ${publicKeyPath}`);
  
  console.log('\n🎉 Key generation complete!');
  console.log('⚠️  Remember: NEVER commit your private key to version control!');
}

generateKeys().catch(console.error);
