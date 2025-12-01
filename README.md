# JTS Express Server

A production-ready Express.js server with TypeScript implementing the **Janus Token System (JTS)** - a two-component authentication architecture for secure, revocable, and stateless API authentication.

This project uses **@engjts/auth**, a modern implementation of JTS that provides enhanced security and performance over the original jts-core package.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Project Structure](#project-structure)
5. [Configuration](#configuration)
6. [Step-by-Step Implementation Guide](#step-by-step-implementation-guide)
7. [API Reference](#api-reference)
8. [Testing](#testing)
9. [Security Considerations](#security-considerations)
10. [Production Recommendations](#production-recommendations)

---

## Overview

### What is JTS?

Janus Token System (JTS) is a modern authentication architecture that separates authentication into two components:

- **BearerPass**: A short-lived token (default: 5 minutes) used in the `Authorization` header for API requests. It contains user identity, permissions, and is cryptographically signed.

- **StateProof**: A long-lived token (default: 7 days) stored as an HttpOnly cookie. It serves as a session anchor for token renewal and revocation.

### Package: @engjts/auth

This implementation uses **@engjts/auth**, an enterprise-grade authentication library built on JTS. It provides:

- Full JTS specification compliance
- Type-safe TypeScript support
- High performance cryptographic operations
- Battle-tested session management
- Production-ready error handling

### Why JTS?

| Traditional JWT | JTS Approach |
|-----------------|--------------|
| Long-lived tokens are security risks | Short-lived BearerPass minimizes exposure |
| Revocation requires blacklists | Instant revocation via StateProof invalidation |
| Stateless but not revocable | Stateless verification with revocable sessions |
| Single token handles everything | Separation of concerns for better security |

### JTS Profiles

This implementation uses **JTS-S (Standard)** profile:

| Profile | Use Case | StateProof Rotation | Replay Detection | Encryption |
|---------|----------|---------------------|------------------|------------|
| JTS-L (Lite) | MVP, Internal Tools | Optional | No | No |
| JTS-S (Standard) | Production Apps | Required | Yes | No |
| JTS-C (Confidentiality) | Fintech, Healthcare | Required | Yes | Yes (JWE) |

---

## Prerequisites

- Node.js 18.x or higher
- npm 9.x or higher
- Basic understanding of Express.js and TypeScript

---

## Installation

### Step 1: Clone or Initialize Project

```bash
mkdir jts-express-server
cd jts-express-server
```

### Step 2: Install Dependencies

```bash
npm install express @engjts/auth dotenv cookie-parser
npm install -D typescript ts-node-dev ts-node @types/express @types/node @types/cookie-parser
```

### Step 3: Generate Signing Keys

The server requires asymmetric key pairs for token signing. Generate them using the built-in script:

```bash
npm run keygen
```

This creates two files in the `keys/` directory:
- `signing-key.pem` - Private key (keep secret, never commit)
- `signing-key.pub.pem` - Public key (can be distributed)

### Step 4: Configure Environment

Copy the example environment file and adjust as needed:

```bash
cp .env.example .env
```

### Step 5: Start Development Server

```bash
npm run dev
```

The server will start at `http://localhost:3000`.

---

## Project Structure

```
jts-express-server/
├── src/
│   ├── config/
│   │   └── index.ts          # Environment configuration
│   ├── jts/
│   │   └── index.ts          # JTS Auth & Resource server setup
│   ├── middleware/
│   │   └── auth.ts           # Authentication middleware
│   ├── routes/
│   │   ├── auth.ts           # Authentication endpoints
│   │   └── api.ts            # Protected API endpoints
│   ├── scripts/
│   │   └── keygen.ts         # Key generation utility
│   ├── users/
│   │   └── index.ts          # User management (demo)
│   └── index.ts              # Application entry point
├── keys/                      # Signing keys (gitignored)
├── .env                       # Environment variables
├── .env.example               # Environment template
├── .gitignore
├── package.json
├── tsconfig.json
└── README.md
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `NODE_ENV` | Environment mode | `development` |
| `JTS_PROFILE` | JTS profile (`JTS-L/v1`, `JTS-S/v1`, `JTS-C/v1`) | `JTS-S/v1` |
| `JTS_ALGORITHM` | Signing algorithm | `ES256` |
| `JTS_AUDIENCE` | Token audience (your API URL) | `http://localhost:3000` |
| `JTS_BEARER_PASS_LIFETIME` | BearerPass lifetime in seconds | `300` (5 min) |
| `JTS_STATE_PROOF_LIFETIME` | StateProof lifetime in seconds | `604800` (7 days) |
| `JTS_PRIVATE_KEY_PATH` | Path to private key | `./keys/signing-key.pem` |
| `JTS_PUBLIC_KEY_PATH` | Path to public key | `./keys/signing-key.pub.pem` |

### Supported Algorithms

- **EC (Recommended)**: `ES256`, `ES384`, `ES512`
- **RSA**: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`

ES256 is recommended for its smaller key size and faster performance.

---

## Step-by-Step Implementation Guide

### Step 1: TypeScript Configuration

Create `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

### Step 2: Environment Configuration

Create `src/config/index.ts`:

```typescript
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  
  jts: {
    profile: process.env.JTS_PROFILE || 'JTS-S/v1',
    algorithm: (process.env.JTS_ALGORITHM || 'ES256') as 'ES256' | 'RS256',
    audience: process.env.JTS_AUDIENCE || 'http://localhost:3000',
    bearerPassLifetime: parseInt(process.env.JTS_BEARER_PASS_LIFETIME || '300', 10),
    stateProofLifetime: parseInt(process.env.JTS_STATE_PROOF_LIFETIME || '604800', 10),
    privateKeyPath: path.resolve(process.env.JTS_PRIVATE_KEY_PATH || './keys/signing-key.pem'),
    publicKeyPath: path.resolve(process.env.JTS_PUBLIC_KEY_PATH || './keys/signing-key.pub.pem'),
  },
};
```

### Step 3: JTS Server Setup

Create `src/jts/index.ts`:

```typescript
import { JTSAuthServer, JTSResourceServer, InMemorySessionStore } from '@engjts/auth';
import * as fs from 'fs';
import { config } from '../config';

// Session store - use Redis or PostgreSQL in production
const sessionStore = new InMemorySessionStore();

// Load signing keys from files
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
    console.error('Failed to load signing keys. Run "npm run keygen" first.');
    process.exit(1);
  }
}

const signingKey = loadSigningKey();

// Auth Server: Handles login, token generation, renewal, and logout
export const authServer = new JTSAuthServer({
  profile: config.jts.profile as 'JTS-L/v1' | 'JTS-S/v1' | 'JTS-C/v1',
  signingKey,
  bearerPassLifetime: config.jts.bearerPassLifetime,
  stateProofLifetime: config.jts.stateProofLifetime,
  sessionStore,
  audience: config.jts.audience,
});

// Resource Server: Verifies tokens on protected endpoints
export const resourceServer = new JTSResourceServer({
  publicKeys: [signingKey],
  audience: config.jts.audience,
});
```

**Key Concepts:**

- `JTSAuthServer`: Responsible for issuing tokens, renewing sessions, and handling logout
- `JTSResourceServer`: Responsible for verifying BearerPass tokens on API requests
- `InMemorySessionStore`: Stores session data (replace with Redis/PostgreSQL in production)

### Step 4: Authentication Middleware

Create `src/middleware/auth.ts`:

```typescript
import { Request, Response, NextFunction } from 'express';
import { jtsAuth, jtsRequirePermissions, JTSError, JTSPayload, JTSHeader } from '@engjts/auth';
import { resourceServer } from '../jts';

// Extend Express Request with JTS context
declare global {
  namespace Express {
    interface Request {
      jts?: {
        payload: JTSPayload;
        header: JTSHeader;
        bearerPass: string;
      };
    }
  }
}

// Main authentication middleware
// Validates BearerPass from Authorization header
export const authenticate = jtsAuth({ resourceServer });

// Permission-based access control
// Usage: requirePermissions(['admin:access', 'write:posts'])
export const requirePermissions = (permissions: string[]) => {
  return jtsRequirePermissions({ required: permissions });
};

// CSRF protection for mutating endpoints
// All POST/PUT/DELETE requests to /jts/* require X-JTS-Request: 1 header
export const csrfCheck = (req: Request, res: Response, next: NextFunction) => {
  const csrfHeader = req.headers['x-jts-request'];
  
  if (csrfHeader !== '1') {
    return res.status(403).json({
      error: 'csrf_missing',
      message: 'X-JTS-Request header is required',
    });
  }
  
  next();
};

// JTS-specific error handler
export const jtsErrorHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err instanceof JTSError) {
    return res.status(err.httpStatus).json(err.toJSON());
  }
  
  next(err);
};
```

**Important:** After successful authentication, the user's information is available in `req.jts.payload`:

```typescript
req.jts.payload.prn    // Principal (user ID)
req.jts.payload.perm   // Permissions array
req.jts.payload.exp    // Expiration timestamp
req.jts.payload.aud    // Audience
```

### Step 5: Authentication Routes

Create `src/routes/auth.ts`:

```typescript
import { Router, Request, Response } from 'express';
import { authServer } from '../jts';
import { findUserByEmail, validatePassword } from '../users';
import { csrfCheck, authenticate } from '../middleware/auth';

const router = Router();

// POST /jts/login
// Authenticates user and returns BearerPass + sets StateProof cookie
router.post('/login', csrfCheck, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        error: 'invalid_request',
        message: 'Email and password are required',
      });
    }
    
    // Validate credentials (replace with your auth logic)
    const user = findUserByEmail(email);
    if (!user || !validatePassword(user, password)) {
      return res.status(401).json({
        error: 'invalid_credentials',
        message: 'Invalid email or password',
      });
    }
    
    // Generate tokens
    const tokens = await authServer.login({
      prn: user.id,                    // Principal (user identifier)
      permissions: user.permissions,    // User's permissions
      metadata: {                       // Optional metadata
        email: user.email,
        name: user.name,
      },
    });
    
    // Set StateProof as HttpOnly cookie (not accessible via JavaScript)
    res.cookie('jts_state_proof', tokens.stateProof, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    
    // Return BearerPass in response body
    res.json({
      bearerPass: tokens.bearerPass,
      expiresIn: 300,
      tokenType: 'Bearer',
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'server_error',
      message: 'An error occurred during login',
    });
  }
});

// POST /jts/renew
// Renews BearerPass using StateProof from cookie
router.post('/renew', csrfCheck, async (req: Request, res: Response) => {
  try {
    const stateProof = req.cookies?.jts_state_proof || req.body.stateProof;
    
    if (!stateProof) {
      return res.status(401).json({
        error: 'missing_state_proof',
        message: 'StateProof is required for renewal',
      });
    }
    
    const tokens = await authServer.renew(stateProof);
    
    // Update StateProof cookie if rotated
    if (tokens.stateProof) {
      res.cookie('jts_state_proof', tokens.stateProof, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
    }
    
    res.json({
      bearerPass: tokens.bearerPass,
      expiresIn: 300,
      tokenType: 'Bearer',
    });
  } catch (error: any) {
    if (error.errorCode) {
      return res.status(error.httpStatus || 401).json(error.toJSON());
    }
    res.status(500).json({
      error: 'server_error',
      message: 'An error occurred during token renewal',
    });
  }
});

// POST /jts/logout
// Invalidates session and clears StateProof cookie
router.post('/logout', csrfCheck, authenticate, async (req: Request, res: Response) => {
  try {
    const stateProof = req.cookies?.jts_state_proof;
    
    if (stateProof) {
      await authServer.logout(stateProof);
    }
    
    res.clearCookie('jts_state_proof');
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({
      error: 'server_error',
      message: 'An error occurred during logout',
    });
  }
});

// GET /jts/.well-known/jwks.json
// Public endpoint for JWKS (JSON Web Key Set)
router.get('/.well-known/jwks.json', (req: Request, res: Response) => {
  const jwks = authServer.getJWKS();
  res.json(jwks);
});

export default router;
```

### Step 6: Protected API Routes

Create `src/routes/api.ts`:

```typescript
import { Router, Request, Response } from 'express';
import { authenticate, requirePermissions } from '../middleware/auth';
import { findUserById } from '../users';

const router = Router();

// GET /api/profile
// Requires authentication
router.get('/profile', authenticate, (req: Request, res: Response) => {
  const userId = req.jts?.payload.prn;
  const user = findUserById(userId!);
  
  if (!user) {
    return res.status(404).json({
      error: 'not_found',
      message: 'User not found',
    });
  }
  
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    permissions: req.jts?.payload.perm,
  });
});

// GET /api/admin
// Requires authentication + admin:access permission
router.get(
  '/admin',
  authenticate,
  requirePermissions(['admin:access']),
  (req: Request, res: Response) => {
    res.json({
      message: 'Welcome to the admin area!',
      user: req.jts?.payload.prn,
      timestamp: new Date().toISOString(),
    });
  }
);

// GET /api/public
// No authentication required
router.get('/public', (req: Request, res: Response) => {
  res.json({
    message: 'This is a public endpoint',
    timestamp: new Date().toISOString(),
  });
});

// GET /api/health
// Health check endpoint
router.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

export default router;
```

### Step 7: Application Entry Point

Create `src/index.ts`:

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config';
import { jtsErrorHandler } from './middleware/auth';
import authRoutes from './routes/auth';
import apiRoutes from './routes/api';

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS configuration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-JTS-Request');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Routes
app.use('/jts', authRoutes);
app.use('/api', apiRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'JTS Express Server',
    version: '1.0.0',
  });
});

// Error handlers
app.use(jtsErrorHandler);
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'server_error',
    message: config.nodeEnv === 'development' ? err.message : 'Internal server error',
  });
});

// Start server
app.listen(config.port, () => {
  console.log(`Server running on http://localhost:${config.port}`);
});

export default app;
```

### Step 8: User Management (Demo)

Create `src/users/index.ts`:

```typescript
export interface User {
  id: string;
  email: string;
  password: string;
  name: string;
  permissions: string[];
}

// Demo users - replace with database in production
const users: User[] = [
  {
    id: 'user-001',
    email: 'admin@example.com',
    password: 'admin123',  // Use bcrypt in production!
    name: 'Admin User',
    permissions: ['read:profile', 'write:profile', 'admin:access'],
  },
  {
    id: 'user-002',
    email: 'user@example.com',
    password: 'user123',
    name: 'Regular User',
    permissions: ['read:profile'],
  },
];

export function findUserByEmail(email: string): User | undefined {
  return users.find((u) => u.email === email);
}

export function findUserById(id: string): User | undefined {
  return users.find((u) => u.id === id);
}

export function validatePassword(user: User, password: string): boolean {
  return user.password === password;  // Use bcrypt.compare in production!
}
```

### Step 9: Key Generation Script

Create `src/scripts/keygen.ts`:

```typescript
import { generateECKeyPair } from '@engjts/auth';
import * as fs from 'fs';
import * as path from 'path';

async function generateKeys() {
  const keysDir = path.join(process.cwd(), 'keys');
  
  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }
  
  const keyId = `jts-key-${new Date().getFullYear()}`;
  const keyPair = await generateECKeyPair(keyId, 'ES256');
  
  if (!keyPair.privateKey || !keyPair.publicKey) {
    throw new Error('Failed to generate key pair');
  }
  
  fs.writeFileSync(path.join(keysDir, 'signing-key.pem'), keyPair.privateKey);
  fs.writeFileSync(path.join(keysDir, 'signing-key.pub.pem'), keyPair.publicKey);
  
  console.log('Key generation complete!');
  console.log('WARNING: Never commit your private key to version control!');
}

generateKeys().catch(console.error);
```

---

## API Reference

### Authentication Endpoints

#### POST /jts/login

Authenticate user and obtain tokens.

**Headers:**
```
Content-Type: application/json
X-JTS-Request: 1
```

**Request Body:**
```json
{
  "email": "admin@example.com",
  "password": "admin123"
}
```

**Response:**
```json
{
  "bearerPass": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoianRzLWtleS0yMDI1In0...",
  "expiresIn": 300,
  "tokenType": "Bearer"
}
```

**Cookie Set:**
```
Set-Cookie: jts_state_proof=<token>; HttpOnly; Secure; SameSite=Strict
```

#### POST /jts/renew

Renew BearerPass using StateProof.

**Headers:**
```
X-JTS-Request: 1
Cookie: jts_state_proof=<token>
```

**Response:**
```json
{
  "bearerPass": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpUUy1TL3YxIiwia2lkIjoianRzLWtleS0yMDI1In0...",
  "expiresIn": 300,
  "tokenType": "Bearer"
}
```

#### POST /jts/logout

Invalidate session and clear cookies.

**Headers:**
```
Authorization: Bearer <bearerPass>
X-JTS-Request: 1
Cookie: jts_state_proof=<token>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

#### GET /jts/.well-known/jwks.json

Get public keys for token verification.

**Response:**
```json
{
  "keys": [
    {
      "kty": "EC",
      "kid": "jts-key-2025",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  ]
}
```

### Protected Endpoints

#### GET /api/profile

Get current user's profile.

**Headers:**
```
Authorization: Bearer <bearerPass>
```

**Response:**
```json
{
  "id": "user-001",
  "email": "admin@example.com",
  "name": "Admin User",
  "permissions": ["read:profile", "write:profile", "admin:access"]
}
```

#### GET /api/admin

Access admin-only area.

**Headers:**
```
Authorization: Bearer <bearerPass>
```

**Required Permission:** `admin:access`

**Response:**
```json
{
  "message": "Welcome to the admin area!",
  "user": "user-001",
  "timestamp": "2025-12-01T02:24:24.037Z"
}
```

### Error Responses

JTS uses standardized error codes:

| Code | Key | Description | Action |
|------|-----|-------------|--------|
| JTS-400-01 | malformed_token | Token cannot be parsed | Reauthenticate |
| JTS-400-02 | missing_claims | Required claims missing | Reauthenticate |
| JTS-401-01 | bearer_expired | BearerPass has expired | Renew token |
| JTS-401-02 | signature_invalid | Signature verification failed | Reauthenticate |
| JTS-401-03 | stateproof_invalid | StateProof not found/invalid | Reauthenticate |
| JTS-401-04 | session_terminated | Session ended (logout) | Reauthenticate |
| JTS-401-05 | session_compromised | Replay attack detected | Reauthenticate |
| JTS-403-01 | audience_mismatch | Wrong audience | None |
| JTS-403-02 | permission_denied | Missing permissions | None |

**Error Response Format:**
```json
{
  "error": "bearer_expired",
  "error_code": "JTS-401-01",
  "message": "BearerPass has expired",
  "action": "renew",
  "retry_after": 0,
  "timestamp": 1764555468
}
```

---

## Testing

### Test Users

| Email | Password | Permissions |
|-------|----------|-------------|
| admin@example.com | admin123 | read:profile, write:profile, admin:access |
| user@example.com | user123 | read:profile |

### Test Commands

**1. Login as Admin:**
```bash
curl -X POST http://localhost:3000/jts/login \
  -H "Content-Type: application/json" \
  -H "X-JTS-Request: 1" \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

**2. Login as Regular User:**
```bash
curl -X POST http://localhost:3000/jts/login \
  -H "Content-Type: application/json" \
  -H "X-JTS-Request: 1" \
  -d '{"email":"user@example.com","password":"user123"}'
```

**3. Access Protected Endpoint:**
```bash
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer <TOKEN>"
```

**4. Access Admin Area:**
```bash
curl http://localhost:3000/api/admin \
  -H "Authorization: Bearer <TOKEN>"
```

**5. Access Public Endpoint:**
```bash
curl http://localhost:3000/api/public
```

**6. Get JWKS:**
```bash
curl http://localhost:3000/jts/.well-known/jwks.json
```

### Test Results (Verified)

| Test Case | Expected Result | Status |
|-----------|-----------------|--------|
| Login Admin | Returns BearerPass | PASS |
| Login User | Returns BearerPass | PASS |
| Get Profile (Admin) | Returns user data | PASS |
| Admin Area (Admin Token) | Access granted | PASS |
| Admin Area (User Token) | JTS-403-02 Permission denied | PASS |
| Public Endpoint | No auth required | PASS |
| Profile without Token | JTS-401-03 Reauth required | PASS |
| Wrong Password | Invalid credentials error | PASS |
| Login without CSRF | CSRF missing error | PASS |
| JWKS Endpoint | Returns public keys | PASS |

---

## Security Considerations

### CSRF Protection

All mutating endpoints (`/jts/login`, `/jts/renew`, `/jts/logout`) require the `X-JTS-Request: 1` header. This prevents cross-site request forgery attacks.

### Token Storage

- **BearerPass**: Store in memory (JavaScript variable). Never store in localStorage.
- **StateProof**: Automatically stored as HttpOnly cookie (not accessible via JavaScript).

### Token Lifetime

- **BearerPass**: 5 minutes (configurable). Short lifetime limits exposure window.
- **StateProof**: 7 days (configurable). Used only for renewal, not API access.

### Key Management

- Private keys must never be committed to version control
- Rotate keys periodically (recommended: annually)
- Use different keys for different environments

---

## Production Recommendations

### 1. Use Production Session Store

Replace `InMemorySessionStore` with Redis or PostgreSQL:

```typescript
import { RedisSessionStore } from '@engjts/auth';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);
const sessionStore = new RedisSessionStore({
  client: redis,
  keyPrefix: 'jts:',
});
```

### 2. Implement Password Hashing

```typescript
import bcrypt from 'bcrypt';

// Hash password before storing
const hashedPassword = await bcrypt.hash(password, 12);

// Verify password
const isValid = await bcrypt.compare(password, user.hashedPassword);
```

### 3. Configure CORS Properly

```typescript
app.use(cors({
  origin: 'https://your-frontend-domain.com',
  credentials: true,
}));
```

### 4. Enable HTTPS

Always use HTTPS in production. The `Secure` flag on cookies requires HTTPS.

### 5. Implement Rate Limiting

```typescript
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
});

app.use('/jts/login', loginLimiter);
```

### 6. Add Request Logging

Use a logging library like Winston or Pino for production logging.

### 7. Key Rotation

Implement a key rotation strategy:
1. Generate new key pair
2. Add new key to `publicKeys` array
3. Update `signingKey` to use new key
4. Remove old key after grace period

---

## Resources

- [EnGJTS Auth on npm](https://www.npmjs.com/package/@engjts/auth)
- [EnGJTS Auth on GitHub](https://github.com/engjts/auth)
- [JTS Specification](https://github.com/ukungzulfah/jts-spec/blob/main/JTS_Specification_v1-en.md)

---

## License

MIT License
