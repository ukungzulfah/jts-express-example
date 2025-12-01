import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config';
import { jtsErrorHandler } from './middleware/auth';
import authRoutes from './routes/auth';
import apiRoutes from './routes/api';

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS (configure for your frontend domain in production)
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
    endpoints: {
      auth: {
        login: 'POST /jts/login',
        renew: 'POST /jts/renew',
        logout: 'POST /jts/logout',
        jwks: 'GET /jts/.well-known/jwks.json',
      },
      api: {
        profile: 'GET /api/profile (requires auth)',
        admin: 'GET /api/admin (requires admin:access)',
        public: 'GET /api/public',
        health: 'GET /api/health',
      },
    },
  });
});

// JTS Error Handler
app.use(jtsErrorHandler);

// Generic Error Handler
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'server_error',
    message: config.nodeEnv === 'development' ? err.message : 'Internal server error',
  });
});

// Start server
app.listen(config.port, () => {
  console.log(`\n🚀 JTS Express Server running on http://localhost:${config.port}`);
  console.log(`📖 API Documentation: http://localhost:${config.port}/`);
  console.log('\n📋 Test Commands:');
  console.log(`
# Login
curl -X POST http://localhost:${config.port}/jts/login \\
  -H "Content-Type: application/json" \\
  -H "X-JTS-Request: 1" \\
  -d '{"email":"admin@example.com","password":"admin123"}'

# Get Profile (replace <token> with bearerPass from login response)
curl http://localhost:${config.port}/api/profile \\
  -H "Authorization: Bearer <token>"

# Admin Endpoint
curl http://localhost:${config.port}/api/admin \\
  -H "Authorization: Bearer <token>"
  `);
});

export default app;
