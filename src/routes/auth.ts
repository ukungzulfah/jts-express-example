import { Router, Request, Response } from 'express';
import { authServer } from '../jts';
import { findUserByEmail, validatePassword } from '../users';
import { csrfCheck, authenticate } from '../middleware/auth';

const router = Router();

/**
 * POST /jts/login
 * Login endpoint - returns BearerPass and StateProof
 */
router.post('/login', csrfCheck, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        error: 'invalid_request',
        message: 'Email and password are required',
      });
    }
    
    // Find user
    const user = findUserByEmail(email);
    if (!user) {
      return res.status(401).json({
        error: 'invalid_credentials',
        message: 'Invalid email or password',
      });
    }
    
    // Validate password
    if (!validatePassword(user, password)) {
      return res.status(401).json({
        error: 'invalid_credentials',
        message: 'Invalid email or password',
      });
    }
    
    // Generate tokens using JTS
    const tokens = await authServer.login({
      prn: user.id,
      permissions: user.permissions,
      metadata: {
        email: user.email,
        name: user.name,
      },
    });
    
    // Set StateProof as HttpOnly cookie
    res.cookie('jts_state_proof', tokens.stateProof, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    
    // Return BearerPass in response body
    res.json({
      bearerPass: tokens.bearerPass,
      expiresIn: 300, // 5 minutes
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

/**
 * POST /jts/renew
 * Renew BearerPass using StateProof
 */
router.post('/renew', csrfCheck, async (req: Request, res: Response) => {
  try {
    const stateProof = req.cookies?.jts_state_proof || req.body.stateProof;
    
    if (!stateProof) {
      return res.status(401).json({
        error: 'missing_state_proof',
        message: 'StateProof is required for renewal',
      });
    }
    
    // Renew tokens
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
    console.error('Renew error:', error);
    
    if (error.errorCode) {
      return res.status(error.httpStatus || 401).json(error.toJSON());
    }
    
    res.status(500).json({
      error: 'server_error',
      message: 'An error occurred during token renewal',
    });
  }
});

/**
 * POST /jts/logout
 * Logout - invalidate session
 */
router.post('/logout', csrfCheck, authenticate, async (req: Request, res: Response) => {
  try {
    const stateProof = req.cookies?.jts_state_proof;
    
    if (stateProof) {
      await authServer.logout(stateProof);
    }
    
    // Clear cookie
    res.clearCookie('jts_state_proof');
    
    res.json({
      message: 'Logged out successfully',
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: 'server_error',
      message: 'An error occurred during logout',
    });
  }
});

/**
 * GET /jts/.well-known/jwks.json
 * JWKS endpoint for public keys
 */
router.get('/.well-known/jwks.json', (req: Request, res: Response) => {
  const jwks = authServer.getJWKS();
  res.json(jwks);
});

export default router;
