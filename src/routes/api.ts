import { Router, Request, Response } from 'express';
import { authenticate, requirePermissions } from '../middleware/auth';
import { findUserById } from '../users';

const router = Router();

/**
 * GET /api/profile
 * Get current user's profile
 */
router.get('/profile', authenticate, (req: Request, res: Response) => {
  const userId = req.jts?.payload.prn;
  
  if (!userId) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'User not authenticated',
    });
  }
  
  const user = findUserById(userId);
  
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

/**
 * GET /api/admin
 * Admin-only endpoint
 */
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

/**
 * GET /api/public
 * Public endpoint (no auth required)
 */
router.get('/public', (req: Request, res: Response) => {
  res.json({
    message: 'This is a public endpoint',
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/health
 * Health check endpoint
 */
router.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

export default router;
