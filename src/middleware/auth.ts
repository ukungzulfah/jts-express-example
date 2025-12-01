import { Request, Response, NextFunction } from 'express';
import { jtsAuth, jtsRequirePermissions, JTSError, JTSPayload, JTSHeader } from '@engjts/auth';
import { resourceServer } from '../jts';

// Extend Express Request type with JTS context
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

// JTS Authentication Middleware
export const authenticate = jtsAuth({ resourceServer });

// Optional Authentication (doesn't fail if no token)
export const optionalAuth = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }
  
  // If token exists, validate it
  authenticate(req, res, next);
};

// Permission Check Middleware Factory
export const requirePermissions = (permissions: string[]) => {
  return jtsRequirePermissions({ required: permissions });
};

// CSRF Check Middleware (required for mutating endpoints)
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

// Error Handler for JTS Errors
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
