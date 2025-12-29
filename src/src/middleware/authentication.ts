/**
 * Authentication Middleware
 *
 * JWT-based authentication with RBAC (Role-Based Access Control)
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import {
  UnauthorizedError,
  InvalidTokenError,
  ForbiddenError,
  InsufficientPermissionsError
} from '../errors/custom-errors';
import { AuthContext, JWTPayload, UserRole } from '../types';
import { logger, logSecurityEvent } from '../utils/logger';
import config from '../config';

/**
 * Extend Express Request to include user context
 */
declare global {
  namespace Express {
    interface Request {
      user?: AuthContext;
    }
  }
}

/**
 * Extract JWT token from request
 */
function extractToken(req: Request): string | null {
  // Check Authorization header (Bearer token)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Check cookie (if using cookie-based auth)
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }

  // Check query parameter (not recommended for production, but useful for WebSocket)
  if (req.query && req.query.token && typeof req.query.token === 'string') {
    return req.query.token;
  }

  return null;
}

/**
 * Verify JWT token
 */
function verifyToken(token: string): JWTPayload {
  try {
    const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new InvalidTokenError('Token has expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new InvalidTokenError('Invalid token');
    } else {
      throw new InvalidTokenError('Token verification failed');
    }
  }
}

/**
 * Internal service API key for service-to-service communication
 * This allows internal Nexus services to bypass JWT auth within the service mesh
 */
const INTERNAL_SERVICE_API_KEY = process.env.INTERNAL_SERVICE_API_KEY ||
  process.env.API_KEY ||
  'brain_0T5uLPyy3j3RUdrJlFMY48VuN1a2ov9X';

/**
 * Trusted internal services that can use service-to-service auth
 */
const TRUSTED_INTERNAL_SERVICES = new Set([
  'nexus-fileprocess',
  'nexus-mageagent',
  'nexus-graphrag',
  'nexus-sandbox',
  'nexus-learningagent',
  'nexus-auth',
]);

/**
 * Check for internal service authentication
 * Internal services authenticate via X-API-Key and X-Internal-Service headers
 */
function checkInternalServiceAuth(req: Request): AuthContext | null {
  const apiKey = req.headers['x-api-key'] as string;
  const internalService = req.headers['x-internal-service'] as string;

  // Require both headers for internal service auth
  if (!apiKey || !internalService) {
    return null;
  }

  // Validate API key
  if (apiKey !== INTERNAL_SERVICE_API_KEY) {
    logger.warn('Internal service auth failed: invalid API key', {
      service: internalService,
      ip: req.ip,
    });
    return null;
  }

  // Validate service name
  if (!TRUSTED_INTERNAL_SERVICES.has(internalService)) {
    logger.warn('Internal service auth failed: untrusted service', {
      service: internalService,
      ip: req.ip,
    });
    return null;
  }

  logger.debug('Internal service authenticated', {
    service: internalService,
    method: req.method,
    url: req.url,
  });

  // Return an admin-like context for internal services
  return {
    user_id: `service:${internalService}`,
    org_id: 'internal',
    email: `${internalService}@nexus.internal`,
    role: 'admin' as UserRole, // Internal services get admin privileges
  };
}

/**
 * Authentication Middleware
 *
 * Validates JWT token and attaches user context to request
 * Also supports internal service-to-service authentication via X-API-Key header
 */
export function authenticate(req: Request, res: Response, next: NextFunction): void {
  try {
    // First, check for internal service authentication (service-to-service)
    const internalAuth = checkInternalServiceAuth(req);
    if (internalAuth) {
      req.user = internalAuth;
      return next();
    }

    // Extract token from request
    const token = extractToken(req);

    if (!token) {
      throw new UnauthorizedError('No authentication token provided');
    }

    // Verify token
    const decoded = verifyToken(token);

    // Attach user context to request
    req.user = {
      user_id: decoded.user_id,
      org_id: decoded.org_id,
      email: decoded.email,
      role: decoded.role
    };

    logger.debug('User authenticated', {
      user_id: req.user.user_id,
      org_id: req.user.org_id,
      role: req.user.role,
      method: req.method,
      url: req.url
    });

    next();
  } catch (error) {
    // Log authentication failure
    logSecurityEvent(
      'AUTHENTICATION_FAILED',
      'medium',
      {
        ip: req.ip,
        method: req.method,
        url: req.url,
        user_agent: req.get('user-agent'),
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    );

    next(error);
  }
}

/**
 * Optional Authentication Middleware
 *
 * Attaches user context if token is present, but doesn't require it
 */
export function optionalAuthenticate(req: Request, res: Response, next: NextFunction): void {
  try {
    const token = extractToken(req);

    if (token) {
      const decoded = verifyToken(token);
      req.user = {
        user_id: decoded.user_id,
        org_id: decoded.org_id,
        email: decoded.email,
        role: decoded.role
      };
    }

    next();
  } catch (error) {
    // Silently fail for optional authentication
    logger.debug('Optional authentication failed', {
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    next();
  }
}

/**
 * Role-Based Access Control Middleware
 *
 * Checks if user has required role(s)
 */
export function requireRole(...allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      if (!allowedRoles.includes(req.user.role)) {
        logSecurityEvent(
          'INSUFFICIENT_PERMISSIONS',
          'high',
          {
            user_id: req.user.user_id,
            user_role: req.user.role,
            required_roles: allowedRoles,
            method: req.method,
            url: req.url,
            ip: req.ip
          }
        );

        throw new InsufficientPermissionsError(
          `This action requires one of the following roles: ${allowedRoles.join(', ')}`
        );
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Organization Access Middleware
 *
 * Ensures user can only access resources from their organization
 */
export function requireOrganization(req: Request, res: Response, next: NextFunction): void {
  try {
    if (!req.user) {
      throw new UnauthorizedError('Authentication required');
    }

    // Extract org_id from request (params, body, or query)
    const requestedOrgId = req.params.org_id || req.body.org_id || req.query.org_id;

    if (requestedOrgId && requestedOrgId !== req.user.org_id) {
      // Admin role can access any organization
      if (req.user.role !== 'admin') {
        logSecurityEvent(
          'UNAUTHORIZED_ORG_ACCESS',
          'high',
          {
            user_id: req.user.user_id,
            user_org_id: req.user.org_id,
            requested_org_id: requestedOrgId,
            method: req.method,
            url: req.url,
            ip: req.ip
          }
        );

        throw new ForbiddenError('Access denied to this organization');
      }
    }

    next();
  } catch (error) {
    next(error);
  }
}

/**
 * Resource Owner Middleware
 *
 * Ensures user owns the resource they're trying to access
 */
export function requireResourceOwner(userIdParam: string = 'user_id') {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      const resourceUserId = req.params[userIdParam] || req.body[userIdParam];

      if (resourceUserId && resourceUserId !== req.user.user_id) {
        // Admin role can access any resource
        if (req.user.role !== 'admin') {
          logSecurityEvent(
            'UNAUTHORIZED_RESOURCE_ACCESS',
            'medium',
            {
              user_id: req.user.user_id,
              resource_user_id: resourceUserId,
              method: req.method,
              url: req.url,
              ip: req.ip
            }
          );

          throw new ForbiddenError('Access denied to this resource');
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Generate JWT Token
 *
 * Utility function to generate JWT tokens (for login/signup)
 */
export function generateToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiration as jwt.SignOptions['expiresIn']
  });
}

/**
 * Generate Refresh Token
 */
export function generateRefreshToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.refreshExpiration as jwt.SignOptions['expiresIn']
  });
}

/**
 * Decode JWT Token (without verification)
 *
 * Useful for extracting user info from expired tokens
 */
export function decodeToken(token: string): JWTPayload | null {
  try {
    return jwt.decode(token) as JWTPayload;
  } catch (error) {
    return null;
  }
}

/**
 * Permission Helpers
 */

/**
 * Check if user is admin
 */
export function isAdmin(user: AuthContext): boolean {
  return user.role === 'admin';
}

/**
 * Check if user is red team operator
 */
export function isRedTeamOperator(user: AuthContext): boolean {
  return user.role === 'red_team_operator' || user.role === 'admin';
}

/**
 * Check if user is blue team analyst
 */
export function isBlueTeamAnalyst(user: AuthContext): boolean {
  return user.role === 'blue_team_analyst' || user.role === 'admin';
}

/**
 * Check if user is researcher
 */
export function isResearcher(user: AuthContext): boolean {
  return user.role === 'researcher' || user.role === 'admin';
}

/**
 * Check if user can perform offensive operations
 */
export function canPerformOffensiveOps(user: AuthContext): boolean {
  return user.role === 'red_team_operator' || user.role === 'admin';
}

/**
 * Check if user can perform defensive operations
 */
export function canPerformDefensiveOps(user: AuthContext): boolean {
  return user.role === 'blue_team_analyst' || user.role === 'admin';
}

/**
 * Check if user can perform research operations
 */
export function canPerformResearch(user: AuthContext): boolean {
  return user.role === 'researcher' || user.role === 'admin';
}
