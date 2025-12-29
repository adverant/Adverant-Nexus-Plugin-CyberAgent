/**
 * Permission Checking Middleware
 *
 * Middleware for enforcing granular permissions in routes
 */

import { Request, Response, NextFunction } from 'express';
import { hasPermission, hasAnyPermission, hasAllPermissions } from '../security/permissions';
import { UnauthorizedError, ForbiddenError } from '../errors/custom-errors';
import { Logger, createContextLogger } from '../utils/logger';

const logger = createContextLogger('PermissionsMiddleware');

/**
 * Extended Request with user
 */
export interface AuthenticatedRequest extends Request {
  user: {
    user_id: string;
    email: string;
    role: string;
    organization_id: string;
  };
}

/**
 * Require specific permission
 */
export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;

    if (!authReq.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    const userRole = authReq.user.role;

    if (!hasPermission(userRole, permission)) {
      logger.warn('Permission denied', {
        user_id: authReq.user.user_id,
        role: userRole,
        required_permission: permission,
        path: req.path,
        method: req.method
      });

      return next(
        new ForbiddenError(`Insufficient permissions. Required: ${permission}`)
      );
    }

    logger.debug('Permission granted', {
      user_id: authReq.user.user_id,
      role: userRole,
      permission,
      path: req.path
    });

    next();
  };
}

/**
 * Require any of the specified permissions
 */
export function requireAnyPermission(...permissions: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;

    if (!authReq.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    const userRole = authReq.user.role;

    if (!hasAnyPermission(userRole, permissions)) {
      logger.warn('Permission denied (any)', {
        user_id: authReq.user.user_id,
        role: userRole,
        required_permissions: permissions,
        path: req.path,
        method: req.method
      });

      return next(
        new ForbiddenError(`Insufficient permissions. Required any of: ${permissions.join(', ')}`)
      );
    }

    logger.debug('Permission granted (any)', {
      user_id: authReq.user.user_id,
      role: userRole,
      permissions,
      path: req.path
    });

    next();
  };
}

/**
 * Require all specified permissions
 */
export function requireAllPermissions(...permissions: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;

    if (!authReq.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    const userRole = authReq.user.role;

    if (!hasAllPermissions(userRole, permissions)) {
      logger.warn('Permission denied (all)', {
        user_id: authReq.user.user_id,
        role: userRole,
        required_permissions: permissions,
        path: req.path,
        method: req.method
      });

      return next(
        new ForbiddenError(`Insufficient permissions. Required all of: ${permissions.join(', ')}`)
      );
    }

    logger.debug('Permission granted (all)', {
      user_id: authReq.user.user_id,
      role: userRole,
      permissions,
      path: req.path
    });

    next();
  };
}

/**
 * Require admin role
 */
export function requireAdmin() {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;

    if (!authReq.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    if (authReq.user.role !== 'admin') {
      logger.warn('Admin access denied', {
        user_id: authReq.user.user_id,
        role: authReq.user.role,
        path: req.path,
        method: req.method
      });

      return next(new ForbiddenError('Administrator access required'));
    }

    next();
  };
}

/**
 * Require specific role
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;

    if (!authReq.user) {
      return next(new UnauthorizedError('Authentication required'));
    }

    if (!roles.includes(authReq.user.role)) {
      logger.warn('Role requirement not met', {
        user_id: authReq.user.user_id,
        user_role: authReq.user.role,
        required_roles: roles,
        path: req.path,
        method: req.method
      });

      return next(
        new ForbiddenError(`Required role: ${roles.join(' or ')}`)
      );
    }

    next();
  };
}

/**
 * Check permission programmatically (not middleware)
 */
export function checkPermission(user: AuthenticatedRequest['user'], permission: string): boolean {
  return hasPermission(user.role, permission);
}

/**
 * Check multiple permissions programmatically
 */
export function checkAnyPermission(user: AuthenticatedRequest['user'], permissions: string[]): boolean {
  return hasAnyPermission(user.role, permissions);
}

/**
 * Check all permissions programmatically
 */
export function checkAllPermissions(user: AuthenticatedRequest['user'], permissions: string[]): boolean {
  return hasAllPermissions(user.role, permissions);
}
