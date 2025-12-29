/**
 * Error Handler Middleware
 *
 * Centralized error handling for Express application
 */

import { Request, Response, NextFunction } from 'express';
import { ApplicationError, isOperationalError } from '../errors/custom-errors';
import { logger, logError, logSecurityEvent } from '../utils/logger';
import { APIErrorResponse } from '../types';
import config from '../config';

/**
 * Error response builder
 */
function buildErrorResponse(
  error: Error,
  requestId?: string
): APIErrorResponse {
  if (error instanceof ApplicationError) {
    return {
      success: false,
      error: {
        code: error.code,
        message: error.message,
        details: config.isDevelopment ? error.details : undefined,
        timestamp: new Date().toISOString(),
        request_id: requestId
      }
    };
  }

  // Unknown error - don't expose internals
  return {
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: config.isDevelopment ? error.message : 'An unexpected error occurred',
      details: config.isDevelopment ? { stack: error.stack } : undefined,
      timestamp: new Date().toISOString(),
      request_id: requestId
    }
  };
}

/**
 * Determine if error should be logged as security event
 */
function isSecurityError(error: ApplicationError): boolean {
  const securityCodes = [
    'UNAUTHORIZED',
    'AUTHENTICATION_ERROR',
    'INVALID_TOKEN',
    'FORBIDDEN',
    'INSUFFICIENT_PERMISSIONS',
    'TARGET_NOT_AUTHORIZED',
    'TARGET_AUTHORIZATION_ERROR'
  ];

  return securityCodes.includes(error.code);
}

/**
 * Main error handler middleware
 */
export function errorHandler(
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Generate request ID if not present
  const requestId = (req as any).id || 'unknown';

  // Log the error
  if (error instanceof ApplicationError) {
    // Operational error - log with context
    const logLevel = error.statusCode >= 500 ? 'error' : 'warn';

    logger.log(logLevel, `API Error: ${error.message}`, {
      code: error.code,
      statusCode: error.statusCode,
      method: req.method,
      url: req.url,
      ip: req.ip,
      user_id: (req as any).user?.user_id,
      org_id: (req as any).user?.org_id,
      request_id: requestId,
      details: error.details,
      stack: config.isDevelopment ? error.stack : undefined
    });

    // Log security events
    if (isSecurityError(error)) {
      const severity = error.statusCode === 403 ? 'high' : 'medium';
      logSecurityEvent(error.code, severity, {
        message: error.message,
        method: req.method,
        url: req.url,
        ip: req.ip,
        user_id: (req as any).user?.user_id,
        request_id: requestId
      });
    }
  } else {
    // Unexpected error - log with full details
    logError(error, 'UnexpectedError', {
      method: req.method,
      url: req.url,
      ip: req.ip,
      user_id: (req as any).user?.user_id,
      request_id: requestId,
      stack: error.stack
    });
  }

  // Build and send error response
  const errorResponse = buildErrorResponse(error, requestId);
  const statusCode = error instanceof ApplicationError ? error.statusCode : 500;

  res.status(statusCode).json(errorResponse);

  // If it's a non-operational error, we might want to crash gracefully
  if (!isOperationalError(error)) {
    logger.error('Non-operational error detected - application may be in unstable state', {
      error: error.message,
      stack: error.stack
    });

    // In production, you might want to:
    // 1. Close server gracefully
    // 2. Let process manager restart the app
    // For now, we'll just log it
  }
}

/**
 * 404 Not Found handler
 */
export function notFoundHandler(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const errorResponse: APIErrorResponse = {
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.path} not found`,
      timestamp: new Date().toISOString(),
      request_id: (req as any).id
    }
  };

  logger.warn('404 Not Found', {
    method: req.method,
    url: req.url,
    ip: req.ip,
    request_id: (req as any).id
  });

  res.status(404).json(errorResponse);
}

/**
 * Async error wrapper
 *
 * Wraps async route handlers to catch rejected promises
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Validation error handler
 *
 * Handles Joi validation errors
 */
export function handleValidationError(error: any): ApplicationError {
  if (error.isJoi) {
    const details = error.details.map((detail: any) => ({
      field: detail.path.join('.'),
      message: detail.message,
      type: detail.type
    }));

    const { ValidationError } = require('../errors/custom-errors');
    return new ValidationError('Validation failed', details);
  }

  return error;
}

/**
 * Database error handler
 *
 * Converts database errors to application errors
 */
export function handleDatabaseError(error: any): ApplicationError {
  const { DatabaseError, DuplicateResourceError } = require('../errors/custom-errors');

  // PostgreSQL error codes
  if (error.code) {
    switch (error.code) {
      case '23505': // unique_violation
        return new DuplicateResourceError('Resource', {
          constraint: error.constraint,
          detail: error.detail
        });

      case '23503': // foreign_key_violation
        return new DatabaseError('Foreign key constraint violation', {
          constraint: error.constraint,
          detail: error.detail
        });

      case '23502': // not_null_violation
        return new DatabaseError('Required field is missing', {
          column: error.column,
          detail: error.detail
        });

      case '23514': // check_violation
        return new DatabaseError('Check constraint violation', {
          constraint: error.constraint,
          detail: error.detail
        });

      case '42P01': // undefined_table
        return new DatabaseError('Database table not found', {
          table: error.table
        });

      default:
        return new DatabaseError('Database operation failed', {
          code: error.code,
          detail: error.detail
        });
    }
  }

  return new DatabaseError(error.message || 'Database operation failed');
}

/**
 * Unhandled rejection handler
 */
export function setupUnhandledRejectionHandler(): void {
  process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
    logger.error('Unhandled Promise Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      promise: promise.toString()
    });

    // In production, you might want to gracefully shutdown
    if (config.isProduction && !isOperationalError(reason)) {
      logger.error('Shutting down due to unhandled rejection');
      process.exit(1);
    }
  });
}

/**
 * Uncaught exception handler
 */
export function setupUncaughtExceptionHandler(): void {
  process.on('uncaughtException', (error: Error) => {
    logger.error('Uncaught Exception', {
      error: error.message,
      stack: error.stack
    });

    // Always exit on uncaught exception
    logger.error('Shutting down due to uncaught exception');
    process.exit(1);
  });
}
