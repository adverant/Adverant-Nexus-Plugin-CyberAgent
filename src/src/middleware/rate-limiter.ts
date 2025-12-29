/**
 * Rate Limiting Middleware
 *
 * Redis-based rate limiting with different strategies for different endpoints
 */

import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';
import { TooManyRequestsError } from '../errors/custom-errors';
import { logger } from '../utils/logger';
import config from '../config';

/**
 * Create Redis client for rate limiting
 */
const redisClient = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
  db: config.redis.db,
  keyPrefix: `${config.redis.keyPrefix}rate-limit:`,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    logger.warn(`Redis connection failed, retrying in ${delay}ms`, { attempt: times });
    return delay;
  }
});

// Handle Redis errors
redisClient.on('error', (error) => {
  logger.error('Redis rate limiter error', {
    error: error.message
  });
});

redisClient.on('connect', () => {
  logger.info('Redis rate limiter connected');
});

/**
 * Rate limiter error handler
 */
function rateLimiterErrorHandler(req: Request, res: Response, next: NextFunction): void {
  const error = new TooManyRequestsError('Too many requests, please try again later', {
    retry_after: res.getHeader('Retry-After'),
    limit: res.getHeader('X-RateLimit-Limit'),
    remaining: res.getHeader('X-RateLimit-Remaining')
  });

  next(error);
}

/**
 * Create rate limiter with custom options
 */
function createRateLimiter(options: {
  windowMs?: number;
  max?: number;
  message?: string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (req: Request) => string;
}) {
  return rateLimit({
    store: new RedisStore({
      // @ts-expect-error - rate-limit-redis v4 requires sendCommand for ioredis
      sendCommand: (...args: string[]) => redisClient.call(...args),
      prefix: 'rl:'
    }),
    windowMs: options.windowMs || config.rateLimit.windowMs,
    max: options.max || config.rateLimit.maxRequests,
    message: options.message || 'Too many requests',
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false, // Disable `X-RateLimit-*` headers
    skipSuccessfulRequests: options.skipSuccessfulRequests || false,
    skipFailedRequests: options.skipFailedRequests || false,
    keyGenerator: options.keyGenerator || ((req: Request) => {
      // Use user ID if authenticated, otherwise use IP
      return (req as any).user?.user_id || req.ip;
    }),
    handler: rateLimiterErrorHandler
  });
}

/**
 * Standard Rate Limiter
 *
 * Default: 100 requests per minute per user/IP
 */
export const standardRateLimiter = createRateLimiter({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: 'Too many requests, please try again later'
});

/**
 * Strict Rate Limiter
 *
 * For sensitive operations: 10 requests per minute
 */
export const strictRateLimiter = createRateLimiter({
  windowMs: 60000, // 1 minute
  max: 10,
  message: 'Too many attempts, please wait before trying again'
});

/**
 * Authentication Rate Limiter
 *
 * For login/signup: 5 attempts per 15 minutes per IP
 */
export const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many authentication attempts, please try again later',
  skipSuccessfulRequests: true, // Don't count successful logins
  keyGenerator: (req: Request) => {
    // Always use IP for auth rate limiting (before authentication)
    return req.ip;
  }
});

/**
 * Job Creation Rate Limiter
 *
 * For creating scan jobs: 20 per hour per organization
 */
export const jobCreationRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: 'Job creation rate limit exceeded, please wait before creating more jobs',
  keyGenerator: (req: Request) => {
    // Use organization ID for job creation limits
    return (req as any).user?.org_id || req.ip;
  }
});

/**
 * Malware Upload Rate Limiter
 *
 * For uploading malware samples: 10 per hour per organization
 */
export const malwareUploadRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Malware upload rate limit exceeded, please wait before uploading more samples',
  keyGenerator: (req: Request) => {
    return (req as any).user?.org_id || req.ip;
  }
});

/**
 * Heavy Operation Rate Limiter
 *
 * For resource-intensive operations: 5 per hour
 */
export const heavyOperationRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: 'Heavy operation rate limit exceeded, please wait before retrying',
  keyGenerator: (req: Request) => {
    return (req as any).user?.user_id || req.ip;
  }
});

/**
 * Workflow Execution Rate Limiter
 *
 * For workflow execution: 10 per hour per user
 */
export const workflowRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Workflow execution rate limit exceeded',
  keyGenerator: (req: Request) => {
    return (req as any).user?.user_id || req.ip;
  }
});

/**
 * API Key Rate Limiter
 *
 * For API key-based access: 1000 requests per hour
 */
export const apiKeyRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1000,
  message: 'API key rate limit exceeded',
  keyGenerator: (req: Request) => {
    // Use API key from header
    return req.get('X-API-Key') || req.ip;
  }
});

/**
 * Custom rate limiter for specific routes
 */
export function customRateLimiter(windowMs: number, max: number, message?: string) {
  return createRateLimiter({
    windowMs,
    max,
    message: message || 'Rate limit exceeded'
  });
}

/**
 * Bypass rate limiting for whitelisted IPs or users
 */
export function bypassRateLimiting(req: Request, res: Response, next: NextFunction): void {
  // Check if user is admin
  if ((req as any).user?.role === 'admin') {
    logger.debug('Rate limiting bypassed for admin user', {
      user_id: (req as any).user.user_id
    });
    return next();
  }

  // Check if IP is whitelisted (can be configured via environment)
  const whitelistedIPs = process.env.RATE_LIMIT_WHITELIST?.split(',') || [];
  if (whitelistedIPs.includes(req.ip)) {
    logger.debug('Rate limiting bypassed for whitelisted IP', {
      ip: req.ip
    });
    return next();
  }

  next();
}

/**
 * Get current rate limit status for a key
 */
export async function getRateLimitStatus(key: string): Promise<{
  limit: number;
  remaining: number;
  reset: Date;
} | null> {
  try {
    const redisKey = `${config.redis.keyPrefix}rate-limit:rl:${key}`;
    const value = await redisClient.get(redisKey);

    if (!value) {
      return null;
    }

    const data = JSON.parse(value);
    return {
      limit: data.limit,
      remaining: data.remaining,
      reset: new Date(data.reset)
    };
  } catch (error) {
    logger.error('Failed to get rate limit status', {
      key,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    return null;
  }
}

/**
 * Reset rate limit for a specific key
 */
export async function resetRateLimit(key: string): Promise<boolean> {
  try {
    const redisKey = `${config.redis.keyPrefix}rate-limit:rl:${key}`;
    await redisClient.del(redisKey);
    logger.info('Rate limit reset', { key });
    return true;
  } catch (error) {
    logger.error('Failed to reset rate limit', {
      key,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    return false;
  }
}

/**
 * Close Redis connection (for graceful shutdown)
 */
export async function closeRateLimiter(): Promise<void> {
  try {
    await redisClient.quit();
    logger.info('Rate limiter Redis connection closed');
  } catch (error) {
    logger.error('Failed to close rate limiter Redis connection', {
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

export { redisClient };
