/**
 * Nexus-CyberAgent Logger
 *
 * Winston-based structured logging with multiple transports
 */

import winston from 'winston';
import { format } from 'winston';

/**
 * Log Levels
 */
export enum LogLevel {
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info',
  HTTP = 'http',
  DEBUG = 'debug'
}

/**
 * Custom log format for development
 */
const developmentFormat = format.combine(
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  format.errors({ stack: true }),
  format.colorize(),
  format.printf(({ timestamp, level, message, ...metadata }) => {
    let msg = `${timestamp} [${level}]: ${message}`;

    // Add metadata if present
    if (Object.keys(metadata).length > 0) {
      // Remove empty objects and undefined values
      const cleanedMetadata = Object.entries(metadata)
        .filter(([key, value]) => {
          if (value === undefined || value === null) return false;
          if (typeof value === 'object' && Object.keys(value).length === 0) return false;
          return true;
        })
        .reduce((obj, [key, value]) => ({ ...obj, [key]: value }), {});

      if (Object.keys(cleanedMetadata).length > 0) {
        msg += `\n${JSON.stringify(cleanedMetadata, null, 2)}`;
      }
    }

    return msg;
  })
);

/**
 * Custom log format for production
 */
const productionFormat = format.combine(
  format.timestamp(),
  format.errors({ stack: true }),
  format.json()
);

/**
 * Determine if we're in production
 */
const isProduction = process.env.NODE_ENV === 'production';

/**
 * Create Winston logger instance
 */
const createLogger = (): winston.Logger => {
  const logLevel = process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug');

  const transports: winston.transport[] = [];

  // Console transport (always enabled)
  transports.push(
    new winston.transports.Console({
      format: isProduction ? productionFormat : developmentFormat,
      level: logLevel
    })
  );

  // File transport for errors (production only)
  if (isProduction) {
    transports.push(
      new winston.transports.File({
        filename: 'logs/error.log',
        level: 'error',
        maxsize: 10485760, // 10MB
        maxFiles: 5,
        format: productionFormat
      })
    );

    // File transport for all logs
    transports.push(
      new winston.transports.File({
        filename: 'logs/combined.log',
        maxsize: 10485760, // 10MB
        maxFiles: 10,
        format: productionFormat
      })
    );
  }

  return winston.createLogger({
    level: logLevel,
    transports,
    exitOnError: false,
    // Prevent uncaught exceptions from crashing the process
    exceptionHandlers: [
      new winston.transports.File({
        filename: 'logs/exceptions.log',
        maxsize: 10485760,
        maxFiles: 3
      })
    ],
    rejectionHandlers: [
      new winston.transports.File({
        filename: 'logs/rejections.log',
        maxsize: 10485760,
        maxFiles: 3
      })
    ]
  });
};

// Create and export logger instance
export const logger = createLogger();

/**
 * Enhanced logger with context
 */
export class Logger {
  private context: string;
  private contextMetadata: Record<string, any>;

  constructor(context: string, metadata: Record<string, any> = {}) {
    this.context = context;
    this.contextMetadata = metadata;
  }

  /**
   * Build metadata with context
   */
  private buildMetadata(metadata?: Record<string, any>): Record<string, any> {
    return {
      context: this.context,
      ...this.contextMetadata,
      ...metadata
    };
  }

  /**
   * Log error message
   */
  error(message: string, metadata?: Record<string, any>): void {
    logger.error(message, this.buildMetadata(metadata));
  }

  /**
   * Log warning message
   */
  warn(message: string, metadata?: Record<string, any>): void {
    logger.warn(message, this.buildMetadata(metadata));
  }

  /**
   * Log info message
   */
  info(message: string, metadata?: Record<string, any>): void {
    logger.info(message, this.buildMetadata(metadata));
  }

  /**
   * Log HTTP request
   */
  http(message: string, metadata?: Record<string, any>): void {
    logger.http(message, this.buildMetadata(metadata));
  }

  /**
   * Log debug message
   */
  debug(message: string, metadata?: Record<string, any>): void {
    logger.debug(message, this.buildMetadata(metadata));
  }

  /**
   * Create child logger with additional context
   */
  child(context: string, metadata: Record<string, any> = {}): Logger {
    return new Logger(`${this.context}:${context}`, {
      ...this.contextMetadata,
      ...metadata
    });
  }
}

/**
 * Create a logger instance with context
 */
export function createContextLogger(
  context: string,
  metadata: Record<string, any> = {}
): Logger {
  return new Logger(context, metadata);
}

/**
 * HTTP request logger middleware (for Express)
 */
export function httpRequestLogger(req: any, res: any, next: any): void {
  const start = Date.now();

  // Log request
  logger.http('Incoming request', {
    method: req.method,
    url: req.url,
    ip: req.ip,
    user_agent: req.get('user-agent'),
    request_id: req.id
  });

  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - start;

    const logLevel = res.statusCode >= 400 ? 'warn' : 'http';
    const message = res.statusCode >= 400 ? 'Request failed' : 'Request completed';

    logger.log(logLevel, message, {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      request_id: req.id
    });
  });

  next();
}

/**
 * Error logger helper
 */
export function logError(
  error: Error,
  context?: string,
  metadata?: Record<string, any>
): void {
  logger.error(error.message, {
    context,
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack
    },
    ...metadata
  });
}

/**
 * Performance logger helper
 */
export function logPerformance(
  operation: string,
  durationMs: number,
  metadata?: Record<string, any>
): void {
  const level = durationMs > 1000 ? 'warn' : 'debug';
  const message = durationMs > 1000 ? `Slow operation: ${operation}` : `Operation: ${operation}`;

  logger.log(level, message, {
    operation,
    duration: `${durationMs}ms`,
    ...metadata
  });
}

/**
 * Security event logger
 */
export function logSecurityEvent(
  event: string,
  severity: 'low' | 'medium' | 'high' | 'critical',
  metadata?: Record<string, any>
): void {
  const level = severity === 'critical' || severity === 'high' ? 'error' : 'warn';

  logger.log(level, `Security event: ${event}`, {
    event_type: 'security',
    event,
    severity,
    timestamp: new Date().toISOString(),
    ...metadata
  });
}

/**
 * Audit logger for compliance
 */
export function logAudit(
  action: string,
  userId: string,
  resource: string,
  metadata?: Record<string, any>
): void {
  logger.info(`Audit: ${action}`, {
    event_type: 'audit',
    action,
    user_id: userId,
    resource,
    timestamp: new Date().toISOString(),
    ...metadata
  });
}

// Export winston logger as default
export default logger;
