/**
 * Nexus-CyberAgent Configuration
 *
 * Environment configuration with validation using Joi
 */

import dotenv from 'dotenv';
import Joi from 'joi';
import { logger } from '../utils/logger';

// Load environment variables
dotenv.config();

/**
 * Configuration Schema
 */
const configSchema = Joi.object({
  // Node environment
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  // Server configuration
  PORT: Joi.number().default(8250),
  WEBSOCKET_PORT: Joi.number().default(8251),
  HOST: Joi.string().default('0.0.0.0'),

  // Database configuration
  DB_HOST: Joi.string().required(),
  DB_PORT: Joi.number().default(5432),
  DB_NAME: Joi.string().required(),
  DB_USER: Joi.string().required(),
  DB_PASSWORD: Joi.string().required(),
  DB_MAX_CONNECTIONS: Joi.number().default(20),
  DB_IDLE_TIMEOUT_MS: Joi.number().default(30000),
  DB_CONNECTION_TIMEOUT_MS: Joi.number().default(5000),

  // Redis configuration
  REDIS_HOST: Joi.string().required(),
  REDIS_PORT: Joi.number().default(6379),
  REDIS_PASSWORD: Joi.string().allow('').optional(),
  REDIS_DB: Joi.number().default(0),
  REDIS_KEY_PREFIX: Joi.string().default('cyberagent:'),

  // JWT configuration
  JWT_SECRET: Joi.string().required().min(32),
  JWT_EXPIRATION: Joi.string().default('24h'),
  JWT_REFRESH_EXPIRATION: Joi.string().default('7d'),

  // Sandbox configuration
  TIER1_SANDBOX_URL: Joi.string().uri().required(),
  TIER2_SANDBOX_URL: Joi.string().uri().required(),
  TIER3_SANDBOX_URL: Joi.string().uri().required(),

  // Nexus integration configuration
  GRAPHRAG_URL: Joi.string().uri().required(),
  GRAPHRAG_API_KEY: Joi.string().allow('').optional(),
  MAGEAGENT_URL: Joi.string().uri().required(),
  MAGEAGENT_API_KEY: Joi.string().allow('').optional(),
  ORCHESTRATION_AGENT_URL: Joi.string().uri().required(),
  ORCHESTRATION_AGENT_API_KEY: Joi.string().allow('').optional(),
  LEARNING_AGENT_URL: Joi.string().uri().allow('').optional(),

  // MinIO configuration (for malware storage)
  MINIO_ENDPOINT: Joi.string().required(),
  MINIO_PORT: Joi.number().default(9000),
  MINIO_ACCESS_KEY: Joi.string().required(),
  MINIO_SECRET_KEY: Joi.string().required(),
  MINIO_BUCKET: Joi.string().default('malware-samples'),
  MINIO_USE_SSL: Joi.boolean().default(false),

  // Rate limiting
  RATE_LIMIT_WINDOW_MS: Joi.number().default(60000), // 1 minute
  RATE_LIMIT_MAX_REQUESTS: Joi.number().default(100),

  // Job queue configuration
  QUEUE_CONCURRENCY: Joi.number().default(5),
  QUEUE_MAX_RETRY_ATTEMPTS: Joi.number().default(3),
  QUEUE_RETRY_DELAY_MS: Joi.number().default(5000),

  // Security configuration
  ENABLE_RBAC: Joi.boolean().default(true),
  ENABLE_AUDIT_LOGGING: Joi.boolean().default(true),
  ENABLE_TARGET_AUTHORIZATION: Joi.boolean().default(true),

  // Logging configuration
  LOG_LEVEL: Joi.string()
    .valid('error', 'warn', 'info', 'http', 'debug')
    .default('info'),

  // CORS configuration
  CORS_ORIGIN: Joi.string().default('*'),
  CORS_CREDENTIALS: Joi.boolean().default(true),

  // OpenTelemetry configuration
  OTEL_ENABLED: Joi.boolean().default(false),
  OTEL_ENDPOINT: Joi.string().uri().allow('').optional(),
  OTEL_SERVICE_NAME: Joi.string().default('nexus-cyberagent-api'),

  // Feature flags
  ENABLE_NEXUS_INTEGRATION: Joi.boolean().default(true),
  ENABLE_WEBSOCKET_STREAMING: Joi.boolean().default(true),
  ENABLE_MULTI_AGENT: Joi.boolean().default(true),
  ENABLE_AUTONOMOUS_MODE: Joi.boolean().default(true),

  // Workflow configuration
  WORKFLOW_MAX_DURATION_MINUTES: Joi.number().default(120),
  WORKFLOW_MAX_PHASES: Joi.number().default(50),

  // Analysis configuration
  MALWARE_ANALYSIS_TIMEOUT_SECONDS: Joi.number().default(600), // 10 minutes
  PENTEST_MAX_DURATION_MINUTES: Joi.number().default(60),
  EXPLOIT_TEST_TIMEOUT_SECONDS: Joi.number().default(300), // 5 minutes

  // Health check configuration
  HEALTH_CHECK_INTERVAL_MS: Joi.number().default(30000), // 30 seconds
  HEALTH_CHECK_TIMEOUT_MS: Joi.number().default(5000), // 5 seconds
}).unknown(); // Allow unknown environment variables

/**
 * Validate environment configuration
 */
function validateConfig(): Record<string, any> {
  const { error, value } = configSchema.validate(process.env, {
    abortEarly: false,
    stripUnknown: true
  });

  if (error) {
    const errorMessages = error.details.map(detail => detail.message).join(', ');
    logger.error('Configuration validation failed', {
      errors: error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }))
    });
    throw new Error(`Configuration validation failed: ${errorMessages}`);
  }

  return value;
}

// Validate and export configuration
const validatedConfig = validateConfig();

/**
 * Application Configuration
 */
export const config = {
  // Environment
  env: validatedConfig.NODE_ENV as 'development' | 'production' | 'test',
  isDevelopment: validatedConfig.NODE_ENV === 'development',
  isProduction: validatedConfig.NODE_ENV === 'production',
  isTest: validatedConfig.NODE_ENV === 'test',

  // Server
  server: {
    port: validatedConfig.PORT as number,
    websocketPort: validatedConfig.WEBSOCKET_PORT as number,
    host: validatedConfig.HOST as string
  },

  // Database
  database: {
    host: validatedConfig.DB_HOST as string,
    port: validatedConfig.DB_PORT as number,
    database: validatedConfig.DB_NAME as string,
    user: validatedConfig.DB_USER as string,
    password: validatedConfig.DB_PASSWORD as string,
    max: validatedConfig.DB_MAX_CONNECTIONS as number,
    idleTimeoutMillis: validatedConfig.DB_IDLE_TIMEOUT_MS as number,
    connectionTimeoutMillis: validatedConfig.DB_CONNECTION_TIMEOUT_MS as number
  },

  // Redis
  redis: {
    host: validatedConfig.REDIS_HOST as string,
    port: validatedConfig.REDIS_PORT as number,
    password: validatedConfig.REDIS_PASSWORD as string | undefined,
    db: validatedConfig.REDIS_DB as number,
    keyPrefix: validatedConfig.REDIS_KEY_PREFIX as string
  },

  // JWT
  jwt: {
    secret: validatedConfig.JWT_SECRET as string,
    expiration: validatedConfig.JWT_EXPIRATION as string,
    refreshExpiration: validatedConfig.JWT_REFRESH_EXPIRATION as string
  },

  // Sandboxes
  sandboxes: {
    tier1: {
      url: validatedConfig.TIER1_SANDBOX_URL as string
    },
    tier2: {
      url: validatedConfig.TIER2_SANDBOX_URL as string
    },
    tier3: {
      url: validatedConfig.TIER3_SANDBOX_URL as string
    }
  },

  // Nexus Integration
  nexus: {
    graphrag: {
      url: validatedConfig.GRAPHRAG_URL as string,
      apiKey: validatedConfig.GRAPHRAG_API_KEY as string | undefined
    },
    mageagent: {
      url: validatedConfig.MAGEAGENT_URL as string,
      apiKey: validatedConfig.MAGEAGENT_API_KEY as string | undefined
    },
    orchestrationAgent: {
      url: validatedConfig.ORCHESTRATION_AGENT_URL as string,
      apiKey: validatedConfig.ORCHESTRATION_AGENT_API_KEY as string | undefined
    },
    learningAgent: {
      url: validatedConfig.LEARNING_AGENT_URL as string | undefined
    }
  },

  // MinIO
  minio: {
    endpoint: validatedConfig.MINIO_ENDPOINT as string,
    port: validatedConfig.MINIO_PORT as number,
    accessKey: validatedConfig.MINIO_ACCESS_KEY as string,
    secretKey: validatedConfig.MINIO_SECRET_KEY as string,
    bucket: validatedConfig.MINIO_BUCKET as string,
    useSSL: validatedConfig.MINIO_USE_SSL as boolean
  },

  // Rate Limiting
  rateLimit: {
    windowMs: validatedConfig.RATE_LIMIT_WINDOW_MS as number,
    maxRequests: validatedConfig.RATE_LIMIT_MAX_REQUESTS as number
  },

  // Job Queue
  queue: {
    concurrency: validatedConfig.QUEUE_CONCURRENCY as number,
    maxRetryAttempts: validatedConfig.QUEUE_MAX_RETRY_ATTEMPTS as number,
    retryDelayMs: validatedConfig.QUEUE_RETRY_DELAY_MS as number
  },

  // Security
  security: {
    enableRBAC: validatedConfig.ENABLE_RBAC as boolean,
    enableAuditLogging: validatedConfig.ENABLE_AUDIT_LOGGING as boolean,
    enableTargetAuthorization: validatedConfig.ENABLE_TARGET_AUTHORIZATION as boolean
  },

  // Logging
  logging: {
    level: validatedConfig.LOG_LEVEL as string
  },

  // CORS
  cors: {
    origin: validatedConfig.CORS_ORIGIN as string,
    credentials: validatedConfig.CORS_CREDENTIALS as boolean
  },

  // OpenTelemetry
  otel: {
    enabled: validatedConfig.OTEL_ENABLED as boolean,
    endpoint: validatedConfig.OTEL_ENDPOINT as string | undefined,
    serviceName: validatedConfig.OTEL_SERVICE_NAME as string
  },

  // Feature Flags
  features: {
    nexusIntegration: validatedConfig.ENABLE_NEXUS_INTEGRATION as boolean,
    websocketStreaming: validatedConfig.ENABLE_WEBSOCKET_STREAMING as boolean,
    multiAgent: validatedConfig.ENABLE_MULTI_AGENT as boolean,
    autonomousMode: validatedConfig.ENABLE_AUTONOMOUS_MODE as boolean
  },

  // Workflow
  workflow: {
    maxDurationMinutes: validatedConfig.WORKFLOW_MAX_DURATION_MINUTES as number,
    maxPhases: validatedConfig.WORKFLOW_MAX_PHASES as number
  },

  // Analysis
  analysis: {
    malwareTimeoutSeconds: validatedConfig.MALWARE_ANALYSIS_TIMEOUT_SECONDS as number,
    pentestMaxDurationMinutes: validatedConfig.PENTEST_MAX_DURATION_MINUTES as number,
    exploitTestTimeoutSeconds: validatedConfig.EXPLOIT_TEST_TIMEOUT_SECONDS as number
  },

  // Health Check
  healthCheck: {
    intervalMs: validatedConfig.HEALTH_CHECK_INTERVAL_MS as number,
    timeoutMs: validatedConfig.HEALTH_CHECK_TIMEOUT_MS as number
  }
};

// Log configuration on startup (mask sensitive values)
logger.info('Configuration loaded successfully', {
  env: config.env,
  server: config.server,
  database: {
    ...config.database,
    password: '***REDACTED***'
  },
  redis: {
    ...config.redis,
    password: config.redis.password ? '***REDACTED***' : undefined
  },
  features: config.features
});

export default config;
