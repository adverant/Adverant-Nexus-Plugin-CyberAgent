/**
 * Nexus-CyberAgent API Server
 *
 * Main entry point for the API Gateway
 */

import express, { Application } from 'express';
import { createServer } from 'http';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { v4 as uuidv4 } from 'uuid';
import { initializeDatabase, closeDatabase } from './database/connection';
import {
  errorHandler,
  notFoundHandler,
  setupUnhandledRejectionHandler,
  setupUncaughtExceptionHandler
} from './middleware/error-handler';
import { httpRequestLogger } from './utils/logger';
import { logger } from './utils/logger';
import config from './config';
import {
  createWebSocketServer,
  createEventPublisher,
  closeEventPublisher,
  WebSocketServer
} from './websocket';
import { closeRateLimiter } from './middleware/rate-limiter';
import { initializeQueueManager, closeQueueManager } from './queue';

// Import routes
import jobsRoutes from './routes/jobs.routes';
import healthRoutes, { trackRequest } from './routes/health.routes';
import { usageTrackingMiddleware, flushPendingReports } from './middleware/usage-tracking';

/**
 * Create Express Application
 */
function createApp(): Application {
  const app = express();

  // Security middleware
  app.use(helmet());

  // CORS middleware
  app.use(cors({
    origin: config.cors.origin,
    credentials: config.cors.credentials
  }));

  // Compression middleware
  app.use(compression());

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request ID middleware
  app.use((req, res, next) => {
    (req as any).id = uuidv4();
    res.setHeader('X-Request-ID', (req as any).id);
    next();
  });

  // HTTP request logging
  app.use(httpRequestLogger);

  // Usage tracking middleware for billing and analytics
  app.use(usageTrackingMiddleware);

  // Request metrics tracking
  app.use(trackRequest);

  // Health check routes (no auth required)
  app.use('/health', healthRoutes);
  app.use('/metrics', healthRoutes);
  app.use('/version', healthRoutes);

  // API routes (v1)
  app.use('/api/v1/jobs', jobsRoutes);

  // TODO: Add more API routes
  // app.use('/api/v1/results', resultsRoutes);
  // app.use('/api/v1/malware', malwareRoutes);
  // app.use('/api/v1/exploits', exploitsRoutes);
  // app.use('/api/v1/workflows', workflowRoutes);
  // app.use('/api/v1/iocs', iocsRoutes);
  // app.use('/api/v1/yara', yaraRoutes);
  // app.use('/api/v1/targets', targetsRoutes);

  // Root endpoint
  app.get('/', (req, res) => {
    res.json({
      name: 'Nexus-CyberAgent API',
      version: process.env.npm_package_version || '1.0.0',
      description: 'Penetration Testing & Malware Analysis Platform',
      documentation: '/api/docs',
      health: '/health',
      websocket: `ws://${req.get('host')}/ws`
    });
  });

  // 404 handler
  app.use(notFoundHandler);

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}

/**
 * Start Server
 */
async function startServer(): Promise<void> {
  try {
    logger.info('Starting Nexus-CyberAgent API Server...', {
      env: config.env,
      node_version: process.version
    });

    // Setup global error handlers
    setupUnhandledRejectionHandler();
    setupUncaughtExceptionHandler();

    // Initialize database
    await initializeDatabase(config.database);
    logger.info('Database initialized successfully');

    // Create Express app
    const app = createApp();

    // Create HTTP server (needed for WebSocket)
    const httpServer = createServer(app);

    // Initialize event publisher
    createEventPublisher();
    logger.info('Event publisher initialized');

    // Initialize queue manager
    await initializeQueueManager();
    logger.info('Queue manager initialized');

    // Start WebSocket server
    const wsServer = createWebSocketServer(httpServer);
    logger.info('WebSocket server initialized');

    // Start HTTP server
    httpServer.listen(config.server.port, config.server.host, () => {
      logger.info('API Server started successfully', {
        port: config.server.port,
        host: config.server.host,
        env: config.env
      });

      logger.info('Available endpoints:', {
        health: `http://${config.server.host}:${config.server.port}/health`,
        api: `http://${config.server.host}:${config.server.port}/api/v1`,
        websocket: `ws://${config.server.host}:${config.server.port}/ws`
      });

      // Log WebSocket statistics
      const wsStats = wsServer.getStatistics();
      logger.info('WebSocket server ready', {
        total_connections: wsStats.total_connections,
        active_subscriptions: wsStats.active_subscriptions
      });
    });

    // Graceful shutdown handler
    const gracefulShutdown = async (signal: string) => {
      logger.info(`${signal} received, starting graceful shutdown...`);

      // Flush pending usage tracking reports
      try {
        await flushPendingReports();
        logger.info('Usage tracking reports flushed');
      } catch (error) {
        logger.error('Failed to flush usage reports', {
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }

      // Stop accepting new connections
      httpServer.close(async () => {
        logger.info('HTTP server closed');

        try {
          // Close WebSocket server
          await wsServer.close();
          logger.info('WebSocket server closed');

          // Close event publisher
          await closeEventPublisher();
          logger.info('Event publisher closed');

          // Close queue manager
          await closeQueueManager();
          logger.info('Queue manager closed');

          // Close rate limiter Redis connections
          await closeRateLimiter();
          logger.info('Rate limiter closed');

          // Close database connections
          await closeDatabase();
          logger.info('Database connections closed');

          logger.info('Graceful shutdown completed');
          process.exit(0);
        } catch (error) {
          logger.error('Error during graceful shutdown', {
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          process.exit(1);
        }
      });

      // Force shutdown after 30 seconds
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    };

    // Register shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  } catch (error) {
    logger.error('Failed to start server', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    });
    process.exit(1);
  }
}

// Export for testing
export { createApp, startServer };

// Start server unconditionally in production
// (require.main === module check fails when run via tini init system)
startServer().catch((error) => {
  logger.error('Unhandled startup error', {
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined
  });
  process.exit(1);
});
