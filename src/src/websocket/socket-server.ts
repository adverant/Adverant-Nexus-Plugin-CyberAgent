/**
 * WebSocket Server
 *
 * Socket.IO server for real-time job progress updates with Redis pub/sub
 */

import { Server as HTTPServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import Redis from 'ioredis';
import jwt from 'jsonwebtoken';
import { JWTPayload, AuthContext } from '../types';
import { Logger, createContextLogger, logSecurityEvent } from '../utils/logger';
import config from '../config';

/**
 * Extended Socket with authentication
 */
interface AuthenticatedSocket extends Socket {
  user?: AuthContext;
}

/**
 * WebSocket Server Configuration
 */
interface WebSocketServerConfig {
  httpServer: HTTPServer;
  cors: {
    origin: string;
    credentials: boolean;
  };
  redis: {
    host: string;
    port: number;
    password?: string;
    db: number;
  };
  channelPrefix: string;
}

/**
 * WebSocket Server Class
 */
export class WebSocketServer {
  private io: SocketIOServer;
  private subscriber: Redis;
  private logger: Logger;
  private channelPrefix: string;
  private connectedClients: Map<string, Set<string>>; // jobId -> Set of socketIds

  constructor(config: WebSocketServerConfig) {
    this.channelPrefix = config.channelPrefix;
    this.logger = createContextLogger('WebSocketServer');
    this.connectedClients = new Map();

    // Create Socket.IO server
    this.io = new SocketIOServer(config.httpServer, {
      cors: config.cors,
      path: '/ws/socket.io',
      transports: ['websocket', 'polling'],
      pingInterval: 25000,
      pingTimeout: 20000,
      maxHttpBufferSize: 1e6 // 1MB
    });

    // Create Redis subscriber client
    this.subscriber = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      db: config.redis.db,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        this.logger.warn('Redis subscriber reconnecting', { attempt: times, delay });
        return delay;
      }
    });

    this.setupRedisEventHandlers();
    this.setupSocketAuthentication();
    this.setupSocketEventHandlers();
    this.setupRedisSubscription();
  }

  /**
   * Setup Redis event handlers
   */
  private setupRedisEventHandlers(): void {
    this.subscriber.on('connect', () => {
      this.logger.info('Redis subscriber connected');
    });

    this.subscriber.on('error', (error) => {
      this.logger.error('Redis subscriber error', {
        error: error.message
      });
    });

    this.subscriber.on('close', () => {
      this.logger.warn('Redis subscriber connection closed');
    });
  }

  /**
   * Setup Socket.IO authentication middleware
   */
  private setupSocketAuthentication(): void {
    this.io.use(async (socket: AuthenticatedSocket, next) => {
      try {
        // Extract token from auth header or query parameter
        const token =
          socket.handshake.auth.token ||
          socket.handshake.query.token as string;

        if (!token) {
          this.logger.warn('WebSocket connection attempt without token', {
            socket_id: socket.id,
            ip: socket.handshake.address
          });
          return next(new Error('Authentication required'));
        }

        // Verify JWT token
        const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;

        // Attach user context to socket
        socket.user = {
          user_id: decoded.user_id,
          org_id: decoded.org_id,
          email: decoded.email,
          role: decoded.role
        };

        this.logger.debug('WebSocket client authenticated', {
          socket_id: socket.id,
          user_id: socket.user.user_id,
          org_id: socket.user.org_id
        });

        next();
      } catch (error) {
        logSecurityEvent('WEBSOCKET_AUTH_FAILED', 'medium', {
          socket_id: socket.id,
          ip: socket.handshake.address,
          error: error instanceof Error ? error.message : 'Unknown error'
        });

        return next(new Error('Authentication failed'));
      }
    });
  }

  /**
   * Setup Socket.IO event handlers
   */
  private setupSocketEventHandlers(): void {
    this.io.on('connection', (socket: AuthenticatedSocket) => {
      const user = socket.user!;

      this.logger.info('WebSocket client connected', {
        socket_id: socket.id,
        user_id: user.user_id,
        org_id: user.org_id
      });

      // Handle subscription to job events
      socket.on('subscribe', async (data: { job_id: string }) => {
        try {
          await this.subscribeToJob(socket, data.job_id);
        } catch (error) {
          socket.emit('error', {
            message: 'Subscription failed',
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      });

      // Handle unsubscription from job events
      socket.on('unsubscribe', async (data: { job_id: string }) => {
        try {
          await this.unsubscribeFromJob(socket, data.job_id);
        } catch (error) {
          socket.emit('error', {
            message: 'Unsubscription failed',
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      });

      // Handle disconnect
      socket.on('disconnect', (reason) => {
        this.logger.info('WebSocket client disconnected', {
          socket_id: socket.id,
          user_id: user.user_id,
          reason
        });

        // Clean up subscriptions
        this.cleanupClientSubscriptions(socket);
      });

      // Handle errors
      socket.on('error', (error) => {
        this.logger.error('WebSocket client error', {
          socket_id: socket.id,
          user_id: user.user_id,
          error: error.message
        });
      });

      // Send welcome message
      socket.emit('connected', {
        socket_id: socket.id,
        message: 'Connected to Nexus-CyberAgent WebSocket server'
      });
    });
  }

  /**
   * Setup Redis subscription for job events
   */
  private setupRedisSubscription(): void {
    // Subscribe to all job channels using pattern matching
    this.subscriber.psubscribe(`${this.channelPrefix}job:*`, (error, count) => {
      if (error) {
        this.logger.error('Failed to subscribe to job channels', {
          error: error.message
        });
        return;
      }

      this.logger.info('Subscribed to job channels', {
        pattern: `${this.channelPrefix}job:*`,
        count
      });
    });

    // Handle incoming messages from Redis
    this.subscriber.on('pmessage', (pattern, channel, message) => {
      try {
        // Extract job ID from channel
        const jobId = channel.replace(`${this.channelPrefix}job:`, '');

        // Parse event
        const event = JSON.parse(message);

        // Emit to all clients subscribed to this job
        this.io.to(`job:${jobId}`).emit('event', event);

        this.logger.debug('Event broadcast to clients', {
          job_id: jobId,
          event_type: event.event_type,
          clients: this.connectedClients.get(jobId)?.size || 0
        });
      } catch (error) {
        this.logger.error('Failed to process Redis message', {
          channel,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    });
  }

  /**
   * Subscribe socket to job events
   */
  private async subscribeToJob(socket: AuthenticatedSocket, jobId: string): Promise<void> {
    const user = socket.user!;

    // TODO: Verify user has access to this job (check organization)
    // For now, we allow all authenticated users

    // Join Socket.IO room
    await socket.join(`job:${jobId}`);

    // Track subscription
    if (!this.connectedClients.has(jobId)) {
      this.connectedClients.set(jobId, new Set());
    }
    this.connectedClients.get(jobId)!.add(socket.id);

    this.logger.info('Client subscribed to job', {
      socket_id: socket.id,
      user_id: user.user_id,
      job_id: jobId,
      total_subscribers: this.connectedClients.get(jobId)!.size
    });

    // Send subscription confirmation
    socket.emit('subscribed', {
      job_id: jobId,
      message: `Subscribed to job ${jobId}`
    });
  }

  /**
   * Unsubscribe socket from job events
   */
  private async unsubscribeFromJob(socket: AuthenticatedSocket, jobId: string): Promise<void> {
    const user = socket.user!;

    // Leave Socket.IO room
    await socket.leave(`job:${jobId}`);

    // Remove from tracking
    const subscribers = this.connectedClients.get(jobId);
    if (subscribers) {
      subscribers.delete(socket.id);
      if (subscribers.size === 0) {
        this.connectedClients.delete(jobId);
      }
    }

    this.logger.info('Client unsubscribed from job', {
      socket_id: socket.id,
      user_id: user.user_id,
      job_id: jobId,
      remaining_subscribers: subscribers?.size || 0
    });

    // Send unsubscription confirmation
    socket.emit('unsubscribed', {
      job_id: jobId,
      message: `Unsubscribed from job ${jobId}`
    });
  }

  /**
   * Clean up client subscriptions on disconnect
   */
  private cleanupClientSubscriptions(socket: AuthenticatedSocket): void {
    // Remove socket from all job subscriptions
    for (const [jobId, subscribers] of this.connectedClients.entries()) {
      if (subscribers.has(socket.id)) {
        subscribers.delete(socket.id);
        if (subscribers.size === 0) {
          this.connectedClients.delete(jobId);
        }
      }
    }
  }

  /**
   * Get connection statistics
   */
  getStatistics(): {
    total_connections: number;
    active_subscriptions: number;
    jobs_with_subscribers: number;
  } {
    return {
      total_connections: this.io.sockets.sockets.size,
      active_subscriptions: Array.from(this.connectedClients.values())
        .reduce((sum, set) => sum + set.size, 0),
      jobs_with_subscribers: this.connectedClients.size
    };
  }

  /**
   * Broadcast message to all connected clients (admin only)
   */
  async broadcastToAll(event: string, data: any): Promise<void> {
    this.io.emit(event, data);
    this.logger.info('Broadcast sent to all clients', {
      event,
      total_clients: this.io.sockets.sockets.size
    });
  }

  /**
   * Close WebSocket server
   */
  async close(): Promise<void> {
    try {
      // Close all connections
      this.io.close();
      this.logger.info('Socket.IO server closed');

      // Close Redis subscriber
      await this.subscriber.quit();
      this.logger.info('Redis subscriber closed');

      // Clear subscriptions
      this.connectedClients.clear();
    } catch (error) {
      this.logger.error('Error closing WebSocket server', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
}

/**
 * Create WebSocket server
 */
export function createWebSocketServer(httpServer: HTTPServer): WebSocketServer {
  return new WebSocketServer({
    httpServer,
    cors: {
      origin: config.cors.origin,
      credentials: config.cors.credentials
    },
    redis: {
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      db: config.redis.db
    },
    channelPrefix: `${config.redis.keyPrefix}ws:`
  });
}
