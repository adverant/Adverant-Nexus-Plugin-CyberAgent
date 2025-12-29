/**
 * Nexus-CyberAgent Database Connection
 *
 * PostgreSQL connection pool with automatic reconnection and health monitoring
 */

import { Pool, PoolClient, PoolConfig, QueryResult } from 'pg';
import { logger } from '../utils/logger';
import { getTargetAuthorizationRepository } from './repositories/target-authorization.repository';

/**
 * Database Configuration
 */
interface DatabaseConfig extends PoolConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  max?: number; // Maximum pool size
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
}

/**
 * Database Connection Manager
 */
class DatabaseConnection {
  private pool: Pool | null = null;
  private config: DatabaseConfig;
  private isConnected: boolean = false;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectDelay: number = 2000; // 2 seconds

  constructor(config: DatabaseConfig) {
    this.config = {
      ...config,
      max: config.max || 20, // Default: 20 connections
      idleTimeoutMillis: config.idleTimeoutMillis || 30000, // 30 seconds
      connectionTimeoutMillis: config.connectionTimeoutMillis || 5000, // 5 seconds
    };
  }

  /**
   * Initialize database connection pool
   */
  async connect(): Promise<void> {
    if (this.pool && this.isConnected) {
      logger.warn('Database pool already initialized');
      return;
    }

    try {
      logger.info('Initializing database connection pool...', {
        host: this.config.host,
        port: this.config.port,
        database: this.config.database,
        user: this.config.user,
        maxConnections: this.config.max
      });

      this.pool = new Pool(this.config);

      // Setup pool event handlers
      this.setupEventHandlers();

      // Test connection
      await this.testConnection();

      this.isConnected = true;
      this.reconnectAttempts = 0;

      logger.info('Database connection pool initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize database connection pool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        host: this.config.host,
        database: this.config.database
      });

      // Attempt reconnection
      await this.handleReconnect();
      throw error;
    }
  }

  /**
   * Setup pool event handlers for monitoring
   */
  private setupEventHandlers(): void {
    if (!this.pool) return;

    // Client connection event
    this.pool.on('connect', (client) => {
      logger.debug('New database client connected');
    });

    // Client error event
    this.pool.on('error', (error, client) => {
      logger.error('Unexpected database client error', {
        error: error.message,
        stack: error.stack
      });

      this.isConnected = false;
      this.handleReconnect().catch((reconnectError) => {
        logger.error('Failed to reconnect after client error', {
          error: reconnectError instanceof Error ? reconnectError.message : 'Unknown error'
        });
      });
    });

    // Client removal event
    this.pool.on('remove', (client) => {
      logger.debug('Database client removed from pool');
    });
  }

  /**
   * Test database connection
   */
  private async testConnection(): Promise<void> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }

    const client = await this.pool.connect();
    try {
      const result = await client.query('SELECT NOW() as current_time');
      logger.info('Database connection test successful', {
        server_time: result.rows[0].current_time
      });
    } finally {
      client.release();
    }
  }

  /**
   * Handle reconnection with exponential backoff
   */
  private async handleReconnect(): Promise<void> {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      logger.error('Max reconnection attempts reached, giving up', {
        attempts: this.reconnectAttempts
      });
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    logger.warn(`Attempting to reconnect to database (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`, {
      delay: `${delay}ms`
    });

    await new Promise(resolve => setTimeout(resolve, delay));

    try {
      await this.connect();
    } catch (error) {
      logger.error('Reconnection attempt failed', {
        attempt: this.reconnectAttempts,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Execute a database query
   */
  async query<T = any>(text: string, params?: any[]): Promise<QueryResult<T>> {
    if (!this.pool || !this.isConnected) {
      throw new Error('Database not connected');
    }

    const start = Date.now();
    try {
      const result = await this.pool.query<T>(text, params);
      const duration = Date.now() - start;

      logger.debug('Query executed successfully', {
        query: text.substring(0, 100), // First 100 chars
        params: params?.length || 0,
        rows: result.rowCount,
        duration: `${duration}ms`
      });

      return result;
    } catch (error) {
      const duration = Date.now() - start;
      logger.error('Query execution failed', {
        query: text.substring(0, 100),
        params: params?.length || 0,
        duration: `${duration}ms`,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get a client from the pool for transactions
   */
  async getClient(): Promise<PoolClient> {
    if (!this.pool || !this.isConnected) {
      throw new Error('Database not connected');
    }

    return this.pool.connect();
  }

  /**
   * Execute queries within a transaction
   */
  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.getClient();

    try {
      await client.query('BEGIN');
      logger.debug('Transaction started');

      const result = await callback(client);

      await client.query('COMMIT');
      logger.debug('Transaction committed');

      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Transaction rolled back', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Check database connection health
   */
  async healthCheck(): Promise<{ healthy: boolean; latency?: number; error?: string }> {
    if (!this.pool || !this.isConnected) {
      return {
        healthy: false,
        error: 'Database not connected'
      };
    }

    const start = Date.now();
    try {
      await this.pool.query('SELECT 1');
      const latency = Date.now() - start;

      return {
        healthy: true,
        latency
      };
    } catch (error) {
      return {
        healthy: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get pool statistics
   */
  getPoolStats(): {
    totalCount: number;
    idleCount: number;
    waitingCount: number;
  } | null {
    if (!this.pool) return null;

    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount
    };
  }

  /**
   * Close all connections in the pool
   */
  async disconnect(): Promise<void> {
    if (!this.pool) {
      logger.warn('Database pool not initialized, nothing to disconnect');
      return;
    }

    try {
      logger.info('Closing database connection pool...');
      await this.pool.end();
      this.pool = null;
      this.isConnected = false;
      logger.info('Database connection pool closed successfully');
    } catch (error) {
      logger.error('Error closing database connection pool', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get connection status
   */
  isHealthy(): boolean {
    return this.isConnected && this.pool !== null;
  }
}

// Singleton database instance
let dbInstance: DatabaseConnection | null = null;

/**
 * Initialize database connection and repository tables
 */
export async function initializeDatabase(config: DatabaseConfig): Promise<DatabaseConnection> {
  if (dbInstance && dbInstance.isHealthy()) {
    logger.warn('Database already initialized');
    return dbInstance;
  }

  dbInstance = new DatabaseConnection(config);
  await dbInstance.connect();

  // Initialize repository tables
  try {
    logger.info('Initializing database tables...');

    // Initialize target authorization repository
    const targetAuthRepo = getTargetAuthorizationRepository();
    await targetAuthRepo.initialize();

    logger.info('Database tables initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize database tables', {
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw error;
  }

  return dbInstance;
}

/**
 * Get database instance
 */
export function getDatabase(): DatabaseConnection {
  if (!dbInstance) {
    throw new Error('Database not initialized. Call initializeDatabase() first.');
  }
  return dbInstance;
}

/**
 * Close database connection
 */
export async function closeDatabase(): Promise<void> {
  if (dbInstance) {
    await dbInstance.disconnect();
    dbInstance = null;
  }
}

// Export the DatabaseConnection class for testing
export { DatabaseConnection };
