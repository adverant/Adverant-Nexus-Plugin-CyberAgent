/**
 * WebSocket Client SDK
 *
 * TypeScript client SDK for connecting to Nexus-CyberAgent WebSocket server
 */

import { io, Socket } from 'socket.io-client';
import { WebSocketEvent } from '../types';

/**
 * Client SDK Configuration
 */
export interface ClientSDKConfig {
  url: string; // WebSocket server URL
  token: string; // JWT authentication token
  autoReconnect?: boolean;
  reconnectionDelay?: number;
  reconnectionDelayMax?: number;
  timeout?: number;
}

/**
 * Event callback type
 */
export type EventCallback = (event: WebSocketEvent) => void;

/**
 * WebSocket Client SDK
 */
export class CyberAgentWebSocketClient {
  private socket: Socket | null = null;
  private config: ClientSDKConfig;
  private eventCallbacks: Map<string, Set<EventCallback>>; // jobId -> callbacks
  private isConnected: boolean = false;

  constructor(config: ClientSDKConfig) {
    this.config = {
      autoReconnect: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 20000,
      ...config
    };

    this.eventCallbacks = new Map();
  }

  /**
   * Connect to WebSocket server
   */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.socket && this.isConnected) {
        resolve();
        return;
      }

      this.socket = io(this.config.url, {
        auth: {
          token: this.config.token
        },
        transports: ['websocket', 'polling'],
        reconnection: this.config.autoReconnect,
        reconnectionDelay: this.config.reconnectionDelay,
        reconnectionDelayMax: this.config.reconnectionDelayMax,
        timeout: this.config.timeout,
        path: '/ws/socket.io'
      });

      // Connection success
      this.socket.on('connected', (data) => {
        this.isConnected = true;
        console.log('Connected to Nexus-CyberAgent:', data.message);
        resolve();
      });

      // Connection error
      this.socket.on('connect_error', (error) => {
        this.isConnected = false;
        console.error('Connection error:', error.message);
        reject(error);
      });

      // Reconnection
      this.socket.on('reconnect', (attemptNumber) => {
        this.isConnected = true;
        console.log('Reconnected after', attemptNumber, 'attempts');
      });

      // Disconnection
      this.socket.on('disconnect', (reason) => {
        this.isConnected = false;
        console.log('Disconnected:', reason);
      });

      // Handle incoming events
      this.socket.on('event', (event: WebSocketEvent) => {
        this.handleEvent(event);
      });

      // Handle errors
      this.socket.on('error', (error) => {
        console.error('WebSocket error:', error);
      });
    });
  }

  /**
   * Subscribe to job events
   */
  async subscribeToJob(jobId: string, callback: EventCallback): Promise<void> {
    if (!this.socket || !this.isConnected) {
      throw new Error('Not connected to WebSocket server');
    }

    return new Promise((resolve, reject) => {
      // Register callback
      if (!this.eventCallbacks.has(jobId)) {
        this.eventCallbacks.set(jobId, new Set());
      }
      this.eventCallbacks.get(jobId)!.add(callback);

      // Send subscription request
      this.socket!.emit('subscribe', { job_id: jobId });

      // Wait for confirmation
      const confirmHandler = (data: { job_id: string; message: string }) => {
        if (data.job_id === jobId) {
          this.socket!.off('subscribed', confirmHandler);
          resolve();
        }
      };

      this.socket!.on('subscribed', confirmHandler);

      // Timeout
      setTimeout(() => {
        this.socket!.off('subscribed', confirmHandler);
        reject(new Error('Subscription timeout'));
      }, 5000);
    });
  }

  /**
   * Unsubscribe from job events
   */
  async unsubscribeFromJob(jobId: string, callback?: EventCallback): Promise<void> {
    if (!this.socket || !this.isConnected) {
      throw new Error('Not connected to WebSocket server');
    }

    // Remove callback
    if (callback) {
      const callbacks = this.eventCallbacks.get(jobId);
      if (callbacks) {
        callbacks.delete(callback);
        if (callbacks.size === 0) {
          this.eventCallbacks.delete(jobId);
        }
      }
    } else {
      // Remove all callbacks for this job
      this.eventCallbacks.delete(jobId);
    }

    // Send unsubscription request if no more callbacks
    if (!this.eventCallbacks.has(jobId)) {
      return new Promise((resolve) => {
        this.socket!.emit('unsubscribe', { job_id: jobId });

        const confirmHandler = (data: { job_id: string }) => {
          if (data.job_id === jobId) {
            this.socket!.off('unsubscribed', confirmHandler);
            resolve();
          }
        };

        this.socket!.on('unsubscribed', confirmHandler);
      });
    }
  }

  /**
   * Handle incoming event
   */
  private handleEvent(event: WebSocketEvent): void {
    const callbacks = this.eventCallbacks.get(event.job_id);

    if (callbacks) {
      callbacks.forEach(callback => {
        try {
          callback(event);
        } catch (error) {
          console.error('Error in event callback:', error);
        }
      });
    }
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.isConnected = false;
      this.eventCallbacks.clear();
    }
  }

  /**
   * Check connection status
   */
  isConnectionActive(): boolean {
    return this.isConnected;
  }
}

/**
 * Example Usage:
 *
 * ```typescript
 * // Create client
 * const client = new CyberAgentWebSocketClient({
 *   url: 'http://localhost:8250',
 *   token: 'your-jwt-token'
 * });
 *
 * // Connect
 * await client.connect();
 *
 * // Subscribe to job
 * await client.subscribeToJob('job-123', (event) => {
 *   console.log('Event received:', event);
 *
 *   switch (event.event_type) {
 *     case 'job:progress':
 *       console.log('Progress:', event.data.progress);
 *       break;
 *     case 'vulnerability:found':
 *       console.log('Vulnerability:', event.data);
 *       break;
 *     case 'job:completed':
 *       console.log('Job completed!');
 *       break;
 *   }
 * });
 *
 * // Later: unsubscribe
 * await client.unsubscribeFromJob('job-123');
 *
 * // Disconnect
 * client.disconnect();
 * ```
 */
