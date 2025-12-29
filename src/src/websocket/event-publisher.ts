/**
 * WebSocket Event Publisher
 *
 * Publishes events to WebSocket clients via Redis pub/sub for multi-worker support
 */

import Redis from 'ioredis';
import { WebSocketEvent, WebSocketEventType, JobStatus, Severity } from '../types';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Event Publisher Configuration
 */
interface PublisherConfig {
  redis: {
    host: string;
    port: number;
    password?: string;
    db: number;
  };
  channelPrefix: string;
}

/**
 * WebSocket Event Publisher Class
 */
export class WebSocketEventPublisher {
  private publisher: Redis;
  private logger: Logger;
  private channelPrefix: string;

  constructor(config: PublisherConfig) {
    this.channelPrefix = config.channelPrefix;
    this.logger = createContextLogger('WebSocketEventPublisher');

    // Create Redis publisher client
    this.publisher = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      db: config.redis.db,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        this.logger.warn('Redis publisher reconnecting', { attempt: times, delay });
        return delay;
      }
    });

    this.setupEventHandlers();
  }

  /**
   * Setup Redis event handlers
   */
  private setupEventHandlers(): void {
    this.publisher.on('connect', () => {
      this.logger.info('Redis publisher connected');
    });

    this.publisher.on('error', (error) => {
      this.logger.error('Redis publisher error', {
        error: error.message
      });
    });

    this.publisher.on('close', () => {
      this.logger.warn('Redis publisher connection closed');
    });
  }

  /**
   * Publish event to a specific job channel
   */
  async publishEvent(jobId: string, event: WebSocketEvent): Promise<void> {
    try {
      const channel = `${this.channelPrefix}job:${jobId}`;
      const message = JSON.stringify(event);

      await this.publisher.publish(channel, message);

      this.logger.debug('Event published', {
        job_id: jobId,
        event_type: event.event_type,
        channel
      });
    } catch (error) {
      this.logger.error('Failed to publish event', {
        job_id: jobId,
        event_type: event.event_type,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Publish job created event
   */
  async publishJobCreated(jobId: string, data: {
    scan_type: string;
    target: string;
    sandbox_tier?: string;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'job:created',
      data
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish job started event
   */
  async publishJobStarted(jobId: string, data: {
    started_at: Date;
    sandbox_tier?: string;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'job:started',
      data
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish job progress event
   */
  async publishJobProgress(jobId: string, progress: number, message?: string, currentPhase?: string): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'job:progress',
      data: {
        progress,
        message,
        current_phase: currentPhase
      }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish job completed event
   */
  async publishJobCompleted(jobId: string, data: {
    completed_at: Date;
    duration_seconds: number;
    results_count: number;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'job:completed',
      data
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish job failed event
   */
  async publishJobFailed(jobId: string, data: {
    error: string;
    failed_at: Date;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'job:failed',
      data
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish job cancelled event
   */
  async publishJobCancelled(jobId: string, data: {
    cancelled_at: Date;
    cancelled_by: string;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'job:cancelled',
      data
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish tool started event
   */
  async publishToolStarted(jobId: string, tool: string): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'tool:started',
      data: { tool }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish tool output event
   */
  async publishToolOutput(jobId: string, tool: string, output: string): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'tool:output',
      data: { tool, output }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish tool completed event
   */
  async publishToolCompleted(jobId: string, tool: string, data: {
    duration_seconds: number;
    success: boolean;
    results_count?: number;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'tool:completed',
      data: { tool, ...data }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish vulnerability found event
   */
  async publishVulnerabilityFound(jobId: string, vulnerability: {
    severity: Severity;
    title: string;
    cve_id?: string;
    cvss_score?: number;
    affected_target?: string;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'vulnerability:found',
      data: vulnerability
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish malware detected event
   */
  async publishMalwareDetected(jobId: string, malware: {
    sha256: string;
    malware_family?: string;
    threat_level?: string;
    yara_matches?: string[];
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'malware:detected',
      data: malware
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish IOC extracted event
   */
  async publishIOCExtracted(jobId: string, ioc: {
    ioc_type: string;
    ioc_value: string;
    confidence?: number;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'ioc:extracted',
      data: ioc
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish exploit success event
   */
  async publishExploitSuccess(jobId: string, exploit: {
    exploit_name: string;
    target: string;
    payload?: string;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'exploit:success',
      data: exploit
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish exploit failed event
   */
  async publishExploitFailed(jobId: string, exploit: {
    exploit_name: string;
    target: string;
    error: string;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'exploit:failed',
      data: exploit
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish agent spawned event
   */
  async publishAgentSpawned(jobId: string, agent: {
    agent_id: string;
    agent_role?: string;
    model?: string;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'agent:spawned',
      data: agent
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish agent thinking event
   */
  async publishAgentThinking(jobId: string, agentId: string, thought: string): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'agent:thinking',
      data: {
        agent_id: agentId,
        thought
      }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish agent action event
   */
  async publishAgentAction(jobId: string, agentId: string, action: string): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'agent:action',
      data: {
        agent_id: agentId,
        action
      }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish agent completed event
   */
  async publishAgentCompleted(jobId: string, agentId: string, result: any): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'agent:completed',
      data: {
        agent_id: agentId,
        result
      }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish workflow phase started event
   */
  async publishWorkflowPhaseStarted(jobId: string, phase: string): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'workflow:phase_started',
      data: { phase }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish workflow phase completed event
   */
  async publishWorkflowPhaseCompleted(jobId: string, phase: string, data: any): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'workflow:phase_completed',
      data: { phase, ...data }
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish Nexus recall event
   */
  async publishNexusRecall(jobId: string, data: {
    query: string;
    results_count: number;
    latency_ms: number;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'nexus:recall',
      data
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Publish Nexus stored event
   */
  async publishNexusStored(jobId: string, data: {
    type: string;
    content_length: number;
  }): Promise<void> {
    const event: WebSocketEvent = {
      job_id: jobId,
      timestamp: new Date().toISOString(),
      event_type: 'nexus:stored',
      data
    };

    await this.publishEvent(jobId, event);
  }

  /**
   * Close publisher connection
   */
  async close(): Promise<void> {
    try {
      await this.publisher.quit();
      this.logger.info('Redis publisher connection closed');
    } catch (error) {
      this.logger.error('Error closing Redis publisher', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
}

/**
 * Create singleton event publisher
 */
let publisherInstance: WebSocketEventPublisher | null = null;

export function createEventPublisher(): WebSocketEventPublisher {
  if (!publisherInstance) {
    publisherInstance = new WebSocketEventPublisher({
      redis: {
        host: config.redis.host,
        port: config.redis.port,
        password: config.redis.password,
        db: config.redis.db
      },
      channelPrefix: `${config.redis.keyPrefix}ws:`
    });
  }

  return publisherInstance;
}

export function getEventPublisher(): WebSocketEventPublisher {
  if (!publisherInstance) {
    throw new Error('Event publisher not initialized. Call createEventPublisher() first.');
  }

  return publisherInstance;
}

export async function closeEventPublisher(): Promise<void> {
  if (publisherInstance) {
    await publisherInstance.close();
    publisherInstance = null;
  }
}
