/**
 * BullMQ Queue Configuration
 *
 * Job queue configuration for asynchronous scan processing.
 *
 * IMPORTANT: BullMQ v5 separates Queue and QueueEvents:
 * - Queue: For adding jobs and managing queue state
 * - QueueEvents: For listening to job lifecycle events (active, completed, failed, stalled)
 */

import { Queue, QueueEvents, Job, JobsOptions } from 'bullmq';
import { validate as uuidValidate } from 'uuid';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';
import { ScanType } from '../types';

/**
 * Queue connection options
 */
const connectionOptions = {
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  db: config.redis.db,
  maxRetriesPerRequest: null, // Required for BullMQ
  enableReadyCheck: false,
  retryStrategy: (times: number) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  }
};

/**
 * Default job options
 */
export const defaultJobOptions: JobsOptions = {
  attempts: config.queue.maxRetryAttempts,
  backoff: {
    type: 'exponential',
    delay: config.queue.retryDelayMs
  },
  removeOnComplete: {
    age: 86400, // Keep completed jobs for 24 hours
    count: 1000 // Keep max 1000 completed jobs
  },
  removeOnFail: {
    age: 604800, // Keep failed jobs for 7 days
    count: 5000 // Keep max 5000 failed jobs
  }
};

/**
 * Queue names by scan type
 * NOTE: BullMQ does not allow colons in queue names, so we use underscores
 */
export const QUEUE_NAMES = {
  PENTEST: 'cyberagent_pentest',
  MALWARE: 'cyberagent_malware',
  EXPLOIT: 'cyberagent_exploit',
  C2: 'cyberagent_c2',
  APT_SIMULATION: 'cyberagent_apt_simulation'
} as const;

/**
 * Get queue name for scan type
 */
export function getQueueName(scanType: ScanType): string {
  const queueMap: Record<ScanType, string> = {
    pentest: QUEUE_NAMES.PENTEST,
    malware: QUEUE_NAMES.MALWARE,
    exploit: QUEUE_NAMES.EXPLOIT,
    c2: QUEUE_NAMES.C2,
    apt_simulation: QUEUE_NAMES.APT_SIMULATION
  };

  return queueMap[scanType];
}

/**
 * Job data interface
 */
export interface JobData {
  job_id: string;
  org_id: string;
  user_id: string;
  scan_type: ScanType;
  target: string;
  sandbox_tier?: string;
  tools: string[];
  config: Record<string, any>;
  priority: number;

  /**
   * Local file path for sandbox-first analysis (shared volume)
   * When provided, the processor reads from this path instead of fetching target URL
   */
  local_file_path?: string;

  /**
   * File metadata for local file analysis
   */
  file_metadata?: {
    filename: string;
    mime_type?: string;
    size?: number;
  };
}

/**
 * Queue Manager Class
 *
 * Manages BullMQ queues for CyberAgent scan job processing.
 * Uses separate QueueEvents instances for job lifecycle monitoring (BullMQ v5 pattern).
 */
export class QueueManager {
  private queues: Map<string, Queue>;
  private queueEvents: Map<string, QueueEvents>;
  private logger: Logger;

  constructor() {
    this.queues = new Map();
    this.queueEvents = new Map();
    this.logger = createContextLogger('QueueManager');
  }

  /**
   * Initialize all queues and their event listeners
   */
  async initialize(): Promise<void> {
    try {
      this.logger.info('Initializing job queues...');

      // Create queue and queue events for each scan type
      for (const [type, queueName] of Object.entries(QUEUE_NAMES)) {
        // Create the queue for job management
        const queue = new Queue(queueName, {
          connection: connectionOptions,
          defaultJobOptions
        });

        // Create QueueEvents for job lifecycle monitoring (BullMQ v5 pattern)
        const queueEventsInstance = new QueueEvents(queueName, {
          connection: connectionOptions
        });

        // Setup event handlers using QueueEvents (not Queue)
        this.setupQueueEventHandlers(queue, queueEventsInstance, type);

        this.queues.set(queueName, queue);
        this.queueEvents.set(queueName, queueEventsInstance);
        this.logger.info(`Queue initialized: ${queueName}`);
      }

      this.logger.info('All job queues initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize queues', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Setup queue event handlers
   *
   * BullMQ v5 separates events:
   * - Queue: error, waiting (when job added), progress, removed, paused, resumed, cleaned
   * - QueueEvents: active, completed, failed, stalled, delayed, etc.
   */
  private setupQueueEventHandlers(queue: Queue, queueEvents: QueueEvents, type: string): void {
    // Queue-level events (available on Queue class in BullMQ v5)
    queue.on('error', (error: Error) => {
      this.logger.error(`Queue error: ${type}`, {
        error: error.message
      });
    });

    // 'waiting' on Queue fires when job is added, provides Job object
    queue.on('waiting', (job: Job) => {
      this.logger.debug(`Job added to queue: ${type}`, {
        job_id: job.id,
        job_name: job.name
      });
    });

    // QueueEvents listeners (BullMQ v5 pattern for job lifecycle events)
    queueEvents.on('active', ({ jobId, prev }, id) => {
      this.logger.info(`Job active: ${type}`, {
        job_id: jobId,
        prev_state: prev,
        event_id: id
      });
    });

    queueEvents.on('completed', ({ jobId, returnvalue, prev }, id) => {
      this.logger.info(`Job completed: ${type}`, {
        job_id: jobId,
        result: returnvalue,
        prev_state: prev,
        event_id: id
      });
    });

    queueEvents.on('failed', ({ jobId, failedReason, prev }, id) => {
      this.logger.error(`Job failed: ${type}`, {
        job_id: jobId,
        error: failedReason,
        prev_state: prev,
        event_id: id
      });
    });

    queueEvents.on('stalled', ({ jobId }, id) => {
      this.logger.warn(`Job stalled: ${type}`, {
        job_id: jobId,
        event_id: id
      });
    });

    queueEvents.on('error', (error: Error) => {
      this.logger.error(`QueueEvents error: ${type}`, {
        error: error.message
      });
    });
  }

  /**
   * Add job to queue
   *
   * IMPORTANT: Validates job_id is a proper UUID before adding to queue.
   * This is a critical security measure to prevent invalid job IDs from
   * causing infinite retry loops when PostgreSQL rejects them.
   */
  async addJob(
    scanType: ScanType,
    jobData: JobData,
    options?: JobsOptions
  ): Promise<Job<JobData>> {
    // CRITICAL: Validate job_id is a valid UUID before adding to queue
    // This prevents invalid job IDs from causing database errors and infinite retries
    if (!jobData.job_id || typeof jobData.job_id !== 'string') {
      const error = new Error(
        `Invalid job_id: expected string, got ${typeof jobData.job_id}. ` +
        `Job IDs must be valid UUIDs generated by the database.`
      );
      this.logger.error('Rejecting job with missing/invalid job_id', {
        job_id: jobData.job_id,
        scan_type: scanType,
        target: jobData.target
      });
      throw error;
    }

    if (!uuidValidate(jobData.job_id)) {
      const error = new Error(
        `Invalid job_id format: "${jobData.job_id}" is not a valid UUID. ` +
        `Job IDs must be valid UUIDs (e.g., "550e8400-e29b-41d4-a716-446655440000"). ` +
        `This appears to be a custom-formatted ID that will cause database errors.`
      );
      this.logger.error('Rejecting job with non-UUID job_id', {
        job_id: jobData.job_id,
        scan_type: scanType,
        target: jobData.target,
        suggestion: 'Jobs must be created through the API to get a valid UUID'
      });
      throw error;
    }

    const queueName = getQueueName(scanType);
    const queue = this.queues.get(queueName);

    if (!queue) {
      throw new Error(`Queue not found for scan type: ${scanType}`);
    }

    // Set priority (BullMQ uses lower numbers for higher priority, opposite of our 1-10 scale)
    const bullMQPriority = 11 - jobData.priority;

    const job = await queue.add(`scan-${scanType}`, jobData, {
      ...options,
      priority: bullMQPriority,
      jobId: jobData.job_id // Use our job ID as BullMQ job ID
    });

    this.logger.info('Job added to queue', {
      job_id: job.id,
      scan_type: scanType,
      queue: queueName,
      priority: jobData.priority
    });

    return job;
  }

  /**
   * Get job by ID
   */
  async getJob(scanType: ScanType, jobId: string): Promise<Job<JobData> | undefined> {
    const queueName = getQueueName(scanType);
    const queue = this.queues.get(queueName);

    if (!queue) {
      throw new Error(`Queue not found for scan type: ${scanType}`);
    }

    return queue.getJob(jobId);
  }

  /**
   * Cancel job
   */
  async cancelJob(scanType: ScanType, jobId: string): Promise<void> {
    const job = await this.getJob(scanType, jobId);

    if (!job) {
      throw new Error(`Job not found: ${jobId}`);
    }

    await job.remove();

    this.logger.info('Job cancelled', {
      job_id: jobId,
      scan_type: scanType
    });
  }

  /**
   * Get queue statistics
   */
  async getQueueStats(scanType?: ScanType): Promise<any> {
    if (scanType) {
      const queueName = getQueueName(scanType);
      const queue = this.queues.get(queueName);

      if (!queue) {
        throw new Error(`Queue not found for scan type: ${scanType}`);
      }

      return this.getQueueCounts(queue);
    }

    // Get stats for all queues
    const stats: Record<string, any> = {};
    const entries = Array.from(this.queues.entries());

    for (const [queueName, queue] of entries) {
      stats[queueName] = await this.getQueueCounts(queue);
    }

    return stats;
  }

  /**
   * Get queue counts
   *
   * Note: BullMQ v5 removed getPausedCount() - paused jobs are in the 'waiting' state
   * with the queue in paused mode.
   */
  private async getQueueCounts(queue: Queue): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
    isPaused: boolean;
    total: number;
  }> {
    const [
      waiting,
      active,
      completed,
      failed,
      delayed,
      isPaused
    ] = await Promise.all([
      queue.getWaitingCount(),
      queue.getActiveCount(),
      queue.getCompletedCount(),
      queue.getFailedCount(),
      queue.getDelayedCount(),
      queue.isPaused()
    ]);

    return {
      waiting,
      active,
      completed,
      failed,
      delayed,
      isPaused,
      total: waiting + active + completed + failed + delayed
    };
  }

  /**
   * Get jobs by status
   */
  async getJobsByStatus(
    scanType: ScanType,
    status: 'waiting' | 'active' | 'completed' | 'failed' | 'delayed',
    start: number = 0,
    end: number = 10
  ): Promise<Job<JobData>[]> {
    const queueName = getQueueName(scanType);
    const queue = this.queues.get(queueName);

    if (!queue) {
      throw new Error(`Queue not found for scan type: ${scanType}`);
    }

    switch (status) {
      case 'waiting':
        return queue.getWaiting(start, end);
      case 'active':
        return queue.getActive(start, end);
      case 'completed':
        return queue.getCompleted(start, end);
      case 'failed':
        return queue.getFailed(start, end);
      case 'delayed':
        return queue.getDelayed(start, end);
      default:
        throw new Error(`Invalid status: ${status}`);
    }
  }

  /**
   * Pause queue
   */
  async pauseQueue(scanType: ScanType): Promise<void> {
    const queueName = getQueueName(scanType);
    const queue = this.queues.get(queueName);

    if (!queue) {
      throw new Error(`Queue not found for scan type: ${scanType}`);
    }

    await queue.pause();
    this.logger.info(`Queue paused: ${queueName}`);
  }

  /**
   * Resume queue
   */
  async resumeQueue(scanType: ScanType): Promise<void> {
    const queueName = getQueueName(scanType);
    const queue = this.queues.get(queueName);

    if (!queue) {
      throw new Error(`Queue not found for scan type: ${scanType}`);
    }

    await queue.resume();
    this.logger.info(`Queue resumed: ${queueName}`);
  }

  /**
   * Clean old jobs
   */
  async cleanQueue(
    scanType: ScanType,
    grace: number = 86400000, // 24 hours
    status?: 'completed' | 'failed'
  ): Promise<void> {
    const queueName = getQueueName(scanType);
    const queue = this.queues.get(queueName);

    if (!queue) {
      throw new Error(`Queue not found for scan type: ${scanType}`);
    }

    if (status) {
      await queue.clean(grace, 1000, status);
    } else {
      await queue.clean(grace, 1000, 'completed');
      await queue.clean(grace, 1000, 'failed');
    }

    this.logger.info(`Queue cleaned: ${queueName}`, { grace, status });
  }

  /**
   * Close all queues and queue events listeners
   */
  async close(): Promise<void> {
    try {
      this.logger.info('Closing all queues...');

      // Close QueueEvents first (they're listeners)
      const queueEventsEntries = Array.from(this.queueEvents.entries());
      for (const [queueName, queueEventsInstance] of queueEventsEntries) {
        await queueEventsInstance.close();
        this.logger.debug(`QueueEvents closed: ${queueName}`);
      }
      this.queueEvents.clear();

      // Then close Queues
      const queueEntries = Array.from(this.queues.entries());
      for (const [queueName, queue] of queueEntries) {
        await queue.close();
        this.logger.info(`Queue closed: ${queueName}`);
      }
      this.queues.clear();

      this.logger.info('All queues closed successfully');
    } catch (error) {
      this.logger.error('Error closing queues', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }
}

/**
 * Singleton queue manager instance
 */
let queueManagerInstance: QueueManager | null = null;

/**
 * Initialize queue manager
 */
export async function initializeQueueManager(): Promise<QueueManager> {
  if (!queueManagerInstance) {
    queueManagerInstance = new QueueManager();
    await queueManagerInstance.initialize();
  }

  return queueManagerInstance;
}

/**
 * Get queue manager instance
 */
export function getQueueManager(): QueueManager {
  if (!queueManagerInstance) {
    throw new Error('Queue manager not initialized. Call initializeQueueManager() first.');
  }

  return queueManagerInstance;
}

/**
 * Close queue manager
 */
export async function closeQueueManager(): Promise<void> {
  if (queueManagerInstance) {
    await queueManagerInstance.close();
    queueManagerInstance = null;
  }
}
