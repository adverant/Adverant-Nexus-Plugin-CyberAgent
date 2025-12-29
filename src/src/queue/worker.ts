/**
 * BullMQ Worker
 *
 * Main worker process for processing scan jobs.
 * Implements queue health management including:
 * - Stale job cleanup on startup
 * - Invalid job_id detection and removal
 * - Queue metrics collection
 */

import { Worker, Job, Queue } from 'bullmq';
import { validate as uuidValidate } from 'uuid';
import { JobData, QUEUE_NAMES } from './queue-config';
import { PentestProcessor, MalwareProcessor } from './processors';
import { initializeDatabase, closeDatabase } from '../database/connection';
import { createEventPublisher, closeEventPublisher } from '../websocket';
import { logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Queue cleanup configuration
 */
const CLEANUP_CONFIG = {
  /** Maximum number of jobs to inspect per queue during cleanup */
  MAX_JOBS_TO_INSPECT: 1000,
  /** Jobs older than this (in ms) are considered stale if still in waiting/active state */
  STALE_JOB_AGE_MS: 24 * 60 * 60 * 1000, // 24 hours
  /** Enable cleanup on startup */
  ENABLE_STARTUP_CLEANUP: true,
} as const;

/**
 * Redis connection options for workers
 */
const connectionOptions = {
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  db: config.redis.db,
  maxRetriesPerRequest: null,
  enableReadyCheck: false
};

/**
 * Cleanup result for a single queue
 */
interface QueueCleanupResult {
  queueName: string;
  inspectedJobs: number;
  removedInvalidJobs: number;
  removedStaleJobs: number;
  errors: string[];
  durationMs: number;
}

/**
 * Worker manager class
 */
class WorkerManager {
  private workers: Worker[] = [];
  private queues: Map<string, Queue> = new Map();
  private processors: Map<string, any> = new Map();
  private logger = createContextLogger('WorkerManager');

  constructor() {
    // Processors are initialized in start() after event publisher is created
  }

  /**
   * Initialize processors (must be called after event publisher is created)
   */
  private initializeProcessors(): void {
    this.processors.set(QUEUE_NAMES.PENTEST, new PentestProcessor());
    this.processors.set(QUEUE_NAMES.MALWARE, new MalwareProcessor());
  }

  /**
   * Initialize queue instances for cleanup and monitoring
   */
  private initializeQueues(): void {
    for (const queueName of Object.values(QUEUE_NAMES)) {
      const queue = new Queue(queueName, {
        connection: connectionOptions,
      });
      this.queues.set(queueName, queue);
    }
  }

  /**
   * Validate a job's data for correctness.
   * Returns null if valid, or error message if invalid.
   */
  private validateJobData(jobData: JobData | undefined): string | null {
    if (!jobData) {
      return 'Job data is missing or undefined';
    }

    const { job_id, target, scan_type } = jobData;

    // Check job_id exists and is a string
    if (!job_id || typeof job_id !== 'string') {
      return `Invalid job_id: expected string, got ${typeof job_id}`;
    }

    // Check job_id is a valid UUID
    if (!uuidValidate(job_id)) {
      return `Invalid job_id format: "${job_id}" is not a valid UUID`;
    }

    // Check target exists
    if (!target || typeof target !== 'string' || target.trim().length === 0) {
      return `Invalid target: expected non-empty string, got ${typeof target}`;
    }

    return null; // Valid
  }

  /**
   * Clean up invalid and stale jobs from a specific queue.
   * This prevents infinite retry loops from bad job data.
   */
  private async cleanupQueue(queueName: string): Promise<QueueCleanupResult> {
    const startTime = Date.now();
    const result: QueueCleanupResult = {
      queueName,
      inspectedJobs: 0,
      removedInvalidJobs: 0,
      removedStaleJobs: 0,
      errors: [],
      durationMs: 0,
    };

    const queue = this.queues.get(queueName);
    if (!queue) {
      result.errors.push(`Queue not found: ${queueName}`);
      result.durationMs = Date.now() - startTime;
      return result;
    }

    try {
      // Get waiting jobs
      const waitingJobs = await queue.getJobs(['waiting'], 0, CLEANUP_CONFIG.MAX_JOBS_TO_INSPECT);

      // Get active jobs (might be stale from crashed worker)
      const activeJobs = await queue.getJobs(['active'], 0, CLEANUP_CONFIG.MAX_JOBS_TO_INSPECT);

      // Get delayed jobs
      const delayedJobs = await queue.getJobs(['delayed'], 0, CLEANUP_CONFIG.MAX_JOBS_TO_INSPECT);

      const allJobs = [...waitingJobs, ...activeJobs, ...delayedJobs];
      result.inspectedJobs = allJobs.length;

      this.logger.info('Starting queue cleanup', {
        queue: queueName,
        waiting_count: waitingJobs.length,
        active_count: activeJobs.length,
        delayed_count: delayedJobs.length,
        total_jobs: allJobs.length
      });

      const now = Date.now();

      for (const job of allJobs) {
        try {
          // Check 1: Validate job data format
          const validationError = this.validateJobData(job.data);
          if (validationError) {
            this.logger.warn('Removing invalid job from queue', {
              queue: queueName,
              bullmq_job_id: job.id,
              job_data_job_id: job.data?.job_id || 'MISSING',
              validation_error: validationError,
              job_state: await job.getState()
            });

            await job.remove();
            result.removedInvalidJobs++;
            continue;
          }

          // Check 2: Remove stale jobs (waiting/active for too long)
          const jobAge = now - job.timestamp;
          if (jobAge > CLEANUP_CONFIG.STALE_JOB_AGE_MS) {
            const jobState = await job.getState();
            if (jobState === 'waiting' || jobState === 'active' || jobState === 'delayed') {
              this.logger.warn('Removing stale job from queue', {
                queue: queueName,
                bullmq_job_id: job.id,
                job_data_job_id: job.data?.job_id,
                age_hours: Math.round(jobAge / (60 * 60 * 1000)),
                job_state: jobState
              });

              await job.remove();
              result.removedStaleJobs++;
              continue;
            }
          }
        } catch (jobError) {
          const errorMsg = jobError instanceof Error ? jobError.message : String(jobError);
          result.errors.push(`Error processing job ${job.id}: ${errorMsg}`);
          this.logger.error('Error during job cleanup', {
            queue: queueName,
            bullmq_job_id: job.id,
            error: errorMsg
          });
        }
      }

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      result.errors.push(`Queue cleanup failed: ${errorMsg}`);
      this.logger.error('Queue cleanup failed', {
        queue: queueName,
        error: errorMsg
      });
    }

    result.durationMs = Date.now() - startTime;
    return result;
  }

  /**
   * Clean up all queues on startup.
   * Removes invalid jobs and stale jobs to prevent processing issues.
   */
  private async cleanupAllQueues(): Promise<void> {
    if (!CLEANUP_CONFIG.ENABLE_STARTUP_CLEANUP) {
      this.logger.info('Queue cleanup disabled by configuration');
      return;
    }

    this.logger.info('Starting queue cleanup on worker startup...');
    const startTime = Date.now();
    const results: QueueCleanupResult[] = [];

    for (const queueName of this.queues.keys()) {
      const result = await this.cleanupQueue(queueName);
      results.push(result);
    }

    // Aggregate results
    const totalInspected = results.reduce((sum, r) => sum + r.inspectedJobs, 0);
    const totalInvalidRemoved = results.reduce((sum, r) => sum + r.removedInvalidJobs, 0);
    const totalStaleRemoved = results.reduce((sum, r) => sum + r.removedStaleJobs, 0);
    const totalErrors = results.reduce((sum, r) => sum + r.errors.length, 0);
    const totalDurationMs = Date.now() - startTime;

    this.logger.info('Queue cleanup completed', {
      total_queues: results.length,
      total_jobs_inspected: totalInspected,
      total_invalid_removed: totalInvalidRemoved,
      total_stale_removed: totalStaleRemoved,
      total_errors: totalErrors,
      duration_ms: totalDurationMs,
      results_by_queue: results.map(r => ({
        queue: r.queueName,
        inspected: r.inspectedJobs,
        invalid_removed: r.removedInvalidJobs,
        stale_removed: r.removedStaleJobs,
        errors: r.errors.length
      }))
    });

    if (totalInvalidRemoved > 0 || totalStaleRemoved > 0) {
      this.logger.warn('Jobs were removed during startup cleanup', {
        invalid_jobs_removed: totalInvalidRemoved,
        stale_jobs_removed: totalStaleRemoved,
        message: 'Review job submission process to prevent invalid job_ids'
      });
    }
  }

  /**
   * Start all workers
   */
  async start(): Promise<void> {
    try {
      this.logger.info('Starting workers...', {
        concurrency: config.queue.concurrency,
        cleanup_enabled: CLEANUP_CONFIG.ENABLE_STARTUP_CLEANUP
      });

      // Initialize dependencies
      await initializeDatabase(config.database);
      this.logger.info('Database initialized for workers');

      createEventPublisher();
      this.logger.info('Event publisher initialized for workers');

      // Initialize processors after event publisher is created
      this.initializeProcessors();
      this.logger.info('Processors initialized', {
        processors: Array.from(this.processors.keys())
      });

      // Initialize queues for cleanup and monitoring
      this.initializeQueues();
      this.logger.info('Queues initialized for cleanup', {
        queues: Array.from(this.queues.keys())
      });

      // CLEANUP PHASE: Clean up invalid and stale jobs before starting workers
      await this.cleanupAllQueues();

      // Create worker for each queue
      for (const [queueName, processor] of this.processors.entries()) {
        const worker = new Worker(
          queueName,
          async (job: Job<JobData>) => {
            return processor.process(job);
          },
          {
            connection: connectionOptions,
            concurrency: config.queue.concurrency,
            limiter: {
              max: 10, // Max 10 jobs per...
              duration: 1000 // ...1 second
            }
          }
        );

        // Setup worker event handlers
        this.setupWorkerEvents(worker, queueName);

        this.workers.push(worker);
        this.logger.info(`Worker started for queue: ${queueName}`);
      }

      this.logger.info('All workers started successfully', {
        worker_count: this.workers.length
      });
    } catch (error) {
      this.logger.error('Failed to start workers', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Setup worker event handlers
   */
  private setupWorkerEvents(worker: Worker, queueName: string): void {
    worker.on('completed', (job) => {
      this.logger.info(`Job completed: ${queueName}`, {
        job_id: job.id,
        duration: Date.now() - job.timestamp
      });
    });

    worker.on('failed', (job, error) => {
      this.logger.error(`Job failed: ${queueName}`, {
        job_id: job?.id,
        error: error.message,
        attempts: job?.attemptsMade,
        max_attempts: job?.opts.attempts
      });
    });

    worker.on('active', (job) => {
      this.logger.info(`Job active: ${queueName}`, {
        job_id: job.id,
        attempt: job.attemptsMade + 1
      });
    });

    worker.on('stalled', (jobId) => {
      this.logger.warn(`Job stalled: ${queueName}`, {
        job_id: jobId
      });
    });

    worker.on('error', (error) => {
      this.logger.error(`Worker error: ${queueName}`, {
        error: error.message
      });
    });

    worker.on('closing', () => {
      this.logger.info(`Worker closing: ${queueName}`);
    });
  }

  /**
   * Gracefully stop all workers
   */
  async stop(): Promise<void> {
    try {
      this.logger.info('Stopping workers...');

      // Close all workers
      await Promise.all(this.workers.map(worker => worker.close()));
      this.logger.info('All workers closed');

      // Close all queue instances
      await Promise.all(
        Array.from(this.queues.values()).map(queue => queue.close())
      );
      this.logger.info('All queue instances closed');

      // Close event publisher
      await closeEventPublisher();
      this.logger.info('Event publisher closed');

      // Close database
      await closeDatabase();
      this.logger.info('Database closed');

      this.logger.info('Worker shutdown completed');
    } catch (error) {
      this.logger.error('Error during worker shutdown', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get worker statistics
   */
  getStats(): any {
    return {
      active_workers: this.workers.length,
      queues: Array.from(this.processors.keys()),
      concurrency: config.queue.concurrency
    };
  }
}

/**
 * Main worker entry point
 */
async function startWorker(): Promise<void> {
  const workerManager = new WorkerManager();

  try {
    logger.info('Nexus-CyberAgent Worker starting...', {
      env: config.env,
      node_version: process.version
    });

    // Start workers
    await workerManager.start();

    logger.info('Worker started successfully', {
      stats: workerManager.getStats()
    });

    // Handle graceful shutdown
    const shutdown = async (signal: string) => {
      logger.info(`${signal} received, shutting down workers...`);

      try {
        await workerManager.stop();
        logger.info('Workers shutdown completed');
        process.exit(0);
      } catch (error) {
        logger.error('Error during shutdown', {
          error: error instanceof Error ? error.message : 'Unknown error'
        });
        process.exit(1);
      }
    };

    // Register shutdown handlers
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    // Handle uncaught errors
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', {
        error: error.message,
        stack: error.stack
      });
      process.exit(1);
    });

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled rejection', {
        reason: reason instanceof Error ? reason.message : String(reason)
      });
      process.exit(1);
    });

  } catch (error) {
    logger.error('Failed to start worker', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    });
    process.exit(1);
  }
}

// Start worker if this is the main module
if (require.main === module) {
  startWorker();
}

export { WorkerManager, startWorker };
