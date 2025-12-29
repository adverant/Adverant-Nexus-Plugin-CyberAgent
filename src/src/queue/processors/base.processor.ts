/**
 * Base Job Processor
 *
 * Abstract base class for all job processors with common functionality.
 * Implements input validation, circuit breaker patterns for non-transient errors,
 * and robust error handling to prevent infinite retry loops.
 */

import { Job, UnrecoverableError } from 'bullmq';
import { validate as uuidValidate } from 'uuid';
import { JobData } from '../queue-config';
import { ScanJobRepository, ScanResultRepository } from '../../database/repositories';
import { getEventPublisher } from '../../websocket';
import { Logger, createContextLogger } from '../../utils/logger';
import { JobStatus, ScanType } from '../../types';
import axios, { AxiosInstance } from 'axios';
import config from '../../config';
import { getTestingSandboxClient } from '../../sandbox/testing-sandbox-client';

/**
 * Non-transient database error patterns that should not be retried.
 * These indicate schema violations, constraint violations, or data format errors
 * that will never succeed regardless of retry attempts.
 */
const NON_TRANSIENT_DB_ERROR_PATTERNS = [
  'invalid input syntax for type uuid',
  'violates check constraint',
  'violates foreign key constraint',
  'violates unique constraint',
  'violates not-null constraint',
  'value too long for type',
  'invalid input syntax for type',
  'duplicate key value',
  'null value in column',
] as const;

/**
 * Sandbox tier URLs
 */
const SANDBOX_URLS = {
  tier1: config.sandboxes.tier1.url,
  tier2: config.sandboxes.tier2.url,
  tier3: config.sandboxes.tier3.url
};

/**
 * Base Processor Class
 */
export abstract class BaseJobProcessor {
  protected jobRepository: ScanJobRepository;
  protected resultRepository: ScanResultRepository;
  protected eventPublisher: ReturnType<typeof getEventPublisher>;
  protected logger: Logger;
  protected scanType: ScanType;

  constructor(scanType: ScanType) {
    this.scanType = scanType;
    this.jobRepository = new ScanJobRepository();
    this.resultRepository = new ScanResultRepository();
    this.eventPublisher = getEventPublisher();
    this.logger = createContextLogger(`${scanType}Processor`);
  }

  /**
   * Validate job data before processing.
   * Throws UnrecoverableError for invalid data to prevent retry loops.
   */
  private validateJobData(jobData: JobData): void {
    const { job_id, target, scan_type } = jobData;

    // Validate job_id is a valid UUID
    if (!job_id || typeof job_id !== 'string') {
      throw new UnrecoverableError(
        `Invalid job data: job_id is required and must be a string. Received: ${typeof job_id}`
      );
    }

    if (!uuidValidate(job_id)) {
      throw new UnrecoverableError(
        `Invalid job_id format: "${job_id}" is not a valid UUID. ` +
        `Job IDs must be valid UUIDs (e.g., "550e8400-e29b-41d4-a716-446655440000"). ` +
        `This job will not be retried.`
      );
    }

    // Validate target is present
    if (!target || typeof target !== 'string' || target.trim().length === 0) {
      throw new UnrecoverableError(
        `Invalid job data: target is required and must be a non-empty string. ` +
        `Job ID: ${job_id}. This job will not be retried.`
      );
    }

    // Validate scan_type matches processor
    if (scan_type && scan_type !== this.scanType) {
      throw new UnrecoverableError(
        `Scan type mismatch: Job has scan_type "${scan_type}" but was routed to ` +
        `"${this.scanType}" processor. Job ID: ${job_id}. This job will not be retried.`
      );
    }
  }

  /**
   * Check if an error is non-transient (should not be retried).
   * Non-transient errors are typically database schema violations or data format errors.
   */
  private isNonTransientError(error: Error): boolean {
    const errorMessage = error.message.toLowerCase();
    return NON_TRANSIENT_DB_ERROR_PATTERNS.some(pattern =>
      errorMessage.includes(pattern.toLowerCase())
    );
  }

  /**
   * Convert a transient error to UnrecoverableError if it matches non-transient patterns.
   * This implements the circuit breaker pattern for database errors.
   */
  private wrapNonTransientError(error: Error, context: string): Error {
    if (this.isNonTransientError(error)) {
      this.logger.warn('Converting non-transient error to UnrecoverableError', {
        context,
        original_error: error.message,
        pattern_matched: NON_TRANSIENT_DB_ERROR_PATTERNS.find(p =>
          error.message.toLowerCase().includes(p.toLowerCase())
        )
      });

      return new UnrecoverableError(
        `Non-transient database error in ${context}: ${error.message}. ` +
        `This indicates a data format or schema violation that cannot be fixed by retrying. ` +
        `This job will not be retried.`
      );
    }
    return error;
  }

  /**
   * Process job (main entry point)
   *
   * Implements comprehensive validation and circuit breaker patterns:
   * 1. Validates job_id is a proper UUID before any database operations
   * 2. Validates required fields (target, scan_type)
   * 3. Wraps non-transient database errors as UnrecoverableError to prevent infinite retries
   */
  async process(job: Job<JobData>): Promise<any> {
    const { job_id, target, tools, config: jobConfig } = job.data;

    // PHASE 1: Validate job data BEFORE any processing
    // This catches invalid UUIDs before they reach the database
    try {
      this.validateJobData(job.data);
    } catch (validationError) {
      this.logger.error('Job validation failed - job will not be retried', {
        job_id: job_id || 'MISSING',
        bullmq_job_id: job.id,
        error: validationError instanceof Error ? validationError.message : 'Unknown validation error',
        job_data_keys: Object.keys(job.data)
      });
      throw validationError; // Re-throw UnrecoverableError
    }

    // PHASE 2: Process the validated job
    try {
      this.logger.info('Processing job started', {
        job_id,
        scan_type: this.scanType,
        target,
        tools,
        bullmq_job_id: job.id,
        attempt: job.attemptsMade + 1
      });

      // Update job status to running
      await this.updateJobStatusSafe(job_id, 'running');
      await this.eventPublisher.publishJobStarted(job_id, {
        started_at: new Date(),
        sandbox_tier: job.data.sandbox_tier
      });

      // Execute scan (implemented by subclass)
      const result = await this.executeScan(job);

      // Update job status to completed
      await this.updateJobStatusSafe(job_id, 'completed');
      await this.eventPublisher.publishJobCompleted(job_id, {
        completed_at: new Date(),
        duration_seconds: (Date.now() - job.timestamp) / 1000,
        results_count: result.results_count || 0
      });

      this.logger.info('Processing job completed', {
        job_id,
        results_count: result.results_count,
        duration_seconds: (Date.now() - job.timestamp) / 1000
      });

      return result;
    } catch (error) {
      const originalError = error instanceof Error ? error : new Error(String(error));

      this.logger.error('Processing job failed', {
        job_id,
        bullmq_job_id: job.id,
        attempt: job.attemptsMade + 1,
        error: originalError.message,
        stack: originalError.stack,
        is_non_transient: this.isNonTransientError(originalError)
      });

      // PHASE 3: Attempt to update job status to failed
      // Use safe method that won't throw on non-transient errors
      try {
        await this.updateJobStatusSafe(job_id, 'failed', originalError.message);
        await this.eventPublisher.publishJobFailed(job_id, {
          error: originalError.message,
          failed_at: new Date()
        });
      } catch (statusUpdateError) {
        // Log but don't let status update failure mask the original error
        this.logger.error('Failed to update job status after processing error', {
          job_id,
          original_error: originalError.message,
          status_update_error: statusUpdateError instanceof Error ? statusUpdateError.message : 'Unknown'
        });
      }

      // PHASE 4: Apply circuit breaker - convert non-transient errors
      const finalError = this.wrapNonTransientError(originalError, `job processing for ${job_id}`);
      throw finalError;
    }
  }

  /**
   * Execute scan (implemented by subclass)
   */
  protected abstract executeScan(job: Job<JobData>): Promise<any>;

  /**
   * Update job status in database (legacy method - use updateJobStatusSafe instead)
   * @deprecated Use updateJobStatusSafe for circuit breaker protection
   */
  protected async updateJobStatus(
    jobId: string,
    status: JobStatus,
    error?: string
  ): Promise<void> {
    await this.jobRepository.updateStatus(jobId, status, error);
  }

  /**
   * Update job status in database with circuit breaker protection.
   * Non-transient database errors are converted to UnrecoverableError to prevent retries.
   *
   * @param jobId - The job UUID
   * @param status - New status to set
   * @param error - Optional error message for failed status
   * @throws UnrecoverableError if database error is non-transient
   */
  protected async updateJobStatusSafe(
    jobId: string,
    status: JobStatus,
    error?: string
  ): Promise<void> {
    try {
      await this.jobRepository.updateStatus(jobId, status, error);
    } catch (dbError) {
      const originalError = dbError instanceof Error ? dbError : new Error(String(dbError));

      this.logger.error('Database error during status update', {
        job_id: jobId,
        status,
        error: originalError.message,
        is_non_transient: this.isNonTransientError(originalError)
      });

      // Apply circuit breaker for non-transient errors
      throw this.wrapNonTransientError(originalError, `status update to "${status}" for job ${jobId}`);
    }
  }

  /**
   * Update job progress
   */
  protected async updateProgress(
    jobId: string,
    progress: number,
    message?: string,
    currentPhase?: string
  ): Promise<void> {
    // Update in database
    await this.jobRepository.updateProgress(jobId, progress);

    // Publish WebSocket event
    await this.eventPublisher.publishJobProgress(jobId, progress, message, currentPhase);

    this.logger.debug('Job progress updated', {
      job_id: jobId,
      progress,
      message
    });
  }

  /**
   * Get sandbox client for tier
   */
  protected getSandboxClient(tier?: string): AxiosInstance {
    const sandboxUrl = tier ? SANDBOX_URLS[tier as keyof typeof SANDBOX_URLS] : SANDBOX_URLS.tier2;

    return axios.create({
      baseURL: sandboxUrl,
      timeout: 300000, // 5 minutes
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  /**
   * Execute tool in sandbox
   */
  protected async executeTool(
    jobId: string,
    tool: string,
    target: string,
    options: Record<string, any>,
    sandboxTier?: string
  ): Promise<any> {
    try {
      this.logger.info('Executing tool', {
        job_id: jobId,
        tool,
        target,
        sandbox_tier: sandboxTier
      });

      // Publish tool started event
      await this.eventPublisher.publishToolStarted(jobId, tool);

      // Determine action based on tool and options
      const action = this.determineToolAction(tool, options);

      // Get Testing Sandbox client for tier2 (Tier 1 and 3 would use different clients)
      if (sandboxTier === 'tier2' || !sandboxTier) {
        const sandboxClient = getTestingSandboxClient();

        // Execute tool and wait for completion
        const startTime = Date.now();
        const result = await sandboxClient.executeToolAndWait({
          tool,
          target,
          action,
          options,
          timeout: options.timeout || 3600
        });

        const duration = (Date.now() - startTime) / 1000;

        // Publish tool completed event
        await this.eventPublisher.publishToolCompleted(jobId, tool, {
          duration_seconds: duration,
          success: result.status === 'completed',
          results_count: result.results?.findings?.length || 0
        });

        this.logger.info('Tool execution completed', {
          job_id: jobId,
          tool,
          duration_seconds: duration,
          results_count: result.results?.findings?.length || 0
        });

        return result.results;
      } else {
        // Fallback to legacy sandbox client for tier1/tier3
        const sandbox = this.getSandboxClient(sandboxTier);

        const startTime = Date.now();
        const response = await sandbox.post('/execute', {
          tool,
          target,
          action,
          options
        });

        const duration = (Date.now() - startTime) / 1000;

        // Publish tool completed event
        await this.eventPublisher.publishToolCompleted(jobId, tool, {
          duration_seconds: duration,
          success: true,
          results_count: response.data.results?.length || 0
        });

        this.logger.info('Tool execution completed', {
          job_id: jobId,
          tool,
          duration_seconds: duration,
          results_count: response.data.results?.length || 0
        });

        return response.data;
      }
    } catch (error) {
      this.logger.error('Tool execution failed', {
        job_id: jobId,
        tool,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      // Publish tool completed with failure
      await this.eventPublisher.publishToolCompleted(jobId, tool, {
        duration_seconds: 0,
        success: false
      });

      throw error;
    }
  }

  /**
   * Determine tool action based on tool name and options
   */
  protected determineToolAction(tool: string, options: Record<string, any>): string {
    // Map tool to default action
    const defaultActions: Record<string, string> = {
      nmap: 'service_detection',
      nuclei: 'scan_all',
      sqlmap: 'test_injection',
      nikto: 'scan_web',
      burp: 'automated_scan',
      hashcat: 'crack_md5',
      hydra: 'crack_ssh',
      masscan: 'quick_scan',
      rustscan: 'quick_scan'
    };

    // Return custom action if provided, otherwise use default
    return options.action || defaultActions[tool] || 'scan';
  }

  /**
   * Store vulnerability finding
   */
  protected async storeVulnerability(
    jobId: string,
    vulnerability: {
      severity: string;
      title: string;
      description?: string;
      affected_target?: string;
      cvss_score?: number;
      cve_id?: string;
      cwe_id?: string;
      remediation?: string;
      evidence: Record<string, any>;
    }
  ): Promise<void> {
    try {
      // Store in database
      await this.resultRepository.create({
        job_id: jobId,
        finding_type: 'vulnerability',
        severity: vulnerability.severity as any,
        title: vulnerability.title,
        description: vulnerability.description,
        affected_target: vulnerability.affected_target,
        cvss_score: vulnerability.cvss_score,
        cve_id: vulnerability.cve_id,
        cwe_id: vulnerability.cwe_id,
        remediation: vulnerability.remediation,
        evidence: vulnerability.evidence,
        false_positive: false,
        verified: false
      });

      // Publish WebSocket event
      await this.eventPublisher.publishVulnerabilityFound(jobId, {
        severity: vulnerability.severity as any,
        title: vulnerability.title,
        cve_id: vulnerability.cve_id,
        cvss_score: vulnerability.cvss_score,
        affected_target: vulnerability.affected_target
      });

      this.logger.info('Vulnerability stored', {
        job_id: jobId,
        severity: vulnerability.severity,
        title: vulnerability.title
      });
    } catch (error) {
      this.logger.error('Failed to store vulnerability', {
        job_id: jobId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      // Don't throw - continue processing other results
    }
  }

  /**
   * Parse tool output and extract findings
   */
  protected abstract parseToolOutput(tool: string, output: any): any[];

  /**
   * Get estimated duration for job (in seconds)
   */
  protected getEstimatedDuration(tools: string[]): number {
    // Override in subclass for specific estimates
    return tools.length * 60; // Default: 1 minute per tool
  }
}
