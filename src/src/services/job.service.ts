/**
 * Job Service
 *
 * Business logic for managing security scan jobs
 */

import { ScanJobRepository, ScanResultRepository } from '../database/repositories';
import {
  ScanJob,
  ScanType,
  JobStatus,
  SandboxTier,
  CreateScanJobRequest,
  UpdateScanJobRequest,
  ListScanJobsQuery,
  PaginatedResponse,
  AuthContext
} from '../types';
import {
  JobNotFoundError,
  InvalidJobStatusError,
  TargetNotAuthorizedError,
  BadRequestError
} from '../errors';
import { Logger, createContextLogger } from '../utils/logger';
import { getQueueManager } from '../queue';
import { getTargetAuthorizationService } from '../security/target-authorization';
import config from '../config';

/**
 * Job Service Class
 */
export class JobService {
  private jobRepository: ScanJobRepository;
  private resultRepository: ScanResultRepository;
  private logger: Logger;

  constructor() {
    this.jobRepository = new ScanJobRepository();
    this.resultRepository = new ScanResultRepository();
    this.logger = createContextLogger('JobService');
  }

  /**
   * Create a new scan job
   */
  async createJob(
    request: CreateScanJobRequest,
    user: AuthContext
  ): Promise<ScanJob> {
    this.logger.info('Creating new scan job', {
      scan_type: request.scan_type,
      target: request.target,
      user_id: user.user_id,
      org_id: user.org_id
    });

    // Validate target authorization if enabled
    // Skip target authorization for internal service-to-service requests
    // Internal services are identified by user_id starting with 'service:'
    // Also skip for local file paths (file:// protocol) since they're on shared volumes
    const isInternalService = user.user_id.startsWith('service:');
    const isLocalFile = request.local_file_path?.startsWith('file://') ||
                        request.target.startsWith('file://');

    if (config.security.enableTargetAuthorization && !isInternalService && !isLocalFile) {
      await this.validateTargetAuthorization(request.target, user.org_id, user.user_id);
    } else if (isInternalService) {
      this.logger.info('Skipping target authorization for internal service request', {
        service: user.user_id,
        target: request.target,
      });
    } else if (isLocalFile) {
      this.logger.info('Skipping target authorization for local file analysis', {
        local_file_path: request.local_file_path || request.target,
        filename: request.file_metadata?.filename,
      });
    }

    // Validate tools are appropriate for scan type
    this.validateTools(request.scan_type, request.tools);

    // Determine sandbox tier if not specified
    const sandboxTier = request.sandbox_tier || this.determineSandboxTier(request.scan_type, request.config);

    // Validate priority
    const priority = request.priority !== undefined
      ? Math.max(1, Math.min(10, request.priority))
      : 3;

    // Create job in database
    const job = await this.jobRepository.create({
      org_id: user.org_id,
      user_id: user.user_id,
      scan_type: request.scan_type,
      target: request.target,
      status: 'queued',
      priority,
      sandbox_tier: sandboxTier,
      tools: request.tools,
      config: request.config || {},
      progress: 0
    });

    this.logger.info('Scan job created successfully', {
      job_id: job.id,
      scan_type: job.scan_type,
      sandbox_tier: job.sandbox_tier
    });

    // Add job to processing queue
    try {
      const queueManager = getQueueManager();

      // Determine effective target - use local file path if provided
      const effectiveTarget = request.local_file_path || request.target;

      await queueManager.addJob(request.scan_type, {
        job_id: job.id,
        org_id: user.org_id,
        user_id: user.user_id,
        scan_type: request.scan_type,
        target: effectiveTarget,
        local_file_path: request.local_file_path,
        file_metadata: request.file_metadata,
        sandbox_tier: sandboxTier,
        tools: request.tools,
        config: request.config || {},
        priority
      });

      this.logger.info('Job added to queue', {
        job_id: job.id,
        scan_type: request.scan_type
      });
    } catch (error) {
      this.logger.error('Failed to add job to queue', {
        job_id: job.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      // Don't throw - job is already in database and can be retried
    }

    return job;
  }

  /**
   * Get job by ID
   */
  async getJob(jobId: string, user: AuthContext): Promise<ScanJob> {
    const job = await this.jobRepository.findById(jobId);

    if (!job) {
      throw new JobNotFoundError(jobId);
    }

    // Check organization access (unless admin)
    if (user.role !== 'admin' && job.org_id !== user.org_id) {
      throw new JobNotFoundError(jobId); // Don't reveal job exists
    }

    return job;
  }

  /**
   * List jobs with filtering and pagination
   */
  async listJobs(
    query: ListScanJobsQuery,
    user: AuthContext
  ): Promise<PaginatedResponse<ScanJob>> {
    const {
      scan_type,
      status,
      limit = 20,
      offset = 0,
      sort_by = 'created_at',
      sort_order = 'desc',
      target_filter
    } = query;

    // Build where clause
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    // Organization filter (unless admin)
    if (user.role !== 'admin') {
      conditions.push(`org_id = $${paramIndex}`);
      params.push(user.org_id);
      paramIndex++;
    }

    // Scan type filter
    if (scan_type) {
      conditions.push(`scan_type = $${paramIndex}`);
      params.push(scan_type);
      paramIndex++;
    }

    // Status filter
    if (status) {
      conditions.push(`status = $${paramIndex}`);
      params.push(status);
      paramIndex++;
    }

    // Target filter
    if (target_filter) {
      conditions.push(`target ILIKE $${paramIndex}`);
      params.push(`%${target_filter}%`);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? conditions.join(' AND ') : '1=1';

    // Get jobs and total count
    const [jobs, total] = await Promise.all([
      this.jobRepository.findWhere(whereClause, params, {
        limit,
        offset,
        orderBy: sort_by,
        orderDirection: sort_order.toUpperCase() as 'ASC' | 'DESC'
      }),
      this.jobRepository.count(whereClause, params)
    ]);

    return {
      data: jobs,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      }
    };
  }

  /**
   * Update job
   */
  async updateJob(
    jobId: string,
    updates: UpdateScanJobRequest,
    user: AuthContext
  ): Promise<ScanJob> {
    const job = await this.getJob(jobId, user);

    // Validate status transition if updating status
    if (updates.status && !this.isValidStatusTransition(job.status, updates.status)) {
      throw new InvalidJobStatusError(
        `Cannot transition from ${job.status} to ${updates.status}`
      );
    }

    const updatedJob = await this.jobRepository.update(jobId, updates);

    if (!updatedJob) {
      throw new JobNotFoundError(jobId);
    }

    this.logger.info('Job updated', {
      job_id: jobId,
      updates: Object.keys(updates)
    });

    return updatedJob;
  }

  /**
   * Update job status
   */
  async updateJobStatus(
    jobId: string,
    status: JobStatus,
    error?: string
  ): Promise<ScanJob> {
    const job = await this.jobRepository.findById(jobId);

    if (!job) {
      throw new JobNotFoundError(jobId);
    }

    if (!this.isValidStatusTransition(job.status, status)) {
      throw new InvalidJobStatusError(
        `Cannot transition from ${job.status} to ${status}`
      );
    }

    const updatedJob = await this.jobRepository.updateStatus(jobId, status, error);

    if (!updatedJob) {
      throw new JobNotFoundError(jobId);
    }

    this.logger.info('Job status updated', {
      job_id: jobId,
      old_status: job.status,
      new_status: status
    });

    return updatedJob;
  }

  /**
   * Update job progress
   */
  async updateJobProgress(jobId: string, progress: number): Promise<ScanJob> {
    const updatedJob = await this.jobRepository.updateProgress(jobId, progress);

    if (!updatedJob) {
      throw new JobNotFoundError(jobId);
    }

    this.logger.debug('Job progress updated', {
      job_id: jobId,
      progress
    });

    return updatedJob;
  }

  /**
   * Cancel job
   */
  async cancelJob(jobId: string, user: AuthContext): Promise<ScanJob> {
    const job = await this.getJob(jobId, user);

    // Can only cancel queued or running jobs
    if (!['queued', 'running'].includes(job.status)) {
      throw new InvalidJobStatusError(
        `Cannot cancel job with status: ${job.status}`
      );
    }

    const cancelledJob = await this.jobRepository.cancelJob(jobId);

    if (!cancelledJob) {
      throw new JobNotFoundError(jobId);
    }

    this.logger.info('Job cancelled', {
      job_id: jobId,
      user_id: user.user_id
    });

    // TODO: Cancel job in BullMQ queue
    // await this.cancelQueuedJob(jobId);

    return cancelledJob;
  }

  /**
   * Get job with results
   */
  async getJobWithResults(jobId: string, user: AuthContext) {
    const job = await this.getJob(jobId, user);

    const resultsSummary = await this.resultRepository.getSummaryByJob(jobId);

    return {
      job,
      results_summary: resultsSummary
    };
  }

  /**
   * Get job statistics by organization
   */
  async getOrganizationStats(orgId: string, user: AuthContext) {
    // Check access
    if (user.role !== 'admin' && user.org_id !== orgId) {
      throw new BadRequestError('Access denied to organization statistics');
    }

    const stats = await this.jobRepository.getStatsByOrganization(orgId);

    return stats;
  }

  /**
   * Find stale jobs (running too long)
   */
  async findStaleJobs(maxDurationMinutes: number = 60): Promise<ScanJob[]> {
    return this.jobRepository.findStaleJobs(maxDurationMinutes);
  }

  /**
   * Validate target authorization
   *
   * Enforces that the target is authorized for scanning by the organization.
   * This is a critical security feature to prevent unauthorized scanning.
   */
  private async validateTargetAuthorization(target: string, orgId: string, userId: string): Promise<void> {
    this.logger.debug('Validating target authorization', { target, org_id: orgId });

    try {
      const authService = getTargetAuthorizationService();

      // Enforce target authorization - throws TargetNotAuthorizedError if unauthorized
      await authService.enforceTargetAuthorization(
        target,
        'scan', // Default scan type for general authorization
        orgId,
        userId
      );

      this.logger.info('Target authorization validated successfully', {
        target,
        org_id: orgId
      });
    } catch (error) {
      // Log authorization failure
      this.logger.warn('Target authorization failed', {
        target,
        org_id: orgId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      // Re-throw TargetNotAuthorizedError or wrap other errors
      if (error instanceof TargetNotAuthorizedError) {
        throw error;
      }

      // Fail secure: treat database errors as authorization failures
      throw new TargetNotAuthorizedError(target);
    }
  }

  /**
   * Validate tools for scan type
   */
  private validateTools(scanType: ScanType, tools: string[]): void {
    if (tools.length === 0) {
      throw new BadRequestError('At least one tool must be specified');
    }

    // TODO: Validate that tools are appropriate for the scan type
    // For now, just check tools array is not empty
    this.logger.debug('Tools validation', { scanType, toolCount: tools.length });
  }

  /**
   * Determine appropriate sandbox tier based on scan type and config
   */
  private determineSandboxTier(scanType: ScanType, config?: any): SandboxTier {
    switch (scanType) {
      case 'malware':
        // Malware analysis should use Tier 3 (detonation chamber) by default
        return 'tier3';

      case 'pentest':
      case 'exploit':
        // Pentests and exploit testing use Tier 2 (isolated network)
        return 'tier2';

      case 'c2':
      case 'apt_simulation':
        // C2 and APT simulation use Tier 2 or 3 depending on config
        return config?.require_full_isolation ? 'tier3' : 'tier2';

      default:
        return 'tier2';
    }
  }

  /**
   * Validate job status transition
   */
  private isValidStatusTransition(currentStatus: JobStatus, newStatus: JobStatus): boolean {
    const validTransitions: Record<JobStatus, JobStatus[]> = {
      queued: ['running', 'cancelled'],
      running: ['completed', 'failed', 'cancelled'],
      completed: [], // Cannot transition from completed
      failed: [], // Cannot transition from failed
      cancelled: [] // Cannot transition from cancelled
    };

    return validTransitions[currentStatus]?.includes(newStatus) || false;
  }
}
