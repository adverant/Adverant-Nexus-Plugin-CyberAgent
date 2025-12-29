/**
 * Scan Jobs API Routes
 *
 * REST API endpoints for managing security scan jobs
 */

import { Router, Request, Response } from 'express';
import { JobService } from '../services/job.service';
import {
  authenticate,
  requireRole,
  requireOrganization
} from '../middleware/authentication';
import {
  jobCreationRateLimiter,
  standardRateLimiter
} from '../middleware/rate-limiter';
import { asyncHandler } from '../middleware/error-handler';
import {
  CreateScanJobRequest,
  UpdateScanJobRequest,
  ListScanJobsQuery,
  CreateScanJobResponse,
  GetScanJobResponse,
  ListScanJobsResponse,
  CancelScanJobResponse
} from '../types';
import { BadRequestError } from '../errors';
import { logAudit } from '../utils/logger';

const router = Router();
const jobService = new JobService();

/**
 * POST /api/v1/jobs
 * Create a new scan job
 */
router.post(
  '/',
  authenticate,
  jobCreationRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const request: CreateScanJobRequest = req.body;

    // Validate request body
    if (!request.scan_type || !request.target || !request.tools || request.tools.length === 0) {
      throw new BadRequestError('scan_type, target, and tools are required');
    }

    // Create job
    const job = await jobService.createJob(request, user);

    // Log audit event
    logAudit('JOB_CREATED', user.user_id, `scan_job:${job.id}`, {
      scan_type: job.scan_type,
      target: job.target,
      sandbox_tier: job.sandbox_tier
    });

    // Build WebSocket URL for real-time updates
    const websocketUrl = `ws://${req.get('host')}/ws/jobs/${job.id}`;

    const response: CreateScanJobResponse = {
      success: true,
      job,
      websocket_url: websocketUrl
    };

    res.status(201).json(response);
  })
);

/**
 * GET /api/v1/jobs
 * List scan jobs with filtering and pagination
 */
router.get(
  '/',
  authenticate,
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const query: ListScanJobsQuery = {
      scan_type: req.query.scan_type as any,
      status: req.query.status as any,
      limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
      offset: req.query.offset ? parseInt(req.query.offset as string, 10) : undefined,
      sort_by: req.query.sort_by as any,
      sort_order: req.query.sort_order as any,
      target_filter: req.query.target_filter as string
    };

    const result = await jobService.listJobs(query, user);

    const response: ListScanJobsResponse = {
      success: true,
      data: result.data,
      pagination: result.pagination
    };

    res.json(response);
  })
);

/**
 * GET /api/v1/jobs/:id
 * Get a specific scan job by ID
 */
router.get(
  '/:id',
  authenticate,
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const jobId = req.params.id;

    const job = await jobService.getJob(jobId, user);

    const response: GetScanJobResponse = {
      success: true,
      job
    };

    res.json(response);
  })
);

/**
 * GET /api/v1/jobs/:id/details
 * Get job with results summary
 */
router.get(
  '/:id/details',
  authenticate,
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const jobId = req.params.id;

    const details = await jobService.getJobWithResults(jobId, user);

    res.json({
      success: true,
      ...details
    });
  })
);

/**
 * PATCH /api/v1/jobs/:id
 * Update a scan job
 */
router.patch(
  '/:id',
  authenticate,
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const jobId = req.params.id;
    const updates: UpdateScanJobRequest = req.body;

    const job = await jobService.updateJob(jobId, updates, user);

    logAudit('JOB_UPDATED', user.user_id, `scan_job:${jobId}`, {
      updates: Object.keys(updates)
    });

    res.json({
      success: true,
      job
    });
  })
);

/**
 * POST /api/v1/jobs/:id/cancel
 * Cancel a running or queued job
 */
router.post(
  '/:id/cancel',
  authenticate,
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const jobId = req.params.id;

    const job = await jobService.cancelJob(jobId, user);

    logAudit('JOB_CANCELLED', user.user_id, `scan_job:${jobId}`);

    const response: CancelScanJobResponse = {
      success: true,
      message: 'Job cancelled successfully',
      job
    };

    res.json(response);
  })
);

/**
 * GET /api/v1/jobs/:id/results
 * Get results for a specific job
 */
router.get(
  '/:id/results',
  authenticate,
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const jobId = req.params.id;

    // Verify job access
    await jobService.getJob(jobId, user);

    // Get results with pagination
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 20;
    const offset = req.query.offset ? parseInt(req.query.offset as string, 10) : 0;

    // This will be implemented in the results service
    res.json({
      success: true,
      message: 'Results endpoint - to be implemented with ScanResultService'
    });
  })
);

/**
 * GET /api/v1/organizations/:org_id/jobs/stats
 * Get job statistics for an organization
 */
router.get(
  '/organizations/:org_id/stats',
  authenticate,
  requireOrganization,
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user!;
    const orgId = req.params.org_id;

    const stats = await jobService.getOrganizationStats(orgId, user);

    res.json({
      success: true,
      stats
    });
  })
);

/**
 * GET /api/v1/jobs/queue/status
 * Get current queue status (admin only)
 */
router.get(
  '/queue/status',
  authenticate,
  requireRole('admin'),
  standardRateLimiter,
  asyncHandler(async (req: Request, res: Response) => {
    const { getQueueManager } = await import('../queue');
    const queueManager = getQueueManager();

    // Get stats for all queues
    const allQueueStats = await queueManager.getQueueStats();

    // Aggregate totals across all queues
    const totals = {
      waiting: 0,
      active: 0,
      completed: 0,
      failed: 0,
      delayed: 0,
      total: 0
    };

    // Build queue breakdown
    const queueBreakdown: Record<string, any> = {};

    for (const [queueName, stats] of Object.entries(allQueueStats)) {
      const queueStats = stats as any;

      // Add to totals
      totals.waiting += queueStats.waiting;
      totals.active += queueStats.active;
      totals.completed += queueStats.completed;
      totals.failed += queueStats.failed;
      totals.delayed += queueStats.delayed;
      totals.total += queueStats.total;

      // Add queue-specific breakdown
      queueBreakdown[queueName] = {
        waiting: queueStats.waiting,
        active: queueStats.active,
        completed: queueStats.completed,
        failed: queueStats.failed,
        delayed: queueStats.delayed,
        total: queueStats.total,
        isPaused: queueStats.isPaused
      };
    }

    res.json({
      success: true,
      totals,
      queues: queueBreakdown,
      timestamp: new Date().toISOString()
    });
  })
);

export default router;
