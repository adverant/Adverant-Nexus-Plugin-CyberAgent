/**
 * Health Check API Routes
 *
 * System health monitoring and metrics endpoints
 */

import { Router, Request, Response } from 'express';
import { getDatabase } from '../database/connection';
import { asyncHandler } from '../middleware/error-handler';
import { optionalAuthenticate } from '../middleware/authentication';
import { HealthCheckResponse, MetricsResponse, ServiceHealth } from '../types';
import { logger } from '../utils/logger';
import config from '../config';
import axios from 'axios';

const router = Router();

/**
 * Request metrics tracker (in-memory)
 */
interface RequestMetrics {
  requestsPerMinute: number;
  avgResponseTimeMs: number;
}

let requestCount = 0;
let totalResponseTime = 0;
let requestCountLastMinute = 0;
let lastResetTime = Date.now();

/**
 * Middleware to track request metrics
 */
export function trackRequest(req: Request, res: Response, next: Function) {
  const startTime = Date.now();

  // Increment request counter
  requestCount++;

  // Hook into response finish event to measure response time
  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    totalResponseTime += responseTime;
  });

  next();
}

/**
 * Get current request metrics
 */
function getRequestMetrics(): RequestMetrics {
  const now = Date.now();
  const timeSinceReset = now - lastResetTime;

  // Reset counters every minute
  if (timeSinceReset >= 60000) {
    requestCountLastMinute = requestCount;
    requestCount = 0;
    lastResetTime = now;
  }

  // Calculate requests per minute
  const requestsPerMinute = timeSinceReset > 0
    ? Math.round((requestCount / timeSinceReset) * 60000)
    : requestCountLastMinute;

  // Calculate average response time
  const avgResponseTimeMs = requestCount > 0
    ? Math.round(totalResponseTime / requestCount)
    : 0;

  return {
    requestsPerMinute,
    avgResponseTimeMs
  };
}

/**
 * Check service health with timeout
 */
async function checkServiceHealth(
  url: string,
  timeout: number = config.healthCheck.timeoutMs
): Promise<ServiceHealth> {
  const start = Date.now();

  try {
    await axios.get(`${url}/health`, {
      timeout,
      validateStatus: (status) => status === 200
    });

    const latency = Date.now() - start;

    return {
      status: 'healthy',
      latency
    };
  } catch (error) {
    const latency = Date.now() - start;

    if (axios.isAxiosError(error) && error.code === 'ECONNABORTED') {
      return {
        status: 'unhealthy',
        latency,
        error: 'Timeout'
      };
    }

    return {
      status: 'unhealthy',
      latency,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * GET /health
 * Basic health check - always returns 200 if server is running
 */
router.get(
  '/',
  asyncHandler(async (req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString()
    });
  })
);

/**
 * GET /health/detailed
 * Detailed health check with all service dependencies
 */
router.get(
  '/detailed',
  optionalAuthenticate,
  asyncHandler(async (req: Request, res: Response) => {
    const startTime = Date.now();

    // Check database
    const db = getDatabase();
    const dbHealth = await db.healthCheck();

    // Check Redis (via rate limiter)
    let redisHealth: ServiceHealth;
    try {
      const { redisClient } = await import('../middleware/rate-limiter');
      const redisPing = await redisClient.ping();
      redisHealth = {
        status: redisPing === 'PONG' ? 'healthy' : 'unhealthy',
        latency: Date.now() - startTime
      };
    } catch (error) {
      redisHealth = {
        status: 'unhealthy',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }

    // Check all external services
    const [
      graphragHealth,
      mageagentHealth,
      orchestrationAgentHealth,
      tier1SandboxHealth,
      tier2SandboxHealth,
      tier3SandboxHealth
    ] = await Promise.all([
      checkServiceHealth(config.nexus.graphrag.url),
      checkServiceHealth(config.nexus.mageagent.url),
      checkServiceHealth(config.nexus.orchestrationAgent.url),
      checkServiceHealth(config.sandboxes.tier1.url),
      checkServiceHealth(config.sandboxes.tier2.url),
      checkServiceHealth(config.sandboxes.tier3.url)
    ]);

    // Normalize dbHealth to match ServiceHealth interface
    const normalizedDbHealth: ServiceHealth = {
      status: dbHealth.healthy ? 'healthy' : 'unhealthy',
      latency: dbHealth.latency,
      error: dbHealth.error
    };

    // Determine overall status
    const allServices: ServiceHealth[] = [
      normalizedDbHealth,
      redisHealth,
      graphragHealth,
      mageagentHealth,
      orchestrationAgentHealth,
      tier1SandboxHealth,
      tier2SandboxHealth,
      tier3SandboxHealth
    ];

    const unhealthyCount = allServices.filter(s => s.status === 'unhealthy').length;
    const overallStatus = unhealthyCount === 0
      ? 'healthy'
      : unhealthyCount < allServices.length / 2
      ? 'degraded'
      : 'unhealthy';

    const response: HealthCheckResponse = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
      services: {
        database: {
          status: dbHealth.healthy ? 'healthy' : 'unhealthy',
          latency: dbHealth.latency,
          error: dbHealth.error
        },
        redis: redisHealth,
        graphrag: graphragHealth,
        mageagent: mageagentHealth,
        orchestration_agent: orchestrationAgentHealth,
        tier1_sandbox: tier1SandboxHealth,
        tier2_sandbox: tier2SandboxHealth,
        tier3_sandbox: tier3SandboxHealth
      },
      uptime: process.uptime()
    };

    // Return 503 if unhealthy, 200 otherwise
    const statusCode = overallStatus === 'unhealthy' ? 503 : 200;

    res.status(statusCode).json(response);
  })
);

/**
 * GET /health/readiness
 * Kubernetes readiness probe - checks if service can accept traffic
 */
router.get(
  '/readiness',
  asyncHandler(async (req: Request, res: Response) => {
    const db = getDatabase();
    const dbHealth = await db.healthCheck();

    if (!dbHealth.healthy) {
      return res.status(503).json({
        ready: false,
        reason: 'Database not available'
      });
    }

    res.json({
      ready: true,
      timestamp: new Date().toISOString()
    });
  })
);

/**
 * GET /health/liveness
 * Kubernetes liveness probe - checks if service should be restarted
 */
router.get(
  '/liveness',
  asyncHandler(async (req: Request, res: Response) => {
    // Simple check - if we can respond, we're alive
    res.json({
      alive: true,
      timestamp: new Date().toISOString()
    });
  })
);

/**
 * GET /metrics
 * Prometheus-compatible metrics endpoint
 */
router.get(
  '/metrics',
  optionalAuthenticate,
  asyncHandler(async (req: Request, res: Response) => {
    // Get database pool stats
    const db = getDatabase();
    const poolStats = db.getPoolStats();

    // Get process metrics
    const memoryUsage = process.memoryUsage();

    // Get job queue metrics from BullMQ
    let queueDepth = 0;
    let jobsByStatus = {
      queued: 0,
      running: 0,
      completed: 0,
      failed: 0,
      cancelled: 0
    };
    let jobsByType = {
      pentest: 0,
      malware: 0,
      exploit: 0,
      c2: 0,
      apt_simulation: 0
    };
    let totalJobs = 0;
    let avgDurationSeconds = 0;

    try {
      const { getQueueManager } = await import('../queue');
      const queueManager = getQueueManager();

      // Get stats for all queues
      const allQueueStats = await queueManager.getQueueStats();

      // Aggregate queue depth from all queues
      for (const [queueName, stats] of Object.entries(allQueueStats)) {
        queueDepth += (stats as any).waiting + (stats as any).active;
      }

      // Get job counts from database
      const jobCountsQuery = `
        SELECT
          status,
          scan_type,
          COUNT(*) as count,
          AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))::float as avg_duration
        FROM scan_jobs
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY status, scan_type
      `;
      const jobCountsResult = await db.query(jobCountsQuery);

      // Aggregate counts
      for (const row of jobCountsResult.rows) {
        const status = row.status as keyof typeof jobsByStatus;
        const scanType = row.scan_type as keyof typeof jobsByType;
        const count = parseInt(row.count, 10);

        if (jobsByStatus[status] !== undefined) {
          jobsByStatus[status] += count;
        }

        if (jobsByType[scanType] !== undefined) {
          jobsByType[scanType] += count;
        }

        totalJobs += count;

        // Average duration (only for completed jobs)
        if (status === 'completed' && row.avg_duration) {
          avgDurationSeconds = parseFloat(row.avg_duration);
        }
      }
    } catch (error) {
      logger.error('Failed to get queue metrics', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      // Continue with default values
    }

    // Get request metrics from in-memory tracker
    const requestMetrics = getRequestMetrics();

    // Get disk usage (best effort - platform specific)
    let diskUsagePercent = 0;
    try {
      const os = await import('os');

      // Use system-wide memory as a proxy for disk usage
      // For accurate disk usage, would need to use platform-specific tools
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      diskUsagePercent = ((totalMem - freeMem) / totalMem) * 100;
    } catch (error) {
      // Disk usage check failed - not critical
      logger.debug('Failed to get system metrics', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    // Calculate CPU usage as percentage
    const cpuUsage = process.cpuUsage();
    const cpuPercent = ((cpuUsage.user + cpuUsage.system) / 1000000) / process.uptime();

    const response: MetricsResponse = {
      jobs: {
        total: totalJobs,
        by_status: jobsByStatus,
        by_type: jobsByType,
        avg_duration_seconds: avgDurationSeconds
      },
      performance: {
        requests_per_minute: requestMetrics.requestsPerMinute,
        avg_response_time_ms: requestMetrics.avgResponseTimeMs,
        active_connections: poolStats?.totalCount || 0,
        queue_depth: queueDepth
      },
      resources: {
        cpu_usage_percent: cpuPercent,
        memory_usage_mb: memoryUsage.heapUsed / 1024 / 1024,
        disk_usage_percent: diskUsagePercent
      }
    };

    res.json(response);
  })
);

/**
 * GET /version
 * Get API version and build info
 */
router.get(
  '/version',
  asyncHandler(async (req: Request, res: Response) => {
    res.json({
      version: process.env.npm_package_version || '1.0.0',
      name: 'nexus-cyberagent-api',
      node_version: process.version,
      environment: config.env,
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    });
  })
);

export default router;
