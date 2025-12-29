/**
 * Scan Job Repository
 *
 * Database operations for scan jobs
 */

import { BaseRepository } from './base.repository';
import { ScanJob, ScanType, JobStatus, QueryOptions, PaginatedResponse } from '../../types';
import { logger } from '../../utils/logger';

/**
 * Scan Job Repository
 */
export class ScanJobRepository extends BaseRepository<ScanJob> {
  constructor() {
    super('scan_jobs');
  }

  /**
   * Declare JSONB columns for scan_jobs table
   *
   * From database.types.ts:
   * - tools: string[] (JSON array of tool names)
   * - config: Record<string, any> (JSON configuration object)
   */
  protected getJsonbColumns(): string[] {
    return ['tools', 'config'];
  }

  /**
   * Find jobs by organization
   */
  async findByOrganization(
    orgId: string,
    options: QueryOptions = {}
  ): Promise<PaginatedResponse<ScanJob>> {
    const { limit = 20, offset = 0, orderBy = 'created_at', orderDirection = 'DESC' } = options;

    const [jobs, total] = await Promise.all([
      this.findWhere('org_id = $1', [orgId], options),
      this.count('org_id = $1', [orgId])
    ]);

    return {
      data: jobs,
      pagination: this.buildPaginationMetadata(total, limit, offset)
    };
  }

  /**
   * Find jobs by user
   */
  async findByUser(
    userId: string,
    options: QueryOptions = {}
  ): Promise<PaginatedResponse<ScanJob>> {
    const { limit = 20, offset = 0 } = options;

    const [jobs, total] = await Promise.all([
      this.findWhere('user_id = $1', [userId], options),
      this.count('user_id = $1', [userId])
    ]);

    return {
      data: jobs,
      pagination: this.buildPaginationMetadata(total, limit, offset)
    };
  }

  /**
   * Find jobs by status
   */
  async findByStatus(
    orgId: string,
    status: JobStatus,
    options: QueryOptions = {}
  ): Promise<ScanJob[]> {
    return this.findWhere('org_id = $1 AND status = $2', [orgId, status], options);
  }

  /**
   * Find jobs by scan type
   */
  async findByScanType(
    orgId: string,
    scanType: ScanType,
    options: QueryOptions = {}
  ): Promise<ScanJob[]> {
    return this.findWhere('org_id = $1 AND scan_type = $2', [orgId, scanType], options);
  }

  /**
   * Find active jobs (queued or running)
   */
  async findActiveJobs(orgId: string): Promise<ScanJob[]> {
    return this.findWhere(
      "org_id = $1 AND status IN ('queued', 'running')",
      [orgId],
      { orderBy: 'priority', orderDirection: 'DESC' }
    );
  }

  /**
   * Find queued jobs by priority
   */
  async findQueuedJobsByPriority(limit: number = 10): Promise<ScanJob[]> {
    try {
      const query = `
        SELECT * FROM ${this.tableName}
        WHERE status = 'queued'
        ORDER BY priority DESC, created_at ASC
        LIMIT $1
      `;

      const result = await this.query<ScanJob>(query, [limit]);
      return result.rows;
    } catch (error) {
      logger.error('Error finding queued jobs by priority', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Update job status
   */
  async updateStatus(
    id: string,
    status: JobStatus,
    error?: string
  ): Promise<ScanJob | null> {
    const updateData: Partial<ScanJob> = { status };

    // Update timestamps based on status
    if (status === 'running' && !await this.hasStarted(id)) {
      updateData.started_at = new Date();
    } else if (status === 'completed' || status === 'failed' || status === 'cancelled') {
      updateData.completed_at = new Date();
    }

    if (error) {
      updateData.error = error;
    }

    return this.update(id, updateData);
  }

  /**
   * Update job progress
   */
  async updateProgress(id: string, progress: number): Promise<ScanJob | null> {
    // Ensure progress is between 0 and 100
    const clampedProgress = Math.max(0, Math.min(100, progress));
    return this.update(id, { progress: clampedProgress });
  }

  /**
   * Check if job has started
   */
  private async hasStarted(id: string): Promise<boolean> {
    try {
      const result = await this.query<{ started_at: Date | null }>(
        'SELECT started_at FROM scan_jobs WHERE id = $1',
        [id]
      );

      return result.rows[0]?.started_at !== null;
    } catch (error) {
      logger.error('Error checking if job has started', {
        id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return false;
    }
  }

  /**
   * Get job statistics by organization
   */
  async getStatsByOrganization(orgId: string): Promise<{
    total: number;
    by_status: Record<JobStatus, number>;
    by_type: Record<ScanType, number>;
    avg_duration_seconds: number;
  }> {
    try {
      const query = `
        SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE status = 'queued') as queued,
          COUNT(*) FILTER (WHERE status = 'running') as running,
          COUNT(*) FILTER (WHERE status = 'completed') as completed,
          COUNT(*) FILTER (WHERE status = 'failed') as failed,
          COUNT(*) FILTER (WHERE status = 'cancelled') as cancelled,
          COUNT(*) FILTER (WHERE scan_type = 'pentest') as pentest,
          COUNT(*) FILTER (WHERE scan_type = 'malware') as malware,
          COUNT(*) FILTER (WHERE scan_type = 'exploit') as exploit,
          COUNT(*) FILTER (WHERE scan_type = 'c2') as c2,
          COUNT(*) FILTER (WHERE scan_type = 'apt_simulation') as apt_simulation,
          COALESCE(AVG(EXTRACT(EPOCH FROM (completed_at - started_at))), 0) as avg_duration_seconds
        FROM ${this.tableName}
        WHERE org_id = $1 AND completed_at IS NOT NULL
      `;

      const result = await this.query<any>(query, [orgId]);
      const row = result.rows[0];

      return {
        total: parseInt(row.total, 10),
        by_status: {
          queued: parseInt(row.queued, 10),
          running: parseInt(row.running, 10),
          completed: parseInt(row.completed, 10),
          failed: parseInt(row.failed, 10),
          cancelled: parseInt(row.cancelled, 10)
        },
        by_type: {
          pentest: parseInt(row.pentest, 10),
          malware: parseInt(row.malware, 10),
          exploit: parseInt(row.exploit, 10),
          c2: parseInt(row.c2, 10),
          apt_simulation: parseInt(row.apt_simulation, 10)
        },
        avg_duration_seconds: parseFloat(row.avg_duration_seconds) || 0
      };
    } catch (error) {
      logger.error('Error getting job statistics', {
        orgId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Cancel job
   */
  async cancelJob(id: string): Promise<ScanJob | null> {
    return this.updateStatus(id, 'cancelled');
  }

  /**
   * Find stale jobs (running for too long)
   */
  async findStaleJobs(maxDurationMinutes: number = 60): Promise<ScanJob[]> {
    try {
      const query = `
        SELECT * FROM ${this.tableName}
        WHERE status = 'running'
        AND started_at < NOW() - INTERVAL '${maxDurationMinutes} minutes'
        ORDER BY started_at ASC
      `;

      const result = await this.query<ScanJob>(query);
      return result.rows;
    } catch (error) {
      logger.error('Error finding stale jobs', {
        maxDurationMinutes,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Search jobs by target
   */
  async searchByTarget(
    orgId: string,
    targetQuery: string,
    options: QueryOptions = {}
  ): Promise<ScanJob[]> {
    return this.findWhere(
      'org_id = $1 AND target ILIKE $2',
      [orgId, `%${targetQuery}%`],
      options
    );
  }
}
