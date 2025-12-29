/**
 * Scan Result Repository
 *
 * Database operations for scan results (vulnerabilities, findings)
 */

import { BaseRepository } from './base.repository';
import { ScanResult, FindingType, Severity, QueryOptions, PaginatedResponse } from '../../types';
import { logger } from '../../utils/logger';

/**
 * Scan Result Repository
 */
export class ScanResultRepository extends BaseRepository<ScanResult> {
  constructor() {
    super('scan_results');
  }

  /**
   * Declare JSONB columns for scan_results table
   *
   * From database.types.ts:
   * - evidence: Record<string, any> (JSON evidence data)
   */
  protected getJsonbColumns(): string[] {
    return ['evidence'];
  }

  /**
   * Find results by job ID
   */
  async findByJobId(
    jobId: string,
    options: QueryOptions = {}
  ): Promise<PaginatedResponse<ScanResult>> {
    const { limit = 20, offset = 0 } = options;

    const [results, total] = await Promise.all([
      this.findWhere('job_id = $1', [jobId], {
        ...options,
        orderBy: 'created_at',
        orderDirection: 'DESC'
      }),
      this.count('job_id = $1', [jobId])
    ]);

    return {
      data: results,
      pagination: this.buildPaginationMetadata(total, limit, offset)
    };
  }

  /**
   * Find results by severity
   */
  async findBySeverity(
    jobId: string,
    severity: Severity,
    options: QueryOptions = {}
  ): Promise<ScanResult[]> {
    return this.findWhere('job_id = $1 AND severity = $2', [jobId, severity], options);
  }

  /**
   * Find results by finding type
   */
  async findByFindingType(
    jobId: string,
    findingType: FindingType,
    options: QueryOptions = {}
  ): Promise<ScanResult[]> {
    return this.findWhere('job_id = $1 AND finding_type = $2', [jobId, findingType], options);
  }

  /**
   * Find critical/high severity findings
   */
  async findHighSeverityFindings(jobId: string): Promise<ScanResult[]> {
    return this.findWhere(
      "job_id = $1 AND severity IN ('critical', 'high')",
      [jobId],
      { orderBy: 'severity', orderDirection: 'ASC' }
    );
  }

  /**
   * Find verified findings only
   */
  async findVerifiedFindings(jobId: string): Promise<ScanResult[]> {
    return this.findWhere(
      'job_id = $1 AND verified = true AND false_positive = false',
      [jobId]
    );
  }

  /**
   * Mark finding as false positive
   */
  async markAsFalsePositive(id: string): Promise<ScanResult | null> {
    return this.update(id, { false_positive: true });
  }

  /**
   * Mark finding as verified
   */
  async markAsVerified(id: string): Promise<ScanResult | null> {
    return this.update(id, { verified: true });
  }

  /**
   * Get findings summary by job
   */
  async getSummaryByJob(jobId: string): Promise<{
    total: number;
    by_severity: Record<Severity, number>;
    by_finding_type: Record<FindingType, number>;
    verified_count: number;
    false_positive_count: number;
  }> {
    try {
      const query = `
        SELECT
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE severity = 'critical') as critical,
          COUNT(*) FILTER (WHERE severity = 'high') as high,
          COUNT(*) FILTER (WHERE severity = 'medium') as medium,
          COUNT(*) FILTER (WHERE severity = 'low') as low,
          COUNT(*) FILTER (WHERE severity = 'info') as info,
          COUNT(*) FILTER (WHERE finding_type = 'vulnerability') as vulnerability,
          COUNT(*) FILTER (WHERE finding_type = 'malware') as malware,
          COUNT(*) FILTER (WHERE finding_type = 'exploit') as exploit,
          COUNT(*) FILTER (WHERE finding_type = 'ioc') as ioc,
          COUNT(*) FILTER (WHERE finding_type = 'config_issue') as config_issue,
          COUNT(*) FILTER (WHERE finding_type = 'credential') as credential,
          COUNT(*) FILTER (WHERE verified = true) as verified_count,
          COUNT(*) FILTER (WHERE false_positive = true) as false_positive_count
        FROM ${this.tableName}
        WHERE job_id = $1
      `;

      const result = await this.query<any>(query, [jobId]);
      const row = result.rows[0];

      return {
        total: parseInt(row.total, 10),
        by_severity: {
          critical: parseInt(row.critical, 10),
          high: parseInt(row.high, 10),
          medium: parseInt(row.medium, 10),
          low: parseInt(row.low, 10),
          info: parseInt(row.info, 10)
        },
        by_finding_type: {
          vulnerability: parseInt(row.vulnerability, 10),
          malware: parseInt(row.malware, 10),
          exploit: parseInt(row.exploit, 10),
          ioc: parseInt(row.ioc, 10),
          config_issue: parseInt(row.config_issue, 10),
          credential: parseInt(row.credential, 10)
        },
        verified_count: parseInt(row.verified_count, 10),
        false_positive_count: parseInt(row.false_positive_count, 10)
      };
    } catch (error) {
      logger.error('Error getting findings summary', {
        jobId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Find results by CVE ID
   */
  async findByCVE(cveId: string): Promise<ScanResult[]> {
    return this.findWhere('cve_id = $1', [cveId]);
  }

  /**
   * Find results by CVSS score range
   */
  async findByCVSSRange(
    jobId: string,
    minScore: number,
    maxScore: number
  ): Promise<ScanResult[]> {
    return this.findWhere(
      'job_id = $1 AND cvss_score >= $2 AND cvss_score <= $3',
      [jobId, minScore, maxScore],
      { orderBy: 'cvss_score', orderDirection: 'DESC' }
    );
  }

  /**
   * Update remediation for a finding
   */
  async updateRemediation(id: string, remediation: string): Promise<ScanResult | null> {
    return this.update(id, { remediation });
  }
}
