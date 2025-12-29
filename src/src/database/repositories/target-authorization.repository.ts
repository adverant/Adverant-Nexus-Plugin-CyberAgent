/**
 * Target Authorization Repository
 *
 * Database operations for target authorization management
 * Ensures only authorized targets can be scanned
 */

import { Pool, PoolClient } from 'pg';
import { getDatabase } from '../connection';
import { Logger, createContextLogger } from '../../utils/logger';
import { DatabaseError } from '../../errors/custom-errors';

const logger = createContextLogger('TargetAuthorizationRepository');

/**
 * Target authorization database record
 */
export interface AuthorizedTargetRecord {
  id: string;
  organization_id: string;
  target: string;
  target_type: 'ip' | 'domain' | 'cidr' | 'hostname';
  description?: string;
  authorized_by: string;
  authorized_at: Date;
  expires_at?: Date;
  scan_types_allowed: string[];
  proof_of_ownership?: string;
  verification_status: 'pending' | 'verified' | 'rejected';
  verification_method?: 'dns_txt' | 'file_upload' | 'email' | 'manual';
  notes?: string;
  created_at: Date;
  updated_at: Date;
}

/**
 * Target Authorization Repository
 */
export class TargetAuthorizationRepository {
  private logger: Logger;
  private db: ReturnType<typeof getDatabase>;

  constructor() {
    this.logger = createContextLogger('TargetAuthorizationRepository');
    this.db = getDatabase();
  }

  /**
   * Initialize target_authorizations table if not exists
   */
  async initialize(): Promise<void> {
    const client = await this.db.getClient();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS target_authorizations (
          id VARCHAR(255) PRIMARY KEY,
          organization_id VARCHAR(255) NOT NULL,
          target TEXT NOT NULL,
          target_type VARCHAR(50) NOT NULL CHECK (target_type IN ('ip', 'domain', 'cidr', 'hostname')),
          description TEXT,
          authorized_by VARCHAR(255) NOT NULL,
          authorized_at TIMESTAMP NOT NULL DEFAULT NOW(),
          expires_at TIMESTAMP,
          scan_types_allowed TEXT[] NOT NULL DEFAULT '{}',
          proof_of_ownership TEXT,
          verification_status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending', 'verified', 'rejected')),
          verification_method VARCHAR(50) CHECK (verification_method IN ('dns_txt', 'file_upload', 'email', 'manual')),
          notes TEXT,
          created_at TIMESTAMP NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );

        -- Index for fast lookups by organization and target
        CREATE INDEX IF NOT EXISTS idx_target_auth_org_target ON target_authorizations(organization_id, target);

        -- Index for verified targets
        CREATE INDEX IF NOT EXISTS idx_target_auth_verified ON target_authorizations(verification_status) WHERE verification_status = 'verified';

        -- Index for expiration checks
        CREATE INDEX IF NOT EXISTS idx_target_auth_expires ON target_authorizations(expires_at) WHERE expires_at IS NOT NULL;
      `);

      this.logger.info('Target authorizations table initialized');
    } catch (error) {
      this.logger.error('Failed to initialize target authorizations table', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to initialize target authorizations table');
    } finally {
      client.release();
    }
  }

  /**
   * Find authorization by target and organization
   */
  async findByTargetAndOrg(
    target: string,
    organizationId: string
  ): Promise<AuthorizedTargetRecord | null> {
    try {
      const result = await this.db.query<AuthorizedTargetRecord>(
        `SELECT * FROM target_authorizations
         WHERE target = $1
         AND organization_id = $2
         AND verification_status = 'verified'
         AND (expires_at IS NULL OR expires_at > NOW())
         LIMIT 1`,
        [target, organizationId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      return result.rows[0];
    } catch (error) {
      this.logger.error('Failed to find target authorization', {
        target,
        organization_id: organizationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to find target authorization');
    }
  }

  /**
   * Find authorization matching target and scan type
   */
  async findMatchingAuthorization(
    target: string,
    scanType: string,
    organizationId: string
  ): Promise<AuthorizedTargetRecord | null> {
    try {
      // Query for exact match or wildcard scan types
      const result = await this.db.query<AuthorizedTargetRecord>(
        `SELECT * FROM target_authorizations
         WHERE target = $1
         AND organization_id = $2
         AND verification_status = 'verified'
         AND (expires_at IS NULL OR expires_at > NOW())
         AND ('*' = ANY(scan_types_allowed) OR $3 = ANY(scan_types_allowed))
         LIMIT 1`,
        [target, organizationId, scanType]
      );

      if (result.rows.length === 0) {
        // Check if target matches any CIDR range
        return await this.findCIDRMatch(target, scanType, organizationId);
      }

      return result.rows[0];
    } catch (error) {
      this.logger.error('Failed to find matching authorization', {
        target,
        scan_type: scanType,
        organization_id: organizationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to find matching authorization');
    }
  }

  /**
   * Find CIDR range match for IP target
   */
  private async findCIDRMatch(
    target: string,
    scanType: string,
    organizationId: string
  ): Promise<AuthorizedTargetRecord | null> {
    try {
      // Get all CIDR authorizations for this organization
      const result = await this.db.query<AuthorizedTargetRecord>(
        `SELECT * FROM target_authorizations
         WHERE target_type = 'cidr'
         AND organization_id = $1
         AND verification_status = 'verified'
         AND (expires_at IS NULL OR expires_at > NOW())
         AND ('*' = ANY(scan_types_allowed) OR $2 = ANY(scan_types_allowed))`,
        [organizationId, scanType]
      );

      // Check if IP falls within any CIDR range
      for (const record of result.rows) {
        if (this.isIPInCIDR(target, record.target)) {
          return record;
        }
      }

      return null;
    } catch (error) {
      this.logger.error('Failed to find CIDR match', {
        target,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return null;
    }
  }

  /**
   * Create new authorization
   */
  async create(authorization: Omit<AuthorizedTargetRecord, 'created_at' | 'updated_at'>): Promise<AuthorizedTargetRecord> {
    try {
      const result = await this.db.query<AuthorizedTargetRecord>(
        `INSERT INTO target_authorizations (
          id, organization_id, target, target_type, description,
          authorized_by, authorized_at, expires_at, scan_types_allowed,
          proof_of_ownership, verification_status, verification_method, notes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING *`,
        [
          authorization.id,
          authorization.organization_id,
          authorization.target,
          authorization.target_type,
          authorization.description,
          authorization.authorized_by,
          authorization.authorized_at,
          authorization.expires_at,
          authorization.scan_types_allowed,
          authorization.proof_of_ownership,
          authorization.verification_status,
          authorization.verification_method,
          authorization.notes
        ]
      );

      this.logger.info('Target authorization created', {
        id: authorization.id,
        target: authorization.target,
        organization_id: authorization.organization_id
      });

      return result.rows[0];
    } catch (error) {
      this.logger.error('Failed to create target authorization', {
        target: authorization.target,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to create target authorization');
    }
  }

  /**
   * Update authorization verification status
   */
  async updateVerificationStatus(
    id: string,
    status: 'pending' | 'verified' | 'rejected',
    notes?: string
  ): Promise<AuthorizedTargetRecord | null> {
    try {
      const result = await this.db.query<AuthorizedTargetRecord>(
        `UPDATE target_authorizations
         SET verification_status = $1,
             notes = COALESCE($2, notes),
             updated_at = NOW()
         WHERE id = $3
         RETURNING *`,
        [status, notes, id]
      );

      if (result.rows.length === 0) {
        return null;
      }

      this.logger.info('Target authorization verification status updated', {
        id,
        status
      });

      return result.rows[0];
    } catch (error) {
      this.logger.error('Failed to update verification status', {
        id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to update verification status');
    }
  }

  /**
   * Delete authorization
   */
  async delete(id: string, organizationId: string): Promise<boolean> {
    try {
      const result = await this.db.query(
        `DELETE FROM target_authorizations
         WHERE id = $1 AND organization_id = $2`,
        [id, organizationId]
      );

      const deleted = (result.rowCount ?? 0) > 0;

      if (deleted) {
        this.logger.info('Target authorization deleted', { id });
      }

      return deleted;
    } catch (error) {
      this.logger.error('Failed to delete target authorization', {
        id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to delete target authorization');
    }
  }

  /**
   * List authorizations for organization
   */
  async listByOrganization(organizationId: string): Promise<AuthorizedTargetRecord[]> {
    try {
      const result = await this.db.query<AuthorizedTargetRecord>(
        `SELECT * FROM target_authorizations
         WHERE organization_id = $1
         ORDER BY created_at DESC`,
        [organizationId]
      );

      return result.rows;
    } catch (error) {
      this.logger.error('Failed to list target authorizations', {
        organization_id: organizationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to list target authorizations');
    }
  }

  /**
   * Find expired authorizations
   */
  async findExpired(): Promise<AuthorizedTargetRecord[]> {
    try {
      const result = await this.db.query<AuthorizedTargetRecord>(
        `SELECT * FROM target_authorizations
         WHERE expires_at IS NOT NULL
         AND expires_at < NOW()
         AND verification_status = 'verified'`
      );

      return result.rows;
    } catch (error) {
      this.logger.error('Failed to find expired authorizations', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to find expired authorizations');
    }
  }

  /**
   * Clean up expired authorizations
   */
  async cleanupExpired(): Promise<number> {
    try {
      const result = await this.db.query(
        `UPDATE target_authorizations
         SET verification_status = 'rejected',
             notes = COALESCE(notes || E'\\n', '') || 'Expired on ' || expires_at::text,
             updated_at = NOW()
         WHERE expires_at IS NOT NULL
         AND expires_at < NOW()
         AND verification_status = 'verified'`
      );

      const count = result.rowCount ?? 0;

      if (count > 0) {
        this.logger.info('Expired authorizations cleaned up', { count });
      }

      return count;
    } catch (error) {
      this.logger.error('Failed to cleanup expired authorizations', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new DatabaseError('Failed to cleanup expired authorizations');
    }
  }

  /**
   * Check if IP is in CIDR range
   */
  private isIPInCIDR(ip: string, cidr: string): boolean {
    try {
      const [range, bits] = cidr.split('/');
      const mask = ~(2 ** (32 - parseInt(bits)) - 1);

      const ipNum = this.ipToNumber(ip);
      const rangeNum = this.ipToNumber(range);

      return (ipNum & mask) === (rangeNum & mask);
    } catch (error) {
      return false;
    }
  }

  /**
   * Convert IP to number
   */
  private ipToNumber(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  }
}

/**
 * Singleton instance
 */
let repository: TargetAuthorizationRepository | null = null;

/**
 * Get repository instance
 */
export function getTargetAuthorizationRepository(): TargetAuthorizationRepository {
  if (!repository) {
    repository = new TargetAuthorizationRepository();
  }
  return repository;
}
