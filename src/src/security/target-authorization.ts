/**
 * Target Authorization Service
 *
 * Ensures scans are only performed on authorized targets
 * Prevents unauthorized scanning and potential legal issues
 */

import { Logger, createContextLogger } from '../utils/logger';
import { getDatabase } from '../database/connection';
import { ForbiddenError, ValidationError } from '../errors/custom-errors';
import { getAuditLogger, AuditSeverity } from './audit-logger';
import { getTargetAuthorizationRepository } from '../database/repositories/target-authorization.repository';
import * as dns from 'dns/promises';
import * as net from 'net';

const logger = createContextLogger('TargetAuthorization');
const auditLogger = getAuditLogger();

/**
 * Target authorization entry
 */
export interface AuthorizedTarget {
  id: string;
  organization_id: string;
  target: string;
  target_type: 'ip' | 'domain' | 'cidr' | 'hostname';
  description?: string;
  authorized_by: string;
  authorized_at: Date;
  expires_at?: Date;
  scan_types_allowed: string[]; // ['pentest', 'malware', 'vuln_scan'] or ['*'] for all
  proof_of_ownership?: string; // URL, DNS record, file path, etc.
  verification_status: 'pending' | 'verified' | 'rejected';
  verification_method?: 'dns_txt' | 'file_upload' | 'email' | 'manual';
  notes?: string;
}

/**
 * Target verification result
 */
export interface TargetVerificationResult {
  authorized: boolean;
  target: string;
  matched_authorization?: AuthorizedTarget;
  reason?: string;
}

/**
 * Target Authorization Service
 */
export class TargetAuthorizationService {
  private logger: Logger;
  private db: ReturnType<typeof getDatabase>;
  private repository: ReturnType<typeof getTargetAuthorizationRepository>;

  constructor() {
    this.logger = createContextLogger('TargetAuthorizationService');
    this.db = getDatabase();
    this.repository = getTargetAuthorizationRepository();
  }

  /**
   * Check if target is authorized for scanning
   */
  async isTargetAuthorized(
    target: string,
    scanType: string,
    organizationId: string
  ): Promise<TargetVerificationResult> {
    try {
      this.logger.debug('Checking target authorization', {
        target,
        scan_type: scanType,
        organization_id: organizationId
      });

      // Normalize target
      const normalizedTarget = this.normalizeTarget(target);

      // Check if target is in authorized list
      const authorization = await this.findAuthorization(normalizedTarget, scanType, organizationId);

      if (!authorization) {
        this.logger.warn('Unauthorized target access attempt', {
          target,
          scan_type: scanType,
          organization_id: organizationId
        });

        // Audit log unauthorized attempt
        await auditLogger.logSecurityEvent({
          action: 'unauthorized_target_scan_attempt',
          severity: AuditSeverity.CRITICAL,
          description: `Attempt to scan unauthorized target: ${target}`,
          organization_id: organizationId,
          details: {
            target,
            scan_type: scanType
          }
        });

        return {
          authorized: false,
          target: normalizedTarget,
          reason: 'Target not in authorized list'
        };
      }

      // Check if authorization is expired
      if (authorization.expires_at && new Date() > authorization.expires_at) {
        this.logger.warn('Expired authorization', {
          target,
          expired_at: authorization.expires_at
        });

        return {
          authorized: false,
          target: normalizedTarget,
          matched_authorization: authorization,
          reason: 'Authorization expired'
        };
      }

      // Check if scan type is allowed
      if (!authorization.scan_types_allowed.includes('*') &&
          !authorization.scan_types_allowed.includes(scanType)) {
        this.logger.warn('Scan type not authorized for target', {
          target,
          scan_type: scanType,
          allowed_types: authorization.scan_types_allowed
        });

        return {
          authorized: false,
          target: normalizedTarget,
          matched_authorization: authorization,
          reason: `Scan type ${scanType} not authorized for this target`
        };
      }

      // Check verification status
      if (authorization.verification_status !== 'verified') {
        this.logger.warn('Target not verified', {
          target,
          verification_status: authorization.verification_status
        });

        return {
          authorized: false,
          target: normalizedTarget,
          matched_authorization: authorization,
          reason: `Target verification status: ${authorization.verification_status}`
        };
      }

      this.logger.info('Target authorized', {
        target,
        scan_type: scanType,
        organization_id: organizationId
      });

      return {
        authorized: true,
        target: normalizedTarget,
        matched_authorization: authorization
      };
    } catch (error) {
      this.logger.error('Target authorization check failed', {
        target,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Enforce target authorization (throws if unauthorized)
   */
  async enforceTargetAuthorization(
    target: string,
    scanType: string,
    organizationId: string,
    userId: string
  ): Promise<void> {
    const result = await this.isTargetAuthorized(target, scanType, organizationId);

    if (!result.authorized) {
      // Audit log
      await auditLogger.logSecurityEvent({
        action: 'target_authorization_denied',
        severity: AuditSeverity.CRITICAL,
        description: `Target authorization denied: ${result.reason}`,
        user_id: userId,
        organization_id: organizationId,
        details: {
          target,
          scan_type: scanType,
          reason: result.reason
        }
      });

      throw new ForbiddenError(
        `Target not authorized for scanning: ${result.reason}`
      );
    }
  }

  /**
   * Add authorized target
   *
   * Production implementation with PostgreSQL persistence
   */
  async addAuthorizedTarget(
    target: AuthorizedTarget,
    userId: string
  ): Promise<string> {
    try {
      const targetId = `target_${Date.now()}_${Math.random().toString(36).substring(7)}`;

      // Validate target format
      this.validateTargetFormat(target.target, target.target_type);

      // Store in database
      await this.repository.create({
        id: targetId,
        organization_id: target.organization_id,
        target: target.target,
        target_type: target.target_type,
        description: target.description,
        authorized_by: target.authorized_by,
        authorized_at: target.authorized_at,
        expires_at: target.expires_at,
        scan_types_allowed: target.scan_types_allowed,
        proof_of_ownership: target.proof_of_ownership,
        verification_status: target.verification_status,
        verification_method: target.verification_method,
        notes: target.notes
      });

      this.logger.info('Authorized target added to database', {
        target_id: targetId,
        target: target.target,
        organization_id: target.organization_id
      });

      // Audit log
      await auditLogger.logSecurityEvent({
        action: 'target_authorized',
        severity: AuditSeverity.WARNING,
        description: `New target authorized: ${target.target}`,
        user_id: userId,
        organization_id: target.organization_id,
        details: {
          target: target.target,
          target_type: target.target_type,
          scan_types_allowed: target.scan_types_allowed
        }
      });

      return targetId;
    } catch (error) {
      this.logger.error('Failed to add authorized target', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Remove authorized target
   *
   * Production implementation with PostgreSQL persistence
   */
  async removeAuthorizedTarget(
    targetId: string,
    organizationId: string,
    userId: string
  ): Promise<void> {
    try {
      // Remove from database
      const deleted = await this.repository.delete(targetId, organizationId);

      if (!deleted) {
        throw new ValidationError(`Target authorization not found: ${targetId}`);
      }

      this.logger.info('Authorized target removed from database', {
        target_id: targetId,
        organization_id: organizationId
      });

      // Audit log
      await auditLogger.logSecurityEvent({
        action: 'target_deauthorized',
        severity: AuditSeverity.WARNING,
        description: `Target authorization removed: ${targetId}`,
        user_id: userId,
        organization_id: organizationId,
        details: {
          target_id: targetId
        }
      });
    } catch (error) {
      this.logger.error('Failed to remove authorized target', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Verify target ownership via DNS TXT record
   */
  async verifyTargetViaDNS(
    target: string,
    expectedToken: string
  ): Promise<boolean> {
    try {
      const records = await dns.resolveTxt(target);

      // Look for TXT record with token
      const tokenRecord = records
        .flat()
        .find(record => record.includes(`nexus-cyberagent-verification=${expectedToken}`));

      return !!tokenRecord;
    } catch (error) {
      this.logger.error('DNS verification failed', {
        target,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return false;
    }
  }

  /**
   * Verify target ownership via file upload
   */
  async verifyTargetViaFile(
    target: string,
    expectedToken: string
  ): Promise<boolean> {
    try {
      // Attempt to fetch verification file from target
      // e.g., https://target.com/.well-known/nexus-cyberagent-verification.txt
      // For now, return false (would implement HTTP fetch)
      return false;
    } catch (error) {
      this.logger.error('File verification failed', {
        target,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return false;
    }
  }

  /**
   * List authorized targets for organization
   *
   * Production implementation with PostgreSQL persistence
   */
  async listAuthorizedTargets(organizationId: string): Promise<AuthorizedTarget[]> {
    try {
      this.logger.debug('Listing authorized targets from database', {
        organization_id: organizationId
      });

      const records = await this.repository.listByOrganization(organizationId);

      // Convert database records to AuthorizedTarget interface
      return records.map(record => ({
        id: record.id,
        organization_id: record.organization_id,
        target: record.target,
        target_type: record.target_type,
        description: record.description,
        authorized_by: record.authorized_by,
        authorized_at: record.authorized_at,
        expires_at: record.expires_at,
        scan_types_allowed: record.scan_types_allowed,
        proof_of_ownership: record.proof_of_ownership,
        verification_status: record.verification_status,
        verification_method: record.verification_method,
        notes: record.notes
      }));
    } catch (error) {
      this.logger.error('Failed to list authorized targets', {
        organization_id: organizationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Check if IP is in CIDR range
   */
  isIPInCIDR(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);

    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);

    return (ipNum & mask) === (rangeNum & mask);
  }

  /**
   * Find matching authorization
   *
   * Production implementation with PostgreSQL persistence
   */
  private async findAuthorization(
    target: string,
    scanType: string,
    organizationId: string
  ): Promise<AuthorizedTarget | null> {
    try {
      // Query database for matching authorization
      const record = await this.repository.findMatchingAuthorization(
        target,
        scanType,
        organizationId
      );

      if (!record) {
        this.logger.debug('No authorization found', {
          target,
          scan_type: scanType,
          organization_id: organizationId
        });
        return null;
      }

      // Convert database record to AuthorizedTarget interface
      const authorization: AuthorizedTarget = {
        id: record.id,
        organization_id: record.organization_id,
        target: record.target,
        target_type: record.target_type,
        description: record.description,
        authorized_by: record.authorized_by,
        authorized_at: record.authorized_at,
        expires_at: record.expires_at,
        scan_types_allowed: record.scan_types_allowed,
        proof_of_ownership: record.proof_of_ownership,
        verification_status: record.verification_status,
        verification_method: record.verification_method,
        notes: record.notes
      };

      return authorization;
    } catch (error) {
      this.logger.error('Database query failed during authorization check', {
        target,
        scan_type: scanType,
        organization_id: organizationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      // Fail secure: return null on database error
      return null;
    }
  }

  /**
   * Normalize target format
   */
  private normalizeTarget(target: string): string {
    // Remove protocol if present
    target = target.replace(/^https?:\/\//, '');

    // Remove port if present
    target = target.replace(/:\d+$/, '');

    // Remove trailing slash
    target = target.replace(/\/$/, '');

    // Convert to lowercase
    return target.toLowerCase();
  }

  /**
   * Validate target format
   */
  private validateTargetFormat(target: string, targetType: string): void {
    switch (targetType) {
      case 'ip':
        if (!net.isIP(target)) {
          throw new ValidationError(`Invalid IP address: ${target}`);
        }
        break;

      case 'cidr':
        if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) {
          throw new ValidationError(`Invalid CIDR notation: ${target}`);
        }
        break;

      case 'domain':
      case 'hostname':
        if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(target)) {
          throw new ValidationError(`Invalid domain/hostname: ${target}`);
        }
        break;

      default:
        throw new ValidationError(`Unknown target type: ${targetType}`);
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
let targetAuthorizationService: TargetAuthorizationService | null = null;

/**
 * Get target authorization service instance
 */
export function getTargetAuthorizationService(): TargetAuthorizationService {
  if (!targetAuthorizationService) {
    targetAuthorizationService = new TargetAuthorizationService();
  }
  return targetAuthorizationService;
}
