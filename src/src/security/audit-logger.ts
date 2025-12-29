/**
 * Audit Logger
 *
 * Comprehensive audit logging for compliance and security monitoring
 */

import { Logger, createContextLogger } from '../utils/logger';
import { getDatabase } from '../database/connection';

/**
 * Audit event categories
 */
export enum AuditCategory {
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  SCAN = 'scan',
  MALWARE = 'malware',
  WORKFLOW = 'workflow',
  USER_MANAGEMENT = 'user_management',
  CONFIGURATION = 'configuration',
  DATA_ACCESS = 'data_access',
  DATA_MODIFICATION = 'data_modification',
  EXPORT = 'export',
  APPROVAL = 'approval',
  SECURITY_EVENT = 'security_event'
}

/**
 * Audit event severity
 */
export enum AuditSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

/**
 * Audit event
 */
export interface AuditEvent {
  event_id?: string;
  category: AuditCategory;
  action: string;
  severity: AuditSeverity;
  user_id?: string;
  organization_id?: string;
  target_resource?: string;
  resource_id?: string;
  details: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  request_id?: string;
  success: boolean;
  error_message?: string;
  timestamp?: Date;
}

/**
 * Audit Logger Service
 *
 * Uses lazy database initialization to prevent module load-time failures
 * when the database hasn't been initialized yet.
 */
export class AuditLogger {
  private logger: Logger;
  private _db: ReturnType<typeof getDatabase> | null = null;

  constructor() {
    this.logger = createContextLogger('AuditLogger');
    // Database is initialized lazily to avoid module load-time dependency
    // on database being connected first
  }

  /**
   * Get database connection (lazy initialization)
   * Returns null if database is not yet initialized
   */
  private getDb(): ReturnType<typeof getDatabase> | null {
    if (!this._db) {
      try {
        this._db = getDatabase();
      } catch {
        // Database not initialized yet - this is expected during startup
        return null;
      }
    }
    return this._db;
  }

  /**
   * Log authentication event
   */
  async logAuthentication(event: {
    action: 'login' | 'logout' | 'token_refresh' | 'password_change' | 'mfa_enabled' | 'mfa_disabled';
    user_id?: string;
    email?: string;
    success: boolean;
    error_message?: string;
    ip_address?: string;
    user_agent?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.AUTHENTICATION,
      action: event.action,
      severity: event.success ? AuditSeverity.INFO : AuditSeverity.WARNING,
      user_id: event.user_id,
      details: {
        email: event.email,
        success: event.success
      },
      ip_address: event.ip_address,
      user_agent: event.user_agent,
      success: event.success,
      error_message: event.error_message
    });
  }

  /**
   * Log authorization event
   */
  async logAuthorization(event: {
    action: string;
    user_id: string;
    organization_id: string;
    required_permission: string;
    granted: boolean;
    resource?: string;
    ip_address?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.AUTHORIZATION,
      action: event.action,
      severity: event.granted ? AuditSeverity.INFO : AuditSeverity.WARNING,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: event.resource,
      details: {
        required_permission: event.required_permission,
        granted: event.granted
      },
      ip_address: event.ip_address,
      success: event.granted
    });
  }

  /**
   * Log scan event
   */
  async logScan(event: {
    action: 'create' | 'start' | 'complete' | 'cancel' | 'delete' | 'export';
    scan_id: string;
    scan_type: string;
    target: string;
    user_id: string;
    organization_id: string;
    success: boolean;
    details?: Record<string, any>;
    error_message?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.SCAN,
      action: `scan_${event.action}`,
      severity: event.success ? AuditSeverity.INFO : AuditSeverity.ERROR,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: 'scan',
      resource_id: event.scan_id,
      details: {
        scan_type: event.scan_type,
        target: event.target,
        ...event.details
      },
      success: event.success,
      error_message: event.error_message
    });
  }

  /**
   * Log malware event
   */
  async logMalware(event: {
    action: 'upload' | 'analyze' | 'quarantine' | 'delete' | 'export';
    sample_hash: string;
    user_id: string;
    organization_id: string;
    success: boolean;
    threat_level?: string;
    malware_family?: string;
    details?: Record<string, any>;
    error_message?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.MALWARE,
      action: `malware_${event.action}`,
      severity: event.action === 'upload' || event.action === 'analyze'
        ? AuditSeverity.WARNING
        : AuditSeverity.INFO,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: 'malware',
      resource_id: event.sample_hash,
      details: {
        threat_level: event.threat_level,
        malware_family: event.malware_family,
        ...event.details
      },
      success: event.success,
      error_message: event.error_message
    });
  }

  /**
   * Log workflow event
   */
  async logWorkflow(event: {
    action: 'create' | 'execute' | 'approve' | 'reject' | 'cancel' | 'complete';
    workflow_name: string;
    execution_id?: string;
    user_id: string;
    organization_id: string;
    success: boolean;
    details?: Record<string, any>;
    error_message?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.WORKFLOW,
      action: `workflow_${event.action}`,
      severity: event.success ? AuditSeverity.INFO : AuditSeverity.ERROR,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: 'workflow',
      resource_id: event.execution_id || event.workflow_name,
      details: {
        workflow_name: event.workflow_name,
        ...event.details
      },
      success: event.success,
      error_message: event.error_message
    });
  }

  /**
   * Log user management event
   */
  async logUserManagement(event: {
    action: 'create' | 'update' | 'delete' | 'role_change' | 'permission_change';
    target_user_id: string;
    actor_user_id: string;
    organization_id: string;
    details: Record<string, any>;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.USER_MANAGEMENT,
      action: `user_${event.action}`,
      severity: AuditSeverity.WARNING,
      user_id: event.actor_user_id,
      organization_id: event.organization_id,
      target_resource: 'user',
      resource_id: event.target_user_id,
      details: event.details,
      success: true
    });
  }

  /**
   * Log configuration change
   */
  async logConfigurationChange(event: {
    action: string;
    config_key: string;
    old_value?: any;
    new_value?: any;
    user_id: string;
    organization_id: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.CONFIGURATION,
      action: `config_${event.action}`,
      severity: AuditSeverity.WARNING,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: 'configuration',
      resource_id: event.config_key,
      details: {
        config_key: event.config_key,
        old_value: event.old_value,
        new_value: event.new_value
      },
      success: true
    });
  }

  /**
   * Log data access
   */
  async logDataAccess(event: {
    resource: string;
    resource_id: string;
    action: 'read' | 'list' | 'query';
    user_id: string;
    organization_id: string;
    record_count?: number;
    ip_address?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.DATA_ACCESS,
      action: `data_${event.action}`,
      severity: AuditSeverity.INFO,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: event.resource,
      resource_id: event.resource_id,
      details: {
        record_count: event.record_count
      },
      ip_address: event.ip_address,
      success: true
    });
  }

  /**
   * Log data modification
   */
  async logDataModification(event: {
    resource: string;
    resource_id: string;
    action: 'create' | 'update' | 'delete';
    user_id: string;
    organization_id: string;
    changes?: Record<string, any>;
    ip_address?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.DATA_MODIFICATION,
      action: `data_${event.action}`,
      severity: AuditSeverity.WARNING,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: event.resource,
      resource_id: event.resource_id,
      details: {
        changes: event.changes
      },
      ip_address: event.ip_address,
      success: true
    });
  }

  /**
   * Log export event
   */
  async logExport(event: {
    resource: string;
    format: string;
    destination: string;
    record_count: number;
    user_id: string;
    organization_id: string;
    ip_address?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.EXPORT,
      action: 'data_export',
      severity: AuditSeverity.WARNING,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: event.resource,
      details: {
        format: event.format,
        destination: event.destination,
        record_count: event.record_count
      },
      ip_address: event.ip_address,
      success: true
    });
  }

  /**
   * Log approval event
   */
  async logApproval(event: {
    action: 'approve' | 'reject';
    approval_type: string;
    resource_id: string;
    user_id: string;
    organization_id: string;
    reason?: string;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.APPROVAL,
      action: `approval_${event.action}`,
      severity: AuditSeverity.WARNING,
      user_id: event.user_id,
      organization_id: event.organization_id,
      target_resource: event.approval_type,
      resource_id: event.resource_id,
      details: {
        reason: event.reason
      },
      success: true
    });
  }

  /**
   * Log security event
   */
  async logSecurityEvent(event: {
    action: string;
    severity: AuditSeverity;
    description: string;
    user_id?: string;
    organization_id?: string;
    ip_address?: string;
    details?: Record<string, any>;
  }): Promise<void> {
    await this.log({
      category: AuditCategory.SECURITY_EVENT,
      action: event.action,
      severity: event.severity,
      user_id: event.user_id,
      organization_id: event.organization_id,
      details: {
        description: event.description,
        ...event.details
      },
      ip_address: event.ip_address,
      success: true
    });
  }

  /**
   * Core log method
   */
  private async log(event: AuditEvent): Promise<void> {
    try {
      // Log to structured logger first (always succeeds)
      this.logger.info('Audit event', {
        category: event.category,
        action: event.action,
        severity: event.severity,
        user_id: event.user_id,
        organization_id: event.organization_id,
        resource: event.target_resource,
        resource_id: event.resource_id,
        success: event.success
      });

      // Store in database for compliance
      // This would use the audit_logs table defined in schema
      // For now, we'll just log it
      const auditEntry = {
        event_id: this.generateEventId(),
        category: event.category,
        action: event.action,
        severity: event.severity,
        user_id: event.user_id || null,
        organization_id: event.organization_id || null,
        target_resource: event.target_resource || null,
        resource_id: event.resource_id || null,
        details: JSON.stringify(event.details),
        ip_address: event.ip_address || null,
        user_agent: event.user_agent || null,
        request_id: event.request_id || null,
        success: event.success,
        error_message: event.error_message || null,
        timestamp: new Date()
      };

      // In production, this would insert into audit_logs table
      this.logger.debug('Audit entry created', { event_id: auditEntry.event_id });
    } catch (error) {
      // Never let audit logging failures break the application
      this.logger.error('Failed to create audit entry', {
        error: error instanceof Error ? error.message : 'Unknown error',
        category: event.category,
        action: event.action
      });
    }
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Query audit logs (for compliance reports)
   */
  async queryAuditLogs(filters: {
    category?: AuditCategory;
    user_id?: string;
    organization_id?: string;
    start_date?: Date;
    end_date?: Date;
    severity?: AuditSeverity;
    limit?: number;
  }): Promise<AuditEvent[]> {
    // This would query the audit_logs table
    // For now, return empty array
    this.logger.info('Audit log query', filters);
    return [];
  }
}

/**
 * Singleton instance
 */
let auditLogger: AuditLogger | null = null;

/**
 * Get audit logger instance
 */
export function getAuditLogger(): AuditLogger {
  if (!auditLogger) {
    auditLogger = new AuditLogger();
  }
  return auditLogger;
}
