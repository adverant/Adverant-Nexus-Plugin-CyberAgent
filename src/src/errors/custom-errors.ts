/**
 * Custom Error Classes
 *
 * Comprehensive error hierarchy for the Nexus-CyberAgent API
 */

/**
 * Base Application Error
 */
export class ApplicationError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly isOperational: boolean;
  public readonly details?: any;

  constructor(
    message: string,
    statusCode: number = 500,
    code: string = 'INTERNAL_ERROR',
    isOperational: boolean = true,
    details?: any
  ) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.details = details;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * ============================================================================
 * Client Errors (4xx)
 * ============================================================================
 */

/**
 * Bad Request Error (400)
 */
export class BadRequestError extends ApplicationError {
  constructor(message: string = 'Bad request', details?: any) {
    super(message, 400, 'BAD_REQUEST', true, details);
  }
}

/**
 * Validation Error (400)
 */
export class ValidationError extends ApplicationError {
  constructor(message: string = 'Validation failed', details?: any) {
    super(message, 400, 'VALIDATION_ERROR', true, details);
  }
}

/**
 * Unauthorized Error (401)
 */
export class UnauthorizedError extends ApplicationError {
  constructor(message: string = 'Unauthorized', details?: any) {
    super(message, 401, 'UNAUTHORIZED', true, details);
  }
}

/**
 * Authentication Error (401)
 */
export class AuthenticationError extends ApplicationError {
  constructor(message: string = 'Authentication failed', details?: any) {
    super(message, 401, 'AUTHENTICATION_ERROR', true, details);
  }
}

/**
 * Invalid Token Error (401)
 */
export class InvalidTokenError extends ApplicationError {
  constructor(message: string = 'Invalid or expired token', details?: any) {
    super(message, 401, 'INVALID_TOKEN', true, details);
  }
}

/**
 * Forbidden Error (403)
 */
export class ForbiddenError extends ApplicationError {
  constructor(message: string = 'Forbidden', details?: any) {
    super(message, 403, 'FORBIDDEN', true, details);
  }
}

/**
 * Insufficient Permissions Error (403)
 */
export class InsufficientPermissionsError extends ApplicationError {
  constructor(message: string = 'Insufficient permissions', details?: any) {
    super(message, 403, 'INSUFFICIENT_PERMISSIONS', true, details);
  }
}

/**
 * Not Found Error (404)
 */
export class NotFoundError extends ApplicationError {
  constructor(resource: string = 'Resource', details?: any) {
    super(`${resource} not found`, 404, 'NOT_FOUND', true, details);
  }
}

/**
 * Conflict Error (409)
 */
export class ConflictError extends ApplicationError {
  constructor(message: string = 'Resource conflict', details?: any) {
    super(message, 409, 'CONFLICT', true, details);
  }
}

/**
 * Duplicate Resource Error (409)
 */
export class DuplicateResourceError extends ApplicationError {
  constructor(resource: string = 'Resource', details?: any) {
    super(`${resource} already exists`, 409, 'DUPLICATE_RESOURCE', true, details);
  }
}

/**
 * Too Many Requests Error (429)
 */
export class TooManyRequestsError extends ApplicationError {
  constructor(message: string = 'Too many requests', details?: any) {
    super(message, 429, 'TOO_MANY_REQUESTS', true, details);
  }
}

/**
 * ============================================================================
 * Server Errors (5xx)
 * ============================================================================
 */

/**
 * Internal Server Error (500)
 */
export class InternalServerError extends ApplicationError {
  constructor(message: string = 'Internal server error', details?: any) {
    super(message, 500, 'INTERNAL_ERROR', true, details);
  }
}

/**
 * Database Error (500)
 */
export class DatabaseError extends ApplicationError {
  constructor(message: string = 'Database operation failed', details?: any) {
    super(message, 500, 'DATABASE_ERROR', true, details);
  }
}

/**
 * External Service Error (502)
 */
export class ExternalServiceError extends ApplicationError {
  constructor(service: string, message?: string, details?: any) {
    super(
      message || `External service '${service}' is unavailable`,
      502,
      'EXTERNAL_SERVICE_ERROR',
      true,
      { service, ...details }
    );
  }
}

/**
 * Service Unavailable Error (503)
 */
export class ServiceUnavailableError extends ApplicationError {
  constructor(message: string = 'Service temporarily unavailable', details?: any) {
    super(message, 503, 'SERVICE_UNAVAILABLE', true, details);
  }
}

/**
 * Gateway Timeout Error (504)
 */
export class GatewayTimeoutError extends ApplicationError {
  constructor(message: string = 'Gateway timeout', details?: any) {
    super(message, 504, 'GATEWAY_TIMEOUT', true, details);
  }
}

/**
 * ============================================================================
 * Business Logic Errors
 * ============================================================================
 */

/**
 * Job Error
 */
export class JobError extends ApplicationError {
  constructor(message: string, details?: any) {
    super(message, 400, 'JOB_ERROR', true, details);
  }
}

/**
 * Invalid Job Status Error
 */
export class InvalidJobStatusError extends ApplicationError {
  constructor(message: string = 'Invalid job status transition', details?: any) {
    super(message, 400, 'INVALID_JOB_STATUS', true, details);
  }
}

/**
 * Job Not Found Error
 */
export class JobNotFoundError extends ApplicationError {
  constructor(jobId: string) {
    super('Job not found', 404, 'JOB_NOT_FOUND', true, { job_id: jobId });
  }
}

/**
 * Sandbox Error
 */
export class SandboxError extends ApplicationError {
  constructor(message: string, tier?: string, details?: any) {
    super(message, 500, 'SANDBOX_ERROR', true, { tier, ...details });
  }
}

/**
 * Sandbox Unavailable Error
 */
export class SandboxUnavailableError extends ApplicationError {
  constructor(tier: string) {
    super(`Sandbox tier ${tier} is unavailable`, 503, 'SANDBOX_UNAVAILABLE', true, { tier });
  }
}

/**
 * Tool Execution Error
 */
export class ToolExecutionError extends ApplicationError {
  constructor(tool: string, message: string, details?: any) {
    super(`Tool '${tool}' execution failed: ${message}`, 500, 'TOOL_EXECUTION_ERROR', true, {
      tool,
      ...details
    });
  }
}

/**
 * Malware Analysis Error
 */
export class MalwareAnalysisError extends ApplicationError {
  constructor(message: string, details?: any) {
    super(message, 500, 'MALWARE_ANALYSIS_ERROR', true, details);
  }
}

/**
 * Malware Sample Not Found Error
 */
export class MalwareSampleNotFoundError extends ApplicationError {
  constructor(identifier: string) {
    super('Malware sample not found', 404, 'MALWARE_SAMPLE_NOT_FOUND', true, { identifier });
  }
}

/**
 * Target Authorization Error
 */
export class TargetAuthorizationError extends ApplicationError {
  constructor(message: string = 'Target authorization failed', details?: any) {
    super(message, 403, 'TARGET_AUTHORIZATION_ERROR', true, details);
  }
}

/**
 * Target Not Authorized Error
 */
export class TargetNotAuthorizedError extends ApplicationError {
  constructor(target: string) {
    super(`Target '${target}' is not authorized for scanning`, 403, 'TARGET_NOT_AUTHORIZED', true, { target });
  }
}

/**
 * Workflow Error
 */
export class WorkflowError extends ApplicationError {
  constructor(message: string, details?: any) {
    super(message, 400, 'WORKFLOW_ERROR', true, details);
  }
}

/**
 * Workflow Execution Error
 */
export class WorkflowExecutionError extends ApplicationError {
  constructor(workflowName: string, message: string, details?: any) {
    super(`Workflow '${workflowName}' execution failed: ${message}`, 500, 'WORKFLOW_EXECUTION_ERROR', true, {
      workflow: workflowName,
      ...details
    });
  }
}

/**
 * Nexus Integration Error
 */
export class NexusIntegrationError extends ApplicationError {
  constructor(service: string, message: string, details?: any) {
    super(`Nexus service '${service}' error: ${message}`, 502, 'NEXUS_INTEGRATION_ERROR', true, {
      service,
      ...details
    });
  }
}

/**
 * Agent Orchestration Error
 */
export class AgentOrchestrationError extends ApplicationError {
  constructor(message: string, details?: any) {
    super(message, 500, 'AGENT_ORCHESTRATION_ERROR', true, details);
  }
}

/**
 * Storage Error
 */
export class StorageError extends ApplicationError {
  constructor(message: string, details?: any) {
    super(message, 500, 'STORAGE_ERROR', true, details);
  }
}

/**
 * File Upload Error
 */
export class FileUploadError extends ApplicationError {
  constructor(message: string, details?: any) {
    super(message, 400, 'FILE_UPLOAD_ERROR', true, details);
  }
}

/**
 * Configuration Error
 */
export class ConfigurationError extends ApplicationError {
  constructor(message: string, details?: any) {
    super(message, 500, 'CONFIGURATION_ERROR', false, details);
  }
}

/**
 * ============================================================================
 * Error Type Guards
 * ============================================================================
 */

/**
 * Check if error is an operational error (expected, can be handled gracefully)
 */
export function isOperationalError(error: Error): boolean {
  if (error instanceof ApplicationError) {
    return error.isOperational;
  }
  return false;
}

/**
 * Check if error is a client error (4xx)
 */
export function isClientError(error: Error): boolean {
  if (error instanceof ApplicationError) {
    return error.statusCode >= 400 && error.statusCode < 500;
  }
  return false;
}

/**
 * Check if error is a server error (5xx)
 */
export function isServerError(error: Error): boolean {
  if (error instanceof ApplicationError) {
    return error.statusCode >= 500;
  }
  return false;
}
