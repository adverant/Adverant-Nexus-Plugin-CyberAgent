/**
 * Nexus-CyberAgent API Types
 *
 * TypeScript type definitions for API requests and responses
 */

import {
  ScanType,
  SandboxTier,
  FindingType,
  Severity,
  JobStatus,
  ScanJob,
  ScanResult,
  MalwareSample,
  IOC,
  YARARule,
  Exploit,
  AgentSession,
  WorkflowExecution,
  TargetAuthorization,
  PaginatedResponse
} from './database.types';

/**
 * ============================================================================
 * Authentication & Authorization
 * ============================================================================
 */

/**
 * JWT Token Payload
 */
export interface JWTPayload {
  user_id: string;
  org_id: string;
  email: string;
  role: UserRole;
  iat: number;
  exp: number;
}

/**
 * User Roles
 */
export type UserRole = 'red_team_operator' | 'blue_team_analyst' | 'researcher' | 'admin';

/**
 * Authentication Context
 */
export interface AuthContext {
  user_id: string;
  org_id: string;
  email: string;
  role: UserRole;
}

/**
 * ============================================================================
 * Scan Job API Types
 * ============================================================================
 */

/**
 * Create Scan Job Request
 */
export interface CreateScanJobRequest {
  scan_type: ScanType;
  target: string;
  priority?: number; // 1-10, default: 3
  sandbox_tier?: SandboxTier;
  tools: string[]; // Array of tool names to use

  /**
   * Local file path for sandbox-first analysis
   * When provided with file:// protocol prefix, CyberAgent reads from shared volume
   * This enables local file analysis without external network access
   *
   * Example: "file:///shared/uploads/binary-abc123.dmg"
   */
  local_file_path?: string;

  /**
   * File metadata for local file analysis
   */
  file_metadata?: {
    filename: string;     // Original filename
    mime_type?: string;   // MIME type of the file
    size?: number;        // File size in bytes
  };

  config?: {
    // Pentest-specific config
    scope?: string[];
    excluded_hosts?: string[];
    ports?: string | number[];
    aggressive_scan?: boolean;

    // Malware-specific config
    analysis_timeout?: number;
    enable_network_simulation?: boolean;
    vm_snapshot?: string;

    // Exploit-specific config
    payload_type?: string;
    target_os?: string;

    // C2-specific config
    c2_framework?: 'cobalt_strike' | 'empire' | 'sliver' | 'metasploit';
    listeners?: any[];

    // APT Simulation config
    ttp_ids?: string[]; // MITRE ATT&CK TTP IDs
    duration?: number; // Simulation duration in minutes

    // Common config
    enable_nexus_integration?: boolean;
    enable_multi_agent?: boolean;
    max_agents?: number;
    enable_autonomous_mode?: boolean;
    workflow_name?: string;
  };
}

/**
 * Create Scan Job Response
 */
export interface CreateScanJobResponse {
  success: boolean;
  job: ScanJob;
  websocket_url?: string; // WebSocket URL for real-time updates
}

/**
 * Update Scan Job Request
 */
export interface UpdateScanJobRequest {
  status?: JobStatus;
  progress?: number; // 0-100
  error?: string;
  config?: Record<string, any>;
}

/**
 * Get Scan Job Response
 */
export interface GetScanJobResponse {
  success: boolean;
  job: ScanJob;
  results?: ScanResult[]; // Include results if requested
  agent_session?: AgentSession; // Include agent session if exists
  workflow_execution?: WorkflowExecution; // Include workflow if exists
}

/**
 * List Scan Jobs Query Parameters
 */
export interface ListScanJobsQuery {
  scan_type?: ScanType;
  status?: JobStatus;
  limit?: number; // Default: 20, max: 100
  offset?: number;
  sort_by?: 'created_at' | 'started_at' | 'completed_at' | 'priority';
  sort_order?: 'asc' | 'desc';
  target_filter?: string; // Filter by target substring
}

/**
 * List Scan Jobs Response
 */
export interface ListScanJobsResponse extends PaginatedResponse<ScanJob> {
  success: boolean;
}

/**
 * Cancel Scan Job Response
 */
export interface CancelScanJobResponse {
  success: boolean;
  message: string;
  job: ScanJob;
}

/**
 * ============================================================================
 * Scan Results API Types
 * ============================================================================
 */

/**
 * List Scan Results Query Parameters
 */
export interface ListScanResultsQuery {
  job_id?: string;
  finding_type?: FindingType;
  severity?: Severity;
  verified_only?: boolean;
  exclude_false_positives?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * List Scan Results Response
 */
export interface ListScanResultsResponse extends PaginatedResponse<ScanResult> {
  success: boolean;
  summary: {
    total: number;
    by_severity: Record<Severity, number>;
    by_finding_type: Record<FindingType, number>;
    verified_count: number;
    false_positive_count: number;
  };
}

/**
 * Update Scan Result Request
 */
export interface UpdateScanResultRequest {
  false_positive?: boolean;
  verified?: boolean;
  remediation?: string;
  notes?: string;
}

/**
 * ============================================================================
 * Malware Analysis API Types
 * ============================================================================
 */

/**
 * Upload Malware Sample Request
 */
export interface UploadMalwareSampleRequest {
  file: Buffer | string; // File buffer or base64 encoded
  file_name: string;
  analysis_options?: {
    priority?: number;
    enable_yara_scan?: boolean;
    enable_static_analysis?: boolean;
    enable_dynamic_analysis?: boolean;
    analysis_timeout?: number; // seconds
    vm_snapshot?: string;
    enable_network_simulation?: boolean;
    enable_agent_analysis?: boolean;
  };
}

/**
 * Upload Malware Sample Response
 */
export interface UploadMalwareSampleResponse {
  success: boolean;
  sample: MalwareSample;
  analysis_job?: ScanJob; // If analysis was triggered
}

/**
 * Get Malware Sample Response
 */
export interface GetMalwareSampleResponse {
  success: boolean;
  sample: MalwareSample;
  iocs?: IOC[];
  related_samples?: MalwareSample[]; // Samples with similar characteristics
}

/**
 * List Malware Samples Query Parameters
 */
export interface ListMalwareSamplesQuery {
  malware_family?: string;
  threat_level?: string;
  analysis_status?: string;
  limit?: number;
  offset?: number;
  search?: string; // Search by hash or filename
}

/**
 * ============================================================================
 * YARA Rules API Types
 * ============================================================================
 */

/**
 * Create YARA Rule Request
 */
export interface CreateYARARuleRequest {
  rule_name: string;
  rule_content: string;
  description?: string;
  author?: string;
  malware_family?: string;
  severity?: Severity;
  tags?: string[];
}

/**
 * Update YARA Rule Request
 */
export interface UpdateYARARuleRequest {
  rule_content?: string;
  description?: string;
  enabled?: boolean;
  severity?: Severity;
  tags?: string[];
}

/**
 * List YARA Rules Query Parameters
 */
export interface ListYARARulesQuery {
  malware_family?: string;
  enabled_only?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * ============================================================================
 * Exploits API Types
 * ============================================================================
 */

/**
 * Create Exploit Request
 */
export interface CreateExploitRequest {
  name: string;
  cve_id?: string;
  description?: string;
  target_platform?: string;
  target_version?: string;
  exploit_type?: string;
  reliability?: string;
  code: string;
  language?: string;
  requirements?: string[];
  references?: string[];
  author?: string;
  tags?: string[];
}

/**
 * List Exploits Query Parameters
 */
export interface ListExploitsQuery {
  cve_id?: string;
  target_platform?: string;
  exploit_type?: string;
  reliability?: string;
  limit?: number;
  offset?: number;
  search?: string; // Search by name or CVE
}

/**
 * Test Exploit Request
 */
export interface TestExploitRequest {
  exploit_id: string;
  target: string;
  config?: {
    payload?: string;
    options?: Record<string, any>;
    timeout?: number;
  };
}

/**
 * Test Exploit Response
 */
export interface TestExploitResponse {
  success: boolean;
  job: ScanJob;
  message: string;
}

/**
 * ============================================================================
 * IOCs API Types
 * ============================================================================
 */

/**
 * Create IOC Request
 */
export interface CreateIOCRequest {
  ioc_type: string;
  ioc_value: string;
  confidence?: number;
  context?: string;
  tags?: string[];
  malware_sample_id?: string;
  scan_job_id?: string;
}

/**
 * Search IOCs Query Parameters
 */
export interface SearchIOCsQuery {
  ioc_type?: string;
  ioc_value?: string; // Partial match
  malware_sample_id?: string;
  scan_job_id?: string;
  min_confidence?: number;
  limit?: number;
  offset?: number;
}

/**
 * ============================================================================
 * Workflow API Types
 * ============================================================================
 */

/**
 * Execute Workflow Request
 */
export interface ExecuteWorkflowRequest {
  workflow_name: string;
  inputs: Record<string, any>;
  config?: {
    enable_nexus_integration?: boolean;
    enable_multi_agent?: boolean;
    max_agents?: number;
  };
}

/**
 * Execute Workflow Response
 */
export interface ExecuteWorkflowResponse {
  success: boolean;
  workflow_execution: WorkflowExecution;
  job?: ScanJob; // If workflow creates a job
  websocket_url?: string;
}

/**
 * ============================================================================
 * Target Authorization API Types
 * ============================================================================
 */

/**
 * Authorize Target Request
 */
export interface AuthorizeTargetRequest {
  target: string;
  authorization_method: 'dns_txt' | 'manual' | 'file_upload';
  notes?: string;
  expires_at?: Date | string;
}

/**
 * Verify Target Authorization Request
 */
export interface VerifyTargetAuthorizationRequest {
  target: string;
}

/**
 * Verify Target Authorization Response
 */
export interface VerifyTargetAuthorizationResponse {
  success: boolean;
  verified: boolean;
  authorization?: TargetAuthorization;
  verification_details?: {
    method: string;
    token_found?: boolean;
    verified_at?: Date;
  };
}

/**
 * ============================================================================
 * Health & Metrics API Types
 * ============================================================================
 */

/**
 * Health Check Response
 */
export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  services: {
    database: ServiceHealth;
    redis: ServiceHealth;
    graphrag: ServiceHealth;
    mageagent: ServiceHealth;
    orchestration_agent: ServiceHealth;
    tier1_sandbox: ServiceHealth;
    tier2_sandbox: ServiceHealth;
    tier3_sandbox: ServiceHealth;
  };
  uptime: number; // seconds
}

/**
 * Service Health Status
 */
export interface ServiceHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  latency?: number; // milliseconds
  error?: string;
}

/**
 * Metrics Response
 */
export interface MetricsResponse {
  jobs: {
    total: number;
    by_status: Record<JobStatus, number>;
    by_type: Record<ScanType, number>;
    avg_duration_seconds: number;
  };
  performance: {
    requests_per_minute: number;
    avg_response_time_ms: number;
    active_connections: number;
    queue_depth: number;
  };
  resources: {
    cpu_usage_percent: number;
    memory_usage_mb: number;
    disk_usage_percent: number;
  };
}

/**
 * ============================================================================
 * WebSocket Event Types
 * ============================================================================
 */

/**
 * WebSocket Event Base
 */
export interface WebSocketEvent {
  job_id: string;
  timestamp: string;
  event_type: WebSocketEventType;
  data: any;
}

/**
 * WebSocket Event Types
 */
export type WebSocketEventType =
  | 'job:created'
  | 'job:started'
  | 'job:progress'
  | 'job:completed'
  | 'job:failed'
  | 'job:cancelled'
  | 'tool:started'
  | 'tool:output'
  | 'tool:completed'
  | 'vulnerability:found'
  | 'malware:detected'
  | 'ioc:extracted'
  | 'exploit:success'
  | 'exploit:failed'
  | 'agent:spawned'
  | 'agent:thinking'
  | 'agent:action'
  | 'agent:completed'
  | 'workflow:phase_started'
  | 'workflow:phase_completed'
  | 'nexus:recall'
  | 'nexus:stored';

/**
 * Job Progress Event
 */
export interface JobProgressEvent extends WebSocketEvent {
  event_type: 'job:progress';
  data: {
    progress: number; // 0-100
    current_phase?: string;
    message?: string;
  };
}

/**
 * Vulnerability Found Event
 */
export interface VulnerabilityFoundEvent extends WebSocketEvent {
  event_type: 'vulnerability:found';
  data: {
    severity: Severity;
    title: string;
    cve_id?: string;
    cvss_score?: number;
    affected_target?: string;
  };
}

/**
 * Agent Event
 */
export interface AgentEvent extends WebSocketEvent {
  event_type: 'agent:spawned' | 'agent:thinking' | 'agent:action' | 'agent:completed';
  data: {
    agent_id: string;
    agent_role?: string;
    model?: string;
    thought?: string;
    action?: string;
    result?: any;
  };
}

/**
 * ============================================================================
 * Error Response Types
 * ============================================================================
 */

/**
 * API Error Response
 */
export interface APIErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    request_id?: string;
  };
}

/**
 * Standard API Response Wrapper
 */
export type APIResponse<T> = T | APIErrorResponse;
