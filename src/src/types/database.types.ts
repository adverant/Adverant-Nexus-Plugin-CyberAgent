/**
 * Nexus-CyberAgent Database Types
 *
 * TypeScript type definitions matching the PostgreSQL database schema
 */

/**
 * Scan Types
 */
export type ScanType = 'pentest' | 'malware' | 'exploit' | 'c2' | 'apt_simulation';

/**
 * Job Status
 */
export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

/**
 * Sandbox Tiers
 */
export type SandboxTier = 'tier1' | 'tier2' | 'tier3';

/**
 * Finding Types
 */
export type FindingType = 'vulnerability' | 'malware' | 'exploit' | 'ioc' | 'config_issue' | 'credential';

/**
 * Severity Levels
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Analysis Status
 */
export type AnalysisStatus = 'pending' | 'analyzing' | 'completed' | 'failed';

/**
 * Threat Levels
 */
export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'benign';

/**
 * Storage Backends
 */
export type StorageBackend = 'minio' | 'google_drive' | 'local';

/**
 * IOC Types
 */
export type IOCType = 'ip' | 'domain' | 'url' | 'hash' | 'registry' | 'mutex' | 'file_path' | 'email';

/**
 * Orchestration Types
 */
export type OrchestrationType = 'mageagent' | 'orchestration_agent';

/**
 * Agent Session Status
 */
export type AgentSessionStatus = 'initializing' | 'running' | 'completed' | 'failed';

/**
 * Workflow Status
 */
export type WorkflowStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

/**
 * Exploit Types
 */
export type ExploitType = 'remote' | 'local' | 'web' | 'dos' | 'privilege_escalation';

/**
 * Exploit Reliability
 */
export type ExploitReliability = 'excellent' | 'great' | 'good' | 'average' | 'low';

/**
 * Authorization Methods
 */
export type AuthorizationMethod = 'dns_txt' | 'manual' | 'file_upload';

/**
 * Scan Job Interface
 */
export interface ScanJob {
  id: string;
  org_id: string;
  user_id: string;
  scan_type: ScanType;
  target: string;
  status: JobStatus;
  priority: number; // 1-10
  sandbox_tier?: SandboxTier;
  tools: string[]; // JSON array of tool names
  config: Record<string, any>; // JSON configuration
  progress: number; // 0-100
  error?: string;
  created_at: Date;
  started_at?: Date;
  completed_at?: Date;
  updated_at: Date;
}

/**
 * Scan Result Interface
 */
export interface ScanResult {
  id: string;
  job_id: string;
  finding_type: FindingType;
  severity: Severity;
  title: string;
  description?: string;
  affected_target?: string;
  cvss_score?: number; // 0.0-10.0
  cve_id?: string;
  cwe_id?: string;
  remediation?: string;
  evidence: Record<string, any>; // JSON evidence data
  false_positive: boolean;
  verified: boolean;
  created_at: Date;
}

/**
 * Malware Sample Interface
 */
export interface MalwareSample {
  id: string;
  org_id: string;
  user_id: string;
  sha256: string;
  md5: string;
  sha1: string;
  file_name?: string;
  file_size?: number;
  mime_type?: string;
  storage_path: string;
  storage_backend: StorageBackend;
  first_seen: Date;
  last_analyzed?: Date;
  analysis_status: AnalysisStatus;
  malware_family?: string;
  threat_level?: ThreatLevel;
  yara_matches: string[]; // JSON array of YARA rule names
  iocs: Record<string, any>; // JSON IOC data
  analysis_results: Record<string, any>; // JSON analysis data
  tags: string[]; // JSON array of tags
  created_at: Date;
  updated_at: Date;
}

/**
 * IOC (Indicator of Compromise) Interface
 */
export interface IOC {
  id: string;
  malware_sample_id?: string;
  scan_job_id?: string;
  ioc_type: IOCType;
  ioc_value: string;
  confidence?: number; // 0.00-1.00
  context?: string;
  tags: string[]; // JSON array of tags
  first_seen: Date;
  last_seen: Date;
  created_at: Date;
}

/**
 * YARA Rule Interface
 */
export interface YARARule {
  id: string;
  rule_name: string;
  rule_content: string;
  description?: string;
  author?: string;
  malware_family?: string;
  severity?: Severity;
  tags: string[]; // JSON array of tags
  enabled: boolean;
  false_positive_rate: number; // 0.00-1.00
  detection_count: number;
  created_at: Date;
  updated_at: Date;
}

/**
 * Exploit Interface
 */
export interface Exploit {
  id: string;
  name: string;
  cve_id?: string;
  description?: string;
  target_platform?: string;
  target_version?: string;
  exploit_type?: ExploitType;
  reliability?: ExploitReliability;
  code: string;
  language?: string;
  requirements: string[]; // JSON array of requirements
  references: string[]; // JSON array of reference URLs
  author?: string;
  tags: string[]; // JSON array of tags
  success_count: number;
  failure_count: number;
  last_tested?: Date;
  created_at: Date;
  updated_at: Date;
}

/**
 * Agent Session Interface
 */
export interface AgentSession {
  id: string;
  job_id: string;
  orchestration_type?: OrchestrationType;
  task_description: string;
  max_agents?: number;
  agents_spawned: number;
  status: AgentSessionStatus;
  agents_data: any[]; // JSON array of agent data
  synthesis_result?: Record<string, any>; // JSON synthesis result
  created_at: Date;
  completed_at?: Date;
}

/**
 * Workflow Execution Interface
 */
export interface WorkflowExecution {
  id: string;
  workflow_name: string;
  workflow_version?: string;
  job_id?: string;
  status: WorkflowStatus;
  current_phase?: string;
  phases_data: any[]; // JSON array of phase data
  inputs: Record<string, any>; // JSON inputs
  outputs: Record<string, any>; // JSON outputs
  error?: string;
  created_at: Date;
  started_at?: Date;
  completed_at?: Date;
}

/**
 * Target Authorization Interface
 */
export interface TargetAuthorization {
  id: string;
  org_id: string;
  target: string;
  authorization_method?: AuthorizationMethod;
  authorization_token?: string;
  verified: boolean;
  verified_at?: Date;
  expires_at?: Date;
  notes?: string;
  created_by: string;
  created_at: Date;
}

/**
 * Database Query Options
 */
export interface QueryOptions {
  limit?: number;
  offset?: number;
  orderBy?: string;
  orderDirection?: 'ASC' | 'DESC';
}

/**
 * Pagination Metadata
 */
export interface PaginationMetadata {
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
}

/**
 * Paginated Response
 */
export interface PaginatedResponse<T> {
  data: T[];
  pagination: PaginationMetadata;
}
