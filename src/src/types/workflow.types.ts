/**
 * Workflow Type Definitions
 *
 * Defines types for YAML-based security workflow automation
 */

/**
 * Workflow step types
 */
export type WorkflowStepType =
  | 'scan' // Execute a security scan
  | 'condition' // Conditional branching
  | 'parallel' // Execute steps in parallel
  | 'loop' // Loop over items
  | 'approval' // Wait for human approval
  | 'notification' // Send notification
  | 'transform' // Transform data
  | 'nexus_analysis' // Trigger Nexus analysis
  | 'report' // Generate report
  | 'export'; // Export results

/**
 * Workflow step configuration
 */
export interface WorkflowStep {
  id: string;
  name: string;
  type: WorkflowStepType;
  description?: string;
  config: Record<string, any>;
  depends_on?: string[]; // Step IDs this step depends on
  timeout_seconds?: number;
  retry?: {
    max_attempts: number;
    delay_seconds: number;
    exponential_backoff?: boolean;
  };
  on_failure?: 'stop' | 'continue' | 'retry';
  conditions?: WorkflowCondition[];
}

/**
 * Workflow condition
 */
export interface WorkflowCondition {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'matches' | 'in';
  value: any;
  combine?: 'and' | 'or';
}

/**
 * Workflow variable
 */
export interface WorkflowVariable {
  name: string;
  value: any;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description?: string;
}

/**
 * Workflow trigger configuration
 */
export interface WorkflowTrigger {
  type: 'manual' | 'schedule' | 'event' | 'webhook';
  config?: {
    schedule?: string; // Cron expression
    event?: string; // Event type
    webhook_path?: string;
  };
}

/**
 * Workflow definition (from YAML)
 */
export interface WorkflowDefinition {
  name: string;
  version: string;
  description: string;
  author?: string;
  tags?: string[];
  variables?: WorkflowVariable[];
  triggers?: WorkflowTrigger[];
  steps: WorkflowStep[];
  notifications?: {
    on_success?: string[];
    on_failure?: string[];
    on_completion?: string[];
  };
  metadata?: Record<string, any>;
}

/**
 * Workflow execution status
 */
export type WorkflowExecutionStatus =
  | 'pending'
  | 'running'
  | 'waiting_approval'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled';

/**
 * Workflow step execution
 */
export interface WorkflowStepExecution {
  step_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  started_at?: Date;
  completed_at?: Date;
  duration_seconds?: number;
  output?: any;
  error?: string;
  retry_count?: number;
}

/**
 * Workflow execution record
 */
export interface WorkflowExecution {
  execution_id: string;
  workflow_name: string;
  workflow_version: string;
  status: WorkflowExecutionStatus;
  triggered_by: 'manual' | 'schedule' | 'event' | 'webhook';
  triggered_at: Date;
  started_at?: Date;
  completed_at?: Date;
  duration_seconds?: number;
  steps: WorkflowStepExecution[];
  variables: Record<string, any>;
  results?: any;
  error?: string;
  organization_id: string;
  created_by: string;
}

/**
 * Workflow execution request
 */
export interface WorkflowExecutionRequest {
  workflow_name: string;
  workflow_version?: string; // Defaults to latest
  variables?: Record<string, any>; // Override workflow variables
  dry_run?: boolean; // Validate without executing
}

/**
 * Workflow validation result
 */
export interface WorkflowValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  steps_validated: number;
  dependencies_valid: boolean;
}

/**
 * Built-in workflow templates
 */
export type BuiltInWorkflowTemplate =
  | 'comprehensive_pentest'
  | 'web_app_security_scan'
  | 'malware_analysis_pipeline'
  | 'apt_simulation'
  | 'vulnerability_assessment'
  | 'network_reconnaissance'
  | 'compliance_audit'
  | 'incident_response';

/**
 * Workflow step scan config
 */
export interface WorkflowScanStepConfig {
  scan_type: 'pentest' | 'malware' | 'vuln_scan' | 'network_recon';
  target: string; // Can use ${variables.target}
  tools: string[];
  sandbox_tier?: 'tier1' | 'tier2' | 'tier3';
  config?: Record<string, any>;
  store_results?: boolean;
}

/**
 * Workflow step condition config
 */
export interface WorkflowConditionStepConfig {
  conditions: WorkflowCondition[];
  on_true: string; // Step ID to execute
  on_false?: string; // Step ID to execute
}

/**
 * Workflow step parallel config
 */
export interface WorkflowParallelStepConfig {
  steps: string[]; // Step IDs to execute in parallel
  wait_for_all?: boolean; // Default true
  max_concurrent?: number;
}

/**
 * Workflow step loop config
 */
export interface WorkflowLoopStepConfig {
  items: any[] | string; // Array or variable reference
  step: string; // Step ID to execute for each item
  item_variable: string; // Variable name for current item
  max_iterations?: number;
  continue_on_error?: boolean;
}

/**
 * Workflow step approval config
 */
export interface WorkflowApprovalStepConfig {
  approvers: string[]; // User IDs or roles
  message: string;
  timeout_minutes?: number;
  auto_approve_after_timeout?: boolean;
}

/**
 * Workflow step notification config
 */
export interface WorkflowNotificationStepConfig {
  channels: ('email' | 'slack' | 'webhook' | 'sms')[];
  recipients: string[];
  subject?: string;
  message: string;
  data?: Record<string, any>;
}

/**
 * Workflow step nexus analysis config
 */
export interface WorkflowNexusAnalysisStepConfig {
  analysis_type: 'scan' | 'malware' | 'threat_hunting' | 'incident_response';
  input_step: string; // Step ID to get input from
  services?: ('graphrag' | 'mageagent' | 'orchestration' | 'learning')[];
  autonomous?: boolean;
}

/**
 * Workflow step report config
 */
export interface WorkflowReportStepConfig {
  report_type: 'executive' | 'technical' | 'compliance' | 'custom';
  format: 'pdf' | 'html' | 'json' | 'markdown';
  include_steps: string[]; // Step IDs to include in report
  template?: string;
}

/**
 * Workflow step export config
 */
export interface WorkflowExportStepConfig {
  format: 'json' | 'csv' | 'xml' | 'siem' | 'misp';
  destination: string; // File path, S3 URL, API endpoint
  include_steps: string[];
  credentials?: string; // Reference to credential store
}

/**
 * Workflow metrics
 */
export interface WorkflowMetrics {
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  avg_duration_seconds: number;
  success_rate: number;
  last_execution?: Date;
}
