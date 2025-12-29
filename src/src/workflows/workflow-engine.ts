/**
 * Workflow Execution Engine
 *
 * Executes workflows step-by-step with dependency management, conditions, retries, and approvals
 */

import { v4 as uuidv4 } from 'uuid';
import { Logger, createContextLogger } from '../utils/logger';
import { EventEmitter } from 'events';
import {
  WorkflowDefinition,
  WorkflowStep,
  WorkflowExecution,
  WorkflowStepExecution,
  WorkflowExecutionRequest,
  WorkflowExecutionStatus,
  WorkflowScanStepConfig,
  WorkflowConditionStepConfig,
  WorkflowParallelStepConfig,
  WorkflowLoopStepConfig,
  WorkflowNexusAnalysisStepConfig
} from '../types/workflow.types';
import { getQueueManager } from '../queue/queue-config';
import { getNexusIntegration } from '../nexus';

/**
 * Workflow execution engine
 */
export class WorkflowEngine extends EventEmitter {
  private logger: Logger;
  private executions: Map<string, WorkflowExecution>;
  private pendingApprovals: Map<string, { step_id: string; resolve: Function; reject: Function }>;

  constructor() {
    super();
    this.logger = createContextLogger('WorkflowEngine');
    this.executions = new Map();
    this.pendingApprovals = new Map();
  }

  /**
   * Execute workflow
   */
  async execute(
    workflow: WorkflowDefinition,
    request: WorkflowExecutionRequest,
    organizationId: string,
    userId: string
  ): Promise<WorkflowExecution> {
    const executionId = uuidv4();

    this.logger.info('Starting workflow execution', {
      execution_id: executionId,
      workflow_name: workflow.name,
      workflow_version: workflow.version
    });

    // Initialize execution record
    const execution: WorkflowExecution = {
      execution_id: executionId,
      workflow_name: workflow.name,
      workflow_version: workflow.version,
      status: 'pending',
      triggered_by: 'manual',
      triggered_at: new Date(),
      steps: workflow.steps.map(step => ({
        step_id: step.id,
        status: 'pending'
      })),
      variables: this.initializeVariables(workflow, request.variables || {}),
      organization_id: organizationId,
      created_by: userId
    };

    this.executions.set(executionId, execution);

    // Emit execution started event
    this.emit('execution:started', execution);

    // Execute in background
    this.executeWorkflow(workflow, execution).catch(error => {
      this.logger.error('Workflow execution failed', {
        execution_id: executionId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      execution.status = 'failed';
      execution.error = error instanceof Error ? error.message : 'Unknown error';
      execution.completed_at = new Date();
      this.emit('execution:failed', execution);
    });

    return execution;
  }

  /**
   * Get execution status
   */
  getExecution(executionId: string): WorkflowExecution | undefined {
    return this.executions.get(executionId);
  }

  /**
   * Approve pending step
   */
  async approveStep(executionId: string, stepId: string, approved: boolean): Promise<void> {
    const key = `${executionId}:${stepId}`;
    const pending = this.pendingApprovals.get(key);

    if (!pending) {
      throw new Error(`No pending approval found for execution ${executionId}, step ${stepId}`);
    }

    this.pendingApprovals.delete(key);

    if (approved) {
      pending.resolve();
    } else {
      pending.reject(new Error('Step approval rejected'));
    }
  }

  /**
   * Cancel workflow execution
   */
  async cancel(executionId: string): Promise<void> {
    const execution = this.executions.get(executionId);
    if (!execution) {
      throw new Error(`Execution not found: ${executionId}`);
    }

    execution.status = 'cancelled';
    execution.completed_at = new Date();

    this.emit('execution:cancelled', execution);

    this.logger.info('Workflow execution cancelled', { execution_id: executionId });
  }

  /**
   * Execute workflow steps
   */
  private async executeWorkflow(workflow: WorkflowDefinition, execution: WorkflowExecution): Promise<void> {
    execution.status = 'running';
    execution.started_at = new Date();

    try {
      // Build dependency graph
      const dependencyGraph = this.buildDependencyGraph(workflow.steps);

      // Execute steps in topological order
      await this.executeStepsInOrder(workflow.steps, dependencyGraph, execution);

      execution.status = 'completed';
      execution.completed_at = new Date();
      execution.duration_seconds = Math.floor(
        (execution.completed_at.getTime() - execution.started_at!.getTime()) / 1000
      );

      this.emit('execution:completed', execution);

      this.logger.info('Workflow execution completed', {
        execution_id: execution.execution_id,
        duration_seconds: execution.duration_seconds
      });
    } catch (error) {
      execution.status = 'failed';
      execution.error = error instanceof Error ? error.message : 'Unknown error';
      execution.completed_at = new Date();

      this.emit('execution:failed', execution);

      throw error;
    }
  }

  /**
   * Execute steps in dependency order
   */
  private async executeStepsInOrder(
    steps: WorkflowStep[],
    dependencyGraph: Map<string, string[]>,
    execution: WorkflowExecution
  ): Promise<void> {
    const executed = new Set<string>();
    const stepMap = new Map(steps.map(s => [s.id, s]));

    while (executed.size < steps.length) {
      // Find steps ready to execute (all dependencies met)
      const readySteps = steps.filter(step => {
        if (executed.has(step.id)) return false;

        const dependencies = dependencyGraph.get(step.id) || [];
        return dependencies.every(depId => executed.has(depId));
      });

      if (readySteps.length === 0) {
        throw new Error('Circular dependency or unresolvable dependencies detected');
      }

      // Execute ready steps
      for (const step of readySteps) {
        await this.executeStep(step, execution, stepMap);
        executed.add(step.id);
      }
    }
  }

  /**
   * Execute single workflow step
   */
  private async executeStep(
    step: WorkflowStep,
    execution: WorkflowExecution,
    stepMap: Map<string, WorkflowStep>
  ): Promise<void> {
    const stepExecution = execution.steps.find(s => s.step_id === step.id)!;

    this.logger.info('Executing workflow step', {
      execution_id: execution.execution_id,
      step_id: step.id,
      step_name: step.name,
      step_type: step.type
    });

    stepExecution.status = 'running';
    stepExecution.started_at = new Date();

    this.emit('step:started', { execution, step });

    try {
      // Check conditions
      if (step.conditions && step.conditions.length > 0) {
        const conditionsMet = this.evaluateConditions(step.conditions, execution);
        if (!conditionsMet) {
          this.logger.info('Step conditions not met, skipping', {
            execution_id: execution.execution_id,
            step_id: step.id
          });
          stepExecution.status = 'skipped';
          stepExecution.completed_at = new Date();
          return;
        }
      }

      // Execute step with retry logic
      let attempt = 0;
      const maxAttempts = step.retry?.max_attempts || 1;

      while (attempt < maxAttempts) {
        try {
          attempt++;
          stepExecution.retry_count = attempt - 1;

          // Execute step based on type
          const result = await this.executeStepByType(step, execution, stepMap);
          stepExecution.output = result;

          stepExecution.status = 'completed';
          stepExecution.completed_at = new Date();
          stepExecution.duration_seconds = Math.floor(
            (stepExecution.completed_at.getTime() - stepExecution.started_at!.getTime()) / 1000
          );

          this.emit('step:completed', { execution, step, result });

          this.logger.info('Step completed successfully', {
            execution_id: execution.execution_id,
            step_id: step.id,
            duration_seconds: stepExecution.duration_seconds
          });

          return;
        } catch (error) {
          this.logger.error('Step execution attempt failed', {
            execution_id: execution.execution_id,
            step_id: step.id,
            attempt,
            max_attempts: maxAttempts,
            error: error instanceof Error ? error.message : 'Unknown error'
          });

          if (attempt >= maxAttempts) {
            throw error;
          }

          // Wait before retry
          if (step.retry) {
            const delay = step.retry.exponential_backoff
              ? step.retry.delay_seconds * Math.pow(2, attempt - 1)
              : step.retry.delay_seconds;
            await this.sleep(delay * 1000);
          }
        }
      }
    } catch (error) {
      stepExecution.status = 'failed';
      stepExecution.error = error instanceof Error ? error.message : 'Unknown error';
      stepExecution.completed_at = new Date();

      this.emit('step:failed', { execution, step, error });

      // Handle failure based on on_failure strategy
      if (step.on_failure === 'stop') {
        throw error;
      } else if (step.on_failure === 'continue') {
        this.logger.warn('Step failed but continuing workflow', {
          execution_id: execution.execution_id,
          step_id: step.id
        });
      }
    }
  }

  /**
   * Execute step by type
   */
  private async executeStepByType(
    step: WorkflowStep,
    execution: WorkflowExecution,
    stepMap: Map<string, WorkflowStep>
  ): Promise<any> {
    // Interpolate variables in config
    const config = this.interpolateVariables(step.config, execution.variables);

    switch (step.type) {
      case 'scan':
        return await this.executeScanStep(config as WorkflowScanStepConfig, execution);

      case 'condition':
        return await this.executeConditionStep(config as WorkflowConditionStepConfig, execution, stepMap);

      case 'parallel':
        return await this.executeParallelStep(config as WorkflowParallelStepConfig, execution, stepMap);

      case 'loop':
        return await this.executeLoopStep(config as WorkflowLoopStepConfig, execution, stepMap);

      case 'approval':
        return await this.executeApprovalStep(config, execution, step.id);

      case 'notification':
        return await this.executeNotificationStep(config, execution);

      case 'nexus_analysis':
        return await this.executeNexusAnalysisStep(config as WorkflowNexusAnalysisStepConfig, execution);

      case 'report':
        return await this.executeReportStep(config, execution);

      case 'export':
        return await this.executeExportStep(config, execution);

      case 'transform':
        return await this.executeTransformStep(config, execution);

      default:
        throw new Error(`Unknown step type: ${step.type}`);
    }
  }

  /**
   * Execute scan step
   */
  private async executeScanStep(config: WorkflowScanStepConfig, execution: WorkflowExecution): Promise<any> {
    const queueManager = getQueueManager();

    // Map workflow scan types to queue ScanType
    // WorkflowScanStepConfig: 'pentest' | 'malware' | 'vuln_scan' | 'network_recon'
    // ScanType: 'pentest' | 'malware' | 'exploit' | 'c2' | 'apt_simulation'
    const scanTypeMap: Record<WorkflowScanStepConfig['scan_type'], 'pentest' | 'malware' | 'exploit' | 'c2' | 'apt_simulation'> = {
      'pentest': 'pentest',
      'malware': 'malware',
      'vuln_scan': 'pentest', // vuln_scan maps to pentest type
      'network_recon': 'pentest' // network_recon maps to pentest type
    };

    const queueScanType = scanTypeMap[config.scan_type];

    // Generate a unique job ID for this scan
    const jobId = uuidv4();

    // Submit scan job with complete JobData
    const job = await queueManager.addJob(queueScanType, {
      job_id: jobId,
      org_id: execution.organization_id,
      user_id: execution.created_by,
      scan_type: queueScanType,
      target: config.target,
      tools: config.tools,
      config: config.config || {},
      sandbox_tier: config.sandbox_tier,
      priority: 5 // Default workflow job priority
    });

    this.logger.info('Scan job submitted', {
      execution_id: execution.execution_id,
      job_id: jobId,
      bullmq_job_id: job.id,
      scan_type: config.scan_type,
      queue_scan_type: queueScanType
    });

    // Wait for job completion (poll or subscribe to events)
    // For simplicity, return job ID
    return { job_id: jobId, scan_type: config.scan_type };
  }

  /**
   * Execute condition step
   */
  private async executeConditionStep(
    config: WorkflowConditionStepConfig,
    execution: WorkflowExecution,
    stepMap: Map<string, WorkflowStep>
  ): Promise<any> {
    const conditionsMet = this.evaluateConditions(config.conditions, execution);

    if (conditionsMet && config.on_true) {
      const targetStep = stepMap.get(config.on_true);
      if (targetStep) {
        return { branch_taken: 'true', target_step: config.on_true };
      }
    } else if (!conditionsMet && config.on_false) {
      const targetStep = stepMap.get(config.on_false);
      if (targetStep) {
        return { branch_taken: 'false', target_step: config.on_false };
      }
    }

    return { branch_taken: conditionsMet ? 'true' : 'false', target_step: null };
  }

  /**
   * Execute parallel step
   */
  private async executeParallelStep(
    config: WorkflowParallelStepConfig,
    execution: WorkflowExecution,
    stepMap: Map<string, WorkflowStep>
  ): Promise<any> {
    const steps = config.steps.map(stepId => stepMap.get(stepId)!).filter(Boolean);

    const results = await Promise.all(
      steps.map(step => this.executeStep(step, execution, stepMap))
    );

    return { parallel_results: results };
  }

  /**
   * Execute loop step
   */
  private async executeLoopStep(
    config: WorkflowLoopStepConfig,
    execution: WorkflowExecution,
    stepMap: Map<string, WorkflowStep>
  ): Promise<any> {
    const items = Array.isArray(config.items) ? config.items : execution.variables[config.items] || [];
    const targetStep = stepMap.get(config.step);

    if (!targetStep) {
      throw new Error(`Loop target step not found: ${config.step}`);
    }

    const results = [];
    const maxIterations = config.max_iterations || items.length;

    for (let i = 0; i < Math.min(items.length, maxIterations); i++) {
      // Set loop variable
      execution.variables[config.item_variable] = items[i];

      try {
        await this.executeStep(targetStep, execution, stepMap);
        results.push({ index: i, success: true });
      } catch (error) {
        if (!config.continue_on_error) {
          throw error;
        }
        results.push({ index: i, success: false, error: error instanceof Error ? error.message : 'Unknown error' });
      }
    }

    return { loop_results: results };
  }

  /**
   * Execute approval step
   */
  private async executeApprovalStep(config: any, execution: WorkflowExecution, stepId: string): Promise<any> {
    execution.status = 'waiting_approval';

    return new Promise((resolve, reject) => {
      const key = `${execution.execution_id}:${stepId}`;
      this.pendingApprovals.set(key, { step_id: stepId, resolve, reject });

      this.emit('approval:required', {
        execution_id: execution.execution_id,
        step_id: stepId,
        approvers: config.approvers,
        message: config.message
      });

      // Set timeout if specified
      if (config.timeout_minutes) {
        setTimeout(() => {
          if (this.pendingApprovals.has(key)) {
            this.pendingApprovals.delete(key);
            if (config.auto_approve_after_timeout) {
              resolve({ approved: true, auto_approved: true });
            } else {
              reject(new Error('Approval timeout'));
            }
          }
        }, config.timeout_minutes * 60 * 1000);
      }
    });
  }

  /**
   * Execute notification step
   */
  private async executeNotificationStep(config: any, execution: WorkflowExecution): Promise<any> {
    // Emit notification event (would be handled by notification service)
    this.emit('notification:send', {
      execution_id: execution.execution_id,
      channels: config.channels,
      recipients: config.recipients,
      subject: config.subject,
      message: config.message,
      data: config.data
    });

    return { notification_sent: true };
  }

  /**
   * Execute Nexus analysis step
   */
  private async executeNexusAnalysisStep(
    config: WorkflowNexusAnalysisStepConfig,
    execution: WorkflowExecution
  ): Promise<any> {
    const nexusIntegration = getNexusIntegration();

    // Get input from referenced step
    const inputStep = execution.steps.find(s => s.step_id === config.input_step);
    if (!inputStep || !inputStep.output) {
      throw new Error(`Input step ${config.input_step} has no output`);
    }

    if (config.analysis_type === 'scan') {
      // Prepare scan data (would need actual scan results)
      const scanData = {
        scan_id: inputStep.output.job_id,
        target: inputStep.output.target || 'unknown',
        scan_type: inputStep.output.scan_type || 'pentest',
        vulnerabilities: [],
        duration_seconds: 0
      };

      return await nexusIntegration.analyzeCompleteScan(scanData);
    } else if (config.analysis_type === 'malware') {
      const malwareData = {
        analysis_id: inputStep.output.analysis_id || inputStep.output.job_id,
        sha256: inputStep.output.sha256 || 'unknown',
        threat_level: 'medium',
        iocs: inputStep.output.iocs || { iocs: {} },
        static_analysis: [],
        behavioral_analysis: {},
        yara_matches: []
      };

      return await nexusIntegration.analyzeCompleteMalware(malwareData);
    }

    throw new Error(`Unknown analysis type: ${config.analysis_type}`);
  }

  /**
   * Execute report step
   */
  private async executeReportStep(config: any, execution: WorkflowExecution): Promise<any> {
    // Gather results from included steps
    const includedSteps = execution.steps.filter(s => config.include_steps.includes(s.step_id));

    return {
      report_generated: true,
      report_type: config.report_type,
      format: config.format,
      steps_included: includedSteps.length
    };
  }

  /**
   * Execute export step
   */
  private async executeExportStep(config: any, execution: WorkflowExecution): Promise<any> {
    return {
      exported: true,
      format: config.format,
      destination: config.destination
    };
  }

  /**
   * Execute transform step
   */
  private async executeTransformStep(config: any, execution: WorkflowExecution): Promise<any> {
    // Apply transformation logic
    return { transformed: true };
  }

  /**
   * Build dependency graph
   */
  private buildDependencyGraph(steps: WorkflowStep[]): Map<string, string[]> {
    const graph = new Map<string, string[]>();

    for (const step of steps) {
      graph.set(step.id, step.depends_on || []);
    }

    return graph;
  }

  /**
   * Evaluate conditions
   */
  private evaluateConditions(conditions: any[], execution: WorkflowExecution): boolean {
    // Simple condition evaluation (would be more sophisticated in production)
    return conditions.every(condition => {
      const value = execution.variables[condition.field];
      switch (condition.operator) {
        case 'eq':
          return value === condition.value;
        case 'ne':
          return value !== condition.value;
        case 'gt':
          return value > condition.value;
        case 'gte':
          return value >= condition.value;
        case 'lt':
          return value < condition.value;
        case 'lte':
          return value <= condition.value;
        case 'contains':
          return String(value).includes(condition.value);
        default:
          return false;
      }
    });
  }

  /**
   * Initialize workflow variables
   */
  private initializeVariables(workflow: WorkflowDefinition, overrides: Record<string, any>): Record<string, any> {
    const variables: Record<string, any> = {};

    // Set default values from workflow definition
    for (const variable of workflow.variables || []) {
      variables[variable.name] = variable.value;
    }

    // Apply overrides
    for (const [key, value] of Object.entries(overrides)) {
      variables[key] = value;
    }

    return variables;
  }

  /**
   * Interpolate variables in configuration
   */
  private interpolateVariables(config: any, variables: Record<string, any>): any {
    const configStr = JSON.stringify(config);
    const interpolated = configStr.replace(/\$\{variables\.(\w+)\}/g, (match, varName) => {
      return variables[varName] !== undefined ? JSON.stringify(variables[varName]) : match;
    });
    return JSON.parse(interpolated);
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Singleton instance
 */
let workflowEngine: WorkflowEngine | null = null;

/**
 * Get workflow engine instance
 */
export function getWorkflowEngine(): WorkflowEngine {
  if (!workflowEngine) {
    workflowEngine = new WorkflowEngine();
  }
  return workflowEngine;
}
