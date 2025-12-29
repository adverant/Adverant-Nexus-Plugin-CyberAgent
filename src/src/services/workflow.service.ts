/**
 * Workflow Service
 *
 * Business logic for workflow management and execution
 */

import { Logger, createContextLogger } from '../utils/logger';
import { getWorkflowParser } from '../workflows/workflow-parser';
import { getWorkflowEngine } from '../workflows/workflow-engine';
import {
  WorkflowDefinition,
  WorkflowExecution,
  WorkflowExecutionRequest,
  WorkflowValidationResult,
  BuiltInWorkflowTemplate
} from '../types/workflow.types';
import { NotFoundError, ValidationError } from '../errors/custom-errors';

/**
 * Workflow Service
 */
export class WorkflowService {
  private logger: Logger;
  private parser: ReturnType<typeof getWorkflowParser>;
  private engine: ReturnType<typeof getWorkflowEngine>;

  constructor() {
    this.logger = createContextLogger('WorkflowService');
    this.parser = getWorkflowParser();
    this.engine = getWorkflowEngine();
  }

  /**
   * Parse workflow from YAML
   */
  async parseWorkflow(yamlContent: string): Promise<WorkflowDefinition> {
    try {
      const workflow = this.parser.parseFromString(yamlContent);

      this.logger.info('Workflow parsed successfully', {
        workflow_name: workflow.name,
        version: workflow.version
      });

      return workflow;
    } catch (error) {
      this.logger.error('Failed to parse workflow', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ValidationError('Failed to parse workflow YAML');
    }
  }

  /**
   * Validate workflow
   */
  validateWorkflow(workflow: WorkflowDefinition): WorkflowValidationResult {
    const validation = this.parser.validate(workflow);

    this.logger.info('Workflow validation complete', {
      workflow_name: workflow.name,
      valid: validation.valid,
      errors_count: validation.errors.length,
      warnings_count: validation.warnings.length
    });

    return validation;
  }

  /**
   * Execute workflow
   */
  async executeWorkflow(
    workflow: WorkflowDefinition,
    request: WorkflowExecutionRequest,
    organizationId: string,
    userId: string
  ): Promise<WorkflowExecution> {
    // Validate workflow first
    const validation = this.validateWorkflow(workflow);
    if (!validation.valid) {
      throw new ValidationError(`Workflow validation failed: ${validation.errors.join(', ')}`);
    }

    try {
      const execution = await this.engine.execute(workflow, request, organizationId, userId);

      this.logger.info('Workflow execution started', {
        execution_id: execution.execution_id,
        workflow_name: workflow.name,
        organization_id: organizationId,
        user_id: userId
      });

      return execution;
    } catch (error) {
      this.logger.error('Failed to execute workflow', {
        workflow_name: workflow.name,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get workflow execution status
   */
  getExecutionStatus(executionId: string): WorkflowExecution {
    const execution = this.engine.getExecution(executionId);

    if (!execution) {
      throw new NotFoundError(`Workflow execution not found: ${executionId}`);
    }

    return execution;
  }

  /**
   * Cancel workflow execution
   */
  async cancelExecution(executionId: string): Promise<void> {
    try {
      await this.engine.cancel(executionId);

      this.logger.info('Workflow execution cancelled', { execution_id: executionId });
    } catch (error) {
      this.logger.error('Failed to cancel workflow execution', {
        execution_id: executionId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Approve workflow step
   */
  async approveStep(executionId: string, stepId: string, approved: boolean): Promise<void> {
    try {
      await this.engine.approveStep(executionId, stepId, approved);

      this.logger.info('Workflow step approval processed', {
        execution_id: executionId,
        step_id: stepId,
        approved
      });
    } catch (error) {
      this.logger.error('Failed to process step approval', {
        execution_id: executionId,
        step_id: stepId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Load built-in workflow template
   */
  async loadBuiltInWorkflow(templateName: BuiltInWorkflowTemplate): Promise<WorkflowDefinition> {
    try {
      const workflow = await this.parser.loadBuiltInWorkflow(templateName);

      this.logger.info('Built-in workflow loaded', {
        template_name: templateName,
        workflow_name: workflow.name
      });

      return workflow;
    } catch (error) {
      this.logger.error('Failed to load built-in workflow', {
        template_name: templateName,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new NotFoundError(`Built-in workflow template not found: ${templateName}`);
    }
  }

  /**
   * List available built-in workflows
   */
  async listBuiltInWorkflows(): Promise<string[]> {
    try {
      const workflows = await this.parser.listBuiltInWorkflows();

      this.logger.info('Listed built-in workflows', { count: workflows.length });

      return workflows;
    } catch (error) {
      this.logger.error('Failed to list built-in workflows', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Execute built-in workflow
   */
  async executeBuiltInWorkflow(
    templateName: BuiltInWorkflowTemplate,
    request: WorkflowExecutionRequest,
    organizationId: string,
    userId: string
  ): Promise<WorkflowExecution> {
    const workflow = await this.loadBuiltInWorkflow(templateName);
    return await this.executeWorkflow(workflow, request, organizationId, userId);
  }
}

/**
 * Singleton instance
 */
let workflowService: WorkflowService | null = null;

/**
 * Get workflow service instance
 */
export function getWorkflowService(): WorkflowService {
  if (!workflowService) {
    workflowService = new WorkflowService();
  }
  return workflowService;
}
