/**
 * Workflow Parser
 *
 * Parses and validates YAML workflow definitions
 */

import * as yaml from 'yaml';
import * as fs from 'fs/promises';
import * as path from 'path';
import { Logger, createContextLogger } from '../utils/logger';
import {
  WorkflowDefinition,
  WorkflowStep,
  WorkflowValidationResult,
  WorkflowCondition
} from '../types/workflow.types';

/**
 * Workflow Parser
 */
export class WorkflowParser {
  private logger: Logger;

  constructor() {
    this.logger = createContextLogger('WorkflowParser');
  }

  /**
   * Parse workflow from YAML file
   */
  async parseFromFile(filePath: string): Promise<WorkflowDefinition> {
    try {
      this.logger.info('Parsing workflow file', { file_path: filePath });

      const fileContent = await fs.readFile(filePath, 'utf-8');
      const workflow = this.parseFromString(fileContent);

      this.logger.info('Workflow file parsed successfully', {
        workflow_name: workflow.name,
        steps_count: workflow.steps.length
      });

      return workflow;
    } catch (error) {
      this.logger.error('Failed to parse workflow file', {
        file_path: filePath,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error(`Failed to parse workflow file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Parse workflow from YAML string
   */
  parseFromString(yamlContent: string): WorkflowDefinition {
    try {
      const parsed = yaml.parse(yamlContent);

      if (!parsed) {
        throw new Error('Empty workflow definition');
      }

      // Validate required fields
      this.validateRequiredFields(parsed);

      // Parse workflow definition
      const workflow: WorkflowDefinition = {
        name: parsed.name,
        version: parsed.version,
        description: parsed.description,
        author: parsed.author,
        tags: parsed.tags || [],
        variables: parsed.variables || [],
        triggers: parsed.triggers || [],
        steps: this.parseSteps(parsed.steps || []),
        notifications: parsed.notifications,
        metadata: parsed.metadata || {}
      };

      return workflow;
    } catch (error) {
      this.logger.error('Failed to parse workflow YAML', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Validate workflow definition
   */
  validate(workflow: WorkflowDefinition): WorkflowValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate basic structure
    if (!workflow.name) {
      errors.push('Workflow name is required');
    }

    if (!workflow.version) {
      errors.push('Workflow version is required');
    }

    if (!workflow.description) {
      warnings.push('Workflow description is missing');
    }

    if (!workflow.steps || workflow.steps.length === 0) {
      errors.push('Workflow must have at least one step');
    }

    // Validate steps
    const stepIds = new Set<string>();
    for (const step of workflow.steps) {
      // Check for duplicate step IDs
      if (stepIds.has(step.id)) {
        errors.push(`Duplicate step ID: ${step.id}`);
      }
      stepIds.add(step.id);

      // Validate step structure
      if (!step.name) {
        errors.push(`Step ${step.id}: name is required`);
      }

      if (!step.type) {
        errors.push(`Step ${step.id}: type is required`);
      }

      if (!step.config) {
        errors.push(`Step ${step.id}: config is required`);
      }

      // Validate step-specific configuration
      this.validateStepConfig(step, errors, warnings);
    }

    // Validate dependencies
    const dependenciesValid = this.validateDependencies(workflow.steps, stepIds, errors);

    // Validate variable references
    this.validateVariableReferences(workflow, errors, warnings);

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      steps_validated: workflow.steps.length,
      dependencies_valid: dependenciesValid
    };
  }

  /**
   * Load workflow from built-in templates directory
   */
  async loadBuiltInWorkflow(templateName: string): Promise<WorkflowDefinition> {
    try {
      const templatePath = path.join(__dirname, '../../workflows/templates', `${templateName}.yaml`);
      return await this.parseFromFile(templatePath);
    } catch (error) {
      this.logger.error('Failed to load built-in workflow', {
        template_name: templateName,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error(`Built-in workflow not found: ${templateName}`);
    }
  }

  /**
   * List available built-in workflows
   */
  async listBuiltInWorkflows(): Promise<string[]> {
    try {
      const templatesDir = path.join(__dirname, '../../workflows/templates');
      const files = await fs.readdir(templatesDir);
      return files
        .filter(f => f.endsWith('.yaml') || f.endsWith('.yml'))
        .map(f => f.replace(/\.(yaml|yml)$/, ''));
    } catch (error) {
      this.logger.error('Failed to list built-in workflows', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Validate required fields
   */
  private validateRequiredFields(parsed: any): void {
    const requiredFields = ['name', 'version', 'description', 'steps'];
    for (const field of requiredFields) {
      if (!parsed[field]) {
        throw new Error(`Required field missing: ${field}`);
      }
    }
  }

  /**
   * Parse workflow steps
   */
  private parseSteps(stepsData: any[]): WorkflowStep[] {
    return stepsData.map((stepData, index) => {
      if (!stepData.id) {
        stepData.id = `step_${index + 1}`;
      }

      return {
        id: stepData.id,
        name: stepData.name,
        type: stepData.type,
        description: stepData.description,
        config: stepData.config || {},
        depends_on: stepData.depends_on || [],
        timeout_seconds: stepData.timeout_seconds,
        retry: stepData.retry,
        on_failure: stepData.on_failure || 'stop',
        conditions: stepData.conditions || []
      };
    });
  }

  /**
   * Validate step configuration
   */
  private validateStepConfig(step: WorkflowStep, errors: string[], warnings: string[]): void {
    switch (step.type) {
      case 'scan':
        if (!step.config.scan_type) {
          errors.push(`Step ${step.id}: scan_type is required for scan steps`);
        }
        if (!step.config.target) {
          errors.push(`Step ${step.id}: target is required for scan steps`);
        }
        if (!step.config.tools || step.config.tools.length === 0) {
          warnings.push(`Step ${step.id}: no tools specified for scan`);
        }
        break;

      case 'condition':
        if (!step.config.conditions || step.config.conditions.length === 0) {
          errors.push(`Step ${step.id}: conditions are required for condition steps`);
        }
        if (!step.config.on_true) {
          errors.push(`Step ${step.id}: on_true is required for condition steps`);
        }
        break;

      case 'parallel':
        if (!step.config.steps || step.config.steps.length === 0) {
          errors.push(`Step ${step.id}: steps are required for parallel execution`);
        }
        break;

      case 'loop':
        if (!step.config.items) {
          errors.push(`Step ${step.id}: items are required for loop steps`);
        }
        if (!step.config.step) {
          errors.push(`Step ${step.id}: step is required for loop steps`);
        }
        if (!step.config.item_variable) {
          errors.push(`Step ${step.id}: item_variable is required for loop steps`);
        }
        break;

      case 'approval':
        if (!step.config.approvers || step.config.approvers.length === 0) {
          errors.push(`Step ${step.id}: approvers are required for approval steps`);
        }
        if (!step.config.message) {
          errors.push(`Step ${step.id}: message is required for approval steps`);
        }
        break;

      case 'notification':
        if (!step.config.channels || step.config.channels.length === 0) {
          errors.push(`Step ${step.id}: channels are required for notification steps`);
        }
        if (!step.config.recipients || step.config.recipients.length === 0) {
          errors.push(`Step ${step.id}: recipients are required for notification steps`);
        }
        if (!step.config.message) {
          errors.push(`Step ${step.id}: message is required for notification steps`);
        }
        break;

      case 'nexus_analysis':
        if (!step.config.analysis_type) {
          errors.push(`Step ${step.id}: analysis_type is required for nexus_analysis steps`);
        }
        if (!step.config.input_step) {
          errors.push(`Step ${step.id}: input_step is required for nexus_analysis steps`);
        }
        break;

      case 'report':
        if (!step.config.report_type) {
          errors.push(`Step ${step.id}: report_type is required for report steps`);
        }
        if (!step.config.format) {
          errors.push(`Step ${step.id}: format is required for report steps`);
        }
        if (!step.config.include_steps || step.config.include_steps.length === 0) {
          warnings.push(`Step ${step.id}: no steps included in report`);
        }
        break;

      case 'export':
        if (!step.config.format) {
          errors.push(`Step ${step.id}: format is required for export steps`);
        }
        if (!step.config.destination) {
          errors.push(`Step ${step.id}: destination is required for export steps`);
        }
        break;
    }
  }

  /**
   * Validate step dependencies
   */
  private validateDependencies(
    steps: WorkflowStep[],
    stepIds: Set<string>,
    errors: string[]
  ): boolean {
    let valid = true;

    for (const step of steps) {
      if (step.depends_on && step.depends_on.length > 0) {
        for (const depId of step.depends_on) {
          if (!stepIds.has(depId)) {
            errors.push(`Step ${step.id}: depends on non-existent step ${depId}`);
            valid = false;
          }

          // Check for circular dependencies
          if (this.hasCircularDependency(step.id, depId, steps)) {
            errors.push(`Step ${step.id}: circular dependency detected with ${depId}`);
            valid = false;
          }
        }
      }

      // Validate step references in configs
      if (step.type === 'condition' && step.config.on_true) {
        if (!stepIds.has(step.config.on_true)) {
          errors.push(`Step ${step.id}: on_true references non-existent step ${step.config.on_true}`);
          valid = false;
        }
      }

      if (step.type === 'condition' && step.config.on_false) {
        if (!stepIds.has(step.config.on_false)) {
          errors.push(`Step ${step.id}: on_false references non-existent step ${step.config.on_false}`);
          valid = false;
        }
      }

      if (step.type === 'nexus_analysis' && step.config.input_step) {
        if (!stepIds.has(step.config.input_step)) {
          errors.push(`Step ${step.id}: input_step references non-existent step ${step.config.input_step}`);
          valid = false;
        }
      }
    }

    return valid;
  }

  /**
   * Check for circular dependencies
   */
  private hasCircularDependency(
    startStepId: string,
    checkStepId: string,
    steps: WorkflowStep[],
    visited: Set<string> = new Set()
  ): boolean {
    if (visited.has(checkStepId)) {
      return checkStepId === startStepId;
    }

    visited.add(checkStepId);

    const step = steps.find(s => s.id === checkStepId);
    if (!step || !step.depends_on) {
      return false;
    }

    for (const depId of step.depends_on) {
      if (this.hasCircularDependency(startStepId, depId, steps, new Set(visited))) {
        return true;
      }
    }

    return false;
  }

  /**
   * Validate variable references
   */
  private validateVariableReferences(
    workflow: WorkflowDefinition,
    errors: string[],
    warnings: string[]
  ): void {
    const definedVariables = new Set((workflow.variables || []).map(v => v.name));
    const variablePattern = /\$\{variables\.(\w+)\}/g;

    // Check variable references in steps
    for (const step of workflow.steps) {
      const configStr = JSON.stringify(step.config);
      let match;

      while ((match = variablePattern.exec(configStr)) !== null) {
        const varName = match[1];
        if (!definedVariables.has(varName)) {
          warnings.push(`Step ${step.id}: references undefined variable ${varName}`);
        }
      }
    }
  }
}

/**
 * Singleton instance
 */
let workflowParser: WorkflowParser | null = null;

/**
 * Get workflow parser instance
 */
export function getWorkflowParser(): WorkflowParser {
  if (!workflowParser) {
    workflowParser = new WorkflowParser();
  }
  return workflowParser;
}
