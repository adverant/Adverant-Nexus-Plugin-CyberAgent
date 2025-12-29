/**
 * Workflow Engine Unit Tests
 *
 * Tests for workflow execution, dependency resolution, and step execution
 */

import { WorkflowEngine } from '../../../src/workflows/workflow-engine';
import {
  WorkflowDefinition,
  WorkflowExecutionRequest,
  WorkflowStepType,
  WorkflowExecutionStatus
} from '../../../src/types/workflow.types';

describe('WorkflowEngine', () => {
  let engine: WorkflowEngine;

  beforeEach(() => {
    engine = new WorkflowEngine();
  });

  afterEach(() => {
    engine.removeAllListeners();
  });

  describe('Dependency Resolution', () => {
    it('should execute steps in correct order based on dependencies', async () => {
      const workflow: WorkflowDefinition = {
        name: 'test-workflow',
        version: '1.0.0',
        description: 'Test workflow',
        steps: [
          {
            id: 'step3',
            name: 'Third Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Step 3' },
            depends_on: ['step1', 'step2']
          },
          {
            id: 'step1',
            name: 'First Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Step 1' }
          },
          {
            id: 'step2',
            name: 'Second Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Step 2' },
            depends_on: ['step1']
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'test-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      // Verify execution order: step1 -> step2 -> step3
      expect(execution.steps[0].step_id).toBe('step1');
      expect(execution.steps[1].step_id).toBe('step2');
      expect(execution.steps[2].step_id).toBe('step3');
      expect(execution.status).toBe('completed' as WorkflowExecutionStatus);
    });

    it('should detect circular dependencies', async () => {
      const workflow: WorkflowDefinition = {
        name: 'circular-workflow',
        version: '1.0.0',
        description: 'Workflow with circular dependencies',
        steps: [
          {
            id: 'step1',
            name: 'Step 1',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Step 1' },
            depends_on: ['step2']
          },
          {
            id: 'step2',
            name: 'Step 2',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Step 2' },
            depends_on: ['step1']
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'circular-workflow',
        variables: {},
        dry_run: false
      };

      await expect(engine.execute(workflow, request, 'org-123', 'user-123'))
        .rejects
        .toThrow('Circular dependency detected');
    });
  });

  describe('Conditional Execution', () => {
    it('should skip steps when condition is false', async () => {
      const workflow: WorkflowDefinition = {
        name: 'conditional-workflow',
        version: '1.0.0',
        description: 'Workflow with conditions',
        steps: [
          {
            id: 'step1',
            name: 'Always Execute',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Always runs' }
          },
          {
            id: 'step2',
            name: 'Conditional Step',
            type: 'condition' as WorkflowStepType,
            config: {
              expression: 'variables.execute === true'
            },
            depends_on: ['step1']
          },
          {
            id: 'step3',
            name: 'After Condition',
            type: 'notification' as WorkflowStepType,
            config: { message: 'After condition' },
            depends_on: ['step2']
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'conditional-workflow',
        variables: { execute: false },
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      const step2 = execution.steps.find(s => s.step_id === 'step2');
      const step3 = execution.steps.find(s => s.step_id === 'step3');

      expect(step2?.status).toBe('skipped');
      expect(step3?.status).toBe('skipped'); // Should be skipped because step2 was skipped
    });

    it('should execute steps when condition is true', async () => {
      const workflow: WorkflowDefinition = {
        name: 'conditional-workflow-true',
        version: '1.0.0',
        description: 'Workflow with true condition',
        steps: [
          {
            id: 'step1',
            name: 'Setup',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Setup' }
          },
          {
            id: 'step2',
            name: 'Condition',
            type: 'condition' as WorkflowStepType,
            config: {
              expression: 'variables.value > 10'
            },
            depends_on: ['step1']
          },
          {
            id: 'step3',
            name: 'After True Condition',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Executed' },
            depends_on: ['step2']
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'conditional-workflow-true',
        variables: { value: 15 },
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      const step2 = execution.steps.find(s => s.step_id === 'step2');
      const step3 = execution.steps.find(s => s.step_id === 'step3');

      expect(step2?.status).toBe('completed');
      expect(step3?.status).toBe('completed');
    });
  });

  describe('Parallel Execution', () => {
    it('should execute parallel steps concurrently', async () => {
      const workflow: WorkflowDefinition = {
        name: 'parallel-workflow',
        version: '1.0.0',
        description: 'Workflow with parallel execution',
        steps: [
          {
            id: 'parallel1',
            name: 'Parallel Execution',
            type: 'parallel' as WorkflowStepType,
            config: {
              branches: [
                {
                  name: 'branch1',
                  steps: [
                    {
                      id: 'branch1-step1',
                      name: 'Branch 1 Step 1',
                      type: 'notification' as WorkflowStepType,
                      config: { message: 'Branch 1' }
                    }
                  ]
                },
                {
                  name: 'branch2',
                  steps: [
                    {
                      id: 'branch2-step1',
                      name: 'Branch 2 Step 1',
                      type: 'notification' as WorkflowStepType,
                      config: { message: 'Branch 2' }
                    }
                  ]
                }
              ]
            }
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'parallel-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      expect(execution.status).toBe('completed' as WorkflowExecutionStatus);
      const parallelStep = execution.steps.find(s => s.step_id === 'parallel1');
      expect(parallelStep?.status).toBe('completed');
    });
  });

  describe('Retry Logic', () => {
    it('should retry failed steps according to retry config', async () => {
      let attemptCount = 0;

      const workflow: WorkflowDefinition = {
        name: 'retry-workflow',
        version: '1.0.0',
        description: 'Workflow with retry',
        steps: [
          {
            id: 'failing-step',
            name: 'Failing Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Will fail' },
            retry: {
              max_attempts: 3,
              delay_seconds: 0.1,
              exponential_backoff: false
            }
          }
        ]
      };

      // Mock step execution to fail first 2 times, succeed on 3rd
      const originalExecute = engine['executeStep'];
      engine['executeStep'] = jest.fn().mockImplementation(async (step, context) => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error('Temporary failure');
        }
        return { success: true, output: {} };
      });

      const request: WorkflowExecutionRequest = {
        workflow_name: 'retry-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      expect(attemptCount).toBe(3);
      expect(execution.steps[0].status).toBe('completed');
    });

    it('should fail after max retry attempts', async () => {
      const workflow: WorkflowDefinition = {
        name: 'max-retry-workflow',
        version: '1.0.0',
        description: 'Workflow exceeding max retries',
        steps: [
          {
            id: 'always-failing',
            name: 'Always Failing Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Will always fail' },
            retry: {
              max_attempts: 2,
              delay_seconds: 0.1,
              exponential_backoff: false
            }
          }
        ]
      };

      // Mock step execution to always fail
      engine['executeStep'] = jest.fn().mockRejectedValue(new Error('Persistent failure'));

      const request: WorkflowExecutionRequest = {
        workflow_name: 'max-retry-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      expect(execution.status).toBe('failed' as WorkflowExecutionStatus);
      expect(execution.steps[0].status).toBe('failed');
    });
  });

  describe('Approval Workflow', () => {
    it('should pause execution at approval step', async () => {
      const workflow: WorkflowDefinition = {
        name: 'approval-workflow',
        version: '1.0.0',
        description: 'Workflow requiring approval',
        steps: [
          {
            id: 'step1',
            name: 'Pre-approval Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Before approval' }
          },
          {
            id: 'approval1',
            name: 'Approval Required',
            type: 'approval' as WorkflowStepType,
            config: {
              approvers: ['user-admin'],
              timeout_minutes: 60,
              message: 'Please approve this action'
            },
            depends_on: ['step1']
          },
          {
            id: 'step2',
            name: 'Post-approval Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'After approval' },
            depends_on: ['approval1']
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'approval-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      // Execution should be pending approval
      expect(execution.status).toBe('pending_approval' as WorkflowExecutionStatus);

      const approvalStep = execution.steps.find(s => s.step_id === 'approval1');
      expect(approvalStep?.status).toBe('pending_approval');

      // Step after approval should not have executed yet
      const step2 = execution.steps.find(s => s.step_id === 'step2');
      expect(step2).toBeUndefined(); // Not executed yet
    });

    it('should continue execution after approval', async () => {
      const workflow: WorkflowDefinition = {
        name: 'approval-continue-workflow',
        version: '1.0.0',
        description: 'Workflow with approval continuation',
        steps: [
          {
            id: 'approval1',
            name: 'Approval',
            type: 'approval' as WorkflowStepType,
            config: {
              approvers: ['user-admin'],
              timeout_minutes: 60
            }
          },
          {
            id: 'step2',
            name: 'After Approval',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Approved action' },
            depends_on: ['approval1']
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'approval-continue-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      // Approve the step
      await engine.approveStep(execution.execution_id, 'approval1', true);

      // Get updated execution
      const updatedExecution = engine.getExecutionStatus(execution.execution_id);

      expect(updatedExecution.status).toBe('completed' as WorkflowExecutionStatus);
      const step2 = updatedExecution.steps.find(s => s.step_id === 'step2');
      expect(step2?.status).toBe('completed');
    });

    it('should cancel workflow on approval rejection', async () => {
      const workflow: WorkflowDefinition = {
        name: 'approval-reject-workflow',
        version: '1.0.0',
        description: 'Workflow with approval rejection',
        steps: [
          {
            id: 'approval1',
            name: 'Approval',
            type: 'approval' as WorkflowStepType,
            config: {
              approvers: ['user-admin'],
              timeout_minutes: 60
            }
          },
          {
            id: 'step2',
            name: 'Should Not Execute',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Should not run' },
            depends_on: ['approval1']
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'approval-reject-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      // Reject the approval
      await engine.approveStep(execution.execution_id, 'approval1', false);

      const updatedExecution = engine.getExecutionStatus(execution.execution_id);

      expect(updatedExecution.status).toBe('cancelled' as WorkflowExecutionStatus);
      const approvalStep = updatedExecution.steps.find(s => s.step_id === 'approval1');
      expect(approvalStep?.status).toBe('rejected');
    });
  });

  describe('Loop Execution', () => {
    it('should execute loop steps multiple times', async () => {
      const workflow: WorkflowDefinition = {
        name: 'loop-workflow',
        version: '1.0.0',
        description: 'Workflow with loop',
        steps: [
          {
            id: 'loop1',
            name: 'Loop Step',
            type: 'loop' as WorkflowStepType,
            config: {
              items: ['item1', 'item2', 'item3'],
              variable_name: 'current_item',
              steps: [
                {
                  id: 'loop-notification',
                  name: 'Loop Notification',
                  type: 'notification' as WorkflowStepType,
                  config: {
                    message: 'Processing {{ variables.current_item }}'
                  }
                }
              ]
            }
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'loop-workflow',
        variables: {},
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      expect(execution.status).toBe('completed' as WorkflowExecutionStatus);
      const loopStep = execution.steps.find(s => s.step_id === 'loop1');
      expect(loopStep?.status).toBe('completed');

      // Loop should have executed 3 times
      expect(loopStep?.output?.iterations).toBe(3);
    });
  });

  describe('Variable Substitution', () => {
    it('should substitute variables in step configs', async () => {
      const workflow: WorkflowDefinition = {
        name: 'variable-workflow',
        version: '1.0.0',
        description: 'Workflow with variables',
        steps: [
          {
            id: 'step1',
            name: 'Variable Step',
            type: 'notification' as WorkflowStepType,
            config: {
              message: 'Hello {{ variables.name }}, value is {{ variables.value }}'
            }
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'variable-workflow',
        variables: {
          name: 'Test User',
          value: 42
        },
        dry_run: false
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      const step1 = execution.steps.find(s => s.step_id === 'step1');
      expect(step1?.output?.message).toContain('Hello Test User');
      expect(step1?.output?.message).toContain('value is 42');
    });
  });

  describe('Dry Run Mode', () => {
    it('should not execute destructive operations in dry run', async () => {
      const workflow: WorkflowDefinition = {
        name: 'dry-run-workflow',
        version: '1.0.0',
        description: 'Workflow in dry run mode',
        steps: [
          {
            id: 'scan1',
            name: 'Scan Step',
            type: 'scan' as WorkflowStepType,
            config: {
              scan_type: 'port_scan',
              target: '{{ variables.target }}'
            }
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'dry-run-workflow',
        variables: { target: '192.168.1.1' },
        dry_run: true
      };

      const execution = await engine.execute(workflow, request, 'org-123', 'user-123');

      expect(execution.dry_run).toBe(true);
      const step1 = execution.steps.find(s => s.step_id === 'scan1');
      expect(step1?.output?.dry_run_simulation).toBe(true);
    });
  });

  describe('Workflow Cancellation', () => {
    it('should cancel running workflow', async () => {
      const workflow: WorkflowDefinition = {
        name: 'cancellable-workflow',
        version: '1.0.0',
        description: 'Workflow that can be cancelled',
        steps: [
          {
            id: 'long-step',
            name: 'Long Running Step',
            type: 'notification' as WorkflowStepType,
            config: { message: 'Long operation' }
          }
        ]
      };

      const request: WorkflowExecutionRequest = {
        workflow_name: 'cancellable-workflow',
        variables: {},
        dry_run: false
      };

      // Start execution (don't await)
      const executionPromise = engine.execute(workflow, request, 'org-123', 'user-123');

      // Wait a bit then cancel
      await new Promise(resolve => setTimeout(resolve, 100));

      const execution = await executionPromise;
      await engine.cancel(execution.execution_id);

      const updatedExecution = engine.getExecutionStatus(execution.execution_id);
      expect(updatedExecution.status).toBe('cancelled' as WorkflowExecutionStatus);
    });
  });
});
