/**
 * Workflow Routes
 *
 * REST API endpoints for workflow management and execution
 */

import { Router, Request, Response, NextFunction } from 'express';
import { getWorkflowService } from '../services/workflow.service';
import { authenticate } from '../middleware/auth';
import { Logger, createContextLogger } from '../utils/logger';
import { WorkflowExecutionRequest } from '../types/workflow.types';

const router = Router();
const logger = createContextLogger('WorkflowRoutes');

/**
 * POST /api/workflows/parse
 * Parse workflow from YAML
 */
router.post('/parse', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { yaml_content } = req.body;

    if (!yaml_content) {
      return res.status(400).json({
        error: 'yaml_content is required'
      });
    }

    const workflowService = getWorkflowService();
    const workflow = await workflowService.parseWorkflow(yaml_content);

    res.json({
      success: true,
      workflow
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/workflows/validate
 * Validate workflow definition
 */
router.post('/validate', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { yaml_content } = req.body;

    if (!yaml_content) {
      return res.status(400).json({
        error: 'yaml_content is required'
      });
    }

    const workflowService = getWorkflowService();
    const workflow = await workflowService.parseWorkflow(yaml_content);
    const validation = workflowService.validateWorkflow(workflow);

    res.json({
      success: true,
      validation
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/workflows/execute
 * Execute workflow from YAML
 */
router.post('/execute', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { yaml_content, variables, dry_run } = req.body;

    if (!yaml_content) {
      return res.status(400).json({
        error: 'yaml_content is required'
      });
    }

    const workflowService = getWorkflowService();
    const workflow = await workflowService.parseWorkflow(yaml_content);

    const request: WorkflowExecutionRequest = {
      workflow_name: workflow.name,
      workflow_version: workflow.version,
      variables: variables || {},
      dry_run: dry_run || false
    };

    const execution = await workflowService.executeWorkflow(
      workflow,
      request,
      (req as any).user.organization_id,
      (req as any).user.user_id
    );

    res.json({
      success: true,
      execution: {
        execution_id: execution.execution_id,
        status: execution.status,
        workflow_name: execution.workflow_name,
        triggered_at: execution.triggered_at,
        steps_count: execution.steps.length
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/workflows/templates
 * List built-in workflow templates
 */
router.get('/templates', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const workflowService = getWorkflowService();
    const templates = await workflowService.listBuiltInWorkflows();

    res.json({
      success: true,
      templates,
      count: templates.length
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/workflows/templates/:name
 * Get built-in workflow template
 */
router.get('/templates/:name', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name } = req.params;

    const workflowService = getWorkflowService();
    const workflow = await workflowService.loadBuiltInWorkflow(name as any);

    res.json({
      success: true,
      workflow
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/workflows/templates/:name/execute
 * Execute built-in workflow template
 */
router.post('/templates/:name/execute', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name } = req.params;
    const { variables, dry_run } = req.body;

    const request: WorkflowExecutionRequest = {
      workflow_name: name,
      variables: variables || {},
      dry_run: dry_run || false
    };

    const workflowService = getWorkflowService();
    const execution = await workflowService.executeBuiltInWorkflow(
      name as any,
      request,
      (req as any).user.organization_id,
      (req as any).user.user_id
    );

    res.json({
      success: true,
      execution: {
        execution_id: execution.execution_id,
        status: execution.status,
        workflow_name: execution.workflow_name,
        triggered_at: execution.triggered_at,
        steps_count: execution.steps.length
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/workflows/executions/:id
 * Get workflow execution status
 */
router.get('/executions/:id', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;

    const workflowService = getWorkflowService();
    const execution = workflowService.getExecutionStatus(id);

    res.json({
      success: true,
      execution
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/workflows/executions/:id/cancel
 * Cancel workflow execution
 */
router.post('/executions/:id/cancel', authenticate, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;

    const workflowService = getWorkflowService();
    await workflowService.cancelExecution(id);

    res.json({
      success: true,
      message: 'Workflow execution cancelled'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/workflows/executions/:id/steps/:stepId/approve
 * Approve workflow step
 */
router.post(
  '/executions/:id/steps/:stepId/approve',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id, stepId } = req.params;
      const { approved } = req.body;

      if (approved === undefined) {
        return res.status(400).json({
          error: 'approved (boolean) is required'
        });
      }

      const workflowService = getWorkflowService();
      await workflowService.approveStep(id, stepId, approved);

      res.json({
        success: true,
        message: `Step ${approved ? 'approved' : 'rejected'}`
      });
    } catch (error) {
      next(error);
    }
  }
);

export default router;
