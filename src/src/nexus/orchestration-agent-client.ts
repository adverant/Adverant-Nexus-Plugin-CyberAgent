/**
 * OrchestrationAgent Integration Client
 *
 * Enables autonomous security operations with ReAct (Reasoning + Acting) loop
 * OrchestrationAgent can autonomously plan and execute complex security workflows
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Autonomous operation request
 */
export interface AutonomousOperationRequest {
  objective: string;
  context: Record<string, any>;
  constraints?: {
    max_duration?: number;
    max_tool_calls?: number;
    allowed_actions?: string[];
    require_approval?: boolean;
  };
  callbacks?: {
    progress_url?: string;
    completion_url?: string;
  };
}

/**
 * ReAct step
 */
export interface ReActStep {
  step_number: number;
  thought: string;
  action: string;
  action_input: any;
  observation: string;
  reasoning: string;
}

/**
 * Autonomous operation response
 */
export interface AutonomousOperationResponse {
  operation_id: string;
  status: 'planning' | 'executing' | 'completed' | 'failed' | 'awaiting_approval';
  objective: string;
  plan: string[];
  react_steps: ReActStep[];
  result?: any;
  error?: string;
  duration_seconds?: number;
}

/**
 * OrchestrationAgent Integration Client
 */
export class OrchestrationAgentClient {
  private client: AxiosInstance;
  private logger: Logger;
  private orchestrationUrl: string;

  constructor() {
    this.orchestrationUrl = config.nexus?.orchestrationAgent?.url || 'http://nexus-orchestration:8091';
    this.logger = createContextLogger('OrchestrationAgentClient');

    this.client = axios.create({
      baseURL: this.orchestrationUrl,
      timeout: 300000, // 5 minutes for autonomous operations
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Nexus-CyberAgent/1.0'
      }
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        this.logger.debug('OrchestrationAgent API request', {
          method: config.method,
          url: config.url
        });
        return config;
      },
      (error) => {
        this.logger.error('OrchestrationAgent API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        this.logger.debug('OrchestrationAgent API response', {
          status: response.status
        });
        return response;
      },
      (error: AxiosError) => {
        this.logger.error('OrchestrationAgent API response error', {
          status: error.response?.status,
          message: error.message
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Autonomous vulnerability assessment and prioritization
   */
  async autonomousVulnerabilityAssessment(vulnerabilities: any[], target: string): Promise<AutonomousOperationResponse> {
    try {
      this.logger.info('Starting autonomous vulnerability assessment', {
        vulnerability_count: vulnerabilities.length,
        target
      });

      const request: AutonomousOperationRequest = {
        objective: `Autonomously assess and prioritize ${vulnerabilities.length} vulnerabilities found on ${target}.
        For each vulnerability:
        1. Determine real-world exploitability
        2. Assess business impact
        3. Check for known exploits in the wild
        4. Identify related vulnerabilities that could be chained
        5. Recommend remediation priority
        6. Estimate remediation effort

        Deliver a prioritized remediation roadmap with timeline.`,
        context: {
          vulnerabilities,
          target,
          organization_context: 'production_environment'
        },
        constraints: {
          max_duration: 600000, // 10 minutes
          max_tool_calls: 50,
          allowed_actions: ['query_cve_database', 'check_exploit_db', 'assess_impact', 'query_graphrag', 'synthesize_findings']
        }
      };

      const response = await this.executeAutonomousOperation(request);

      this.logger.info('Autonomous vulnerability assessment completed', {
        operation_id: response.operation_id,
        steps_executed: response.react_steps.length
      });

      return response;
    } catch (error) {
      this.logger.error('Failed autonomous vulnerability assessment', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Autonomous threat hunting based on IOCs
   */
  async autonomousThreatHunting(iocs: any, context: string): Promise<AutonomousOperationResponse> {
    try {
      this.logger.info('Starting autonomous threat hunting', {
        ioc_count: Object.values(iocs.iocs).reduce((sum: number, arr: any) => sum + arr.length, 0)
      });

      const request: AutonomousOperationRequest = {
        objective: `Hunt for threats across the organization based on discovered IOCs.
        Tasks:
        1. Correlate IOCs with historical scan data
        2. Identify affected systems
        3. Determine scope of compromise
        4. Reconstruct attack timeline
        5. Identify persistence mechanisms
        6. Map lateral movement
        7. Assess data exfiltration
        8. Generate containment recommendations

        Deliver comprehensive threat hunting report with evidence.`,
        context: {
          iocs,
          hunt_context: context
        },
        constraints: {
          max_duration: 900000, // 15 minutes
          max_tool_calls: 100,
          allowed_actions: [
            'query_graphrag',
            'correlate_iocs',
            'check_historical_scans',
            'analyze_network_traffic',
            'query_siem',
            'synthesize_findings'
          ]
        }
      };

      const response = await this.executeAutonomousOperation(request);

      this.logger.info('Autonomous threat hunting completed', {
        operation_id: response.operation_id,
        steps_executed: response.react_steps.length
      });

      return response;
    } catch (error) {
      this.logger.error('Failed autonomous threat hunting', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Autonomous incident response
   */
  async autonomousIncidentResponse(incident: {
    title: string;
    description: string;
    severity: string;
    affected_systems: string[];
    iocs?: any;
  }): Promise<AutonomousOperationResponse> {
    try {
      this.logger.info('Starting autonomous incident response', {
        incident: incident.title,
        severity: incident.severity
      });

      const request: AutonomousOperationRequest = {
        objective: `Autonomously respond to security incident: ${incident.title}
        Execute incident response playbook:
        1. Containment: Identify and isolate affected systems
        2. Eradication: Determine root cause and remove threat
        3. Recovery: Plan system restoration
        4. Lessons Learned: Document findings and improvements

        Consider severity: ${incident.severity}
        Affected systems: ${incident.affected_systems.join(', ')}

        Deliver detailed incident response plan with actions and timeline.`,
        context: {
          incident,
          response_phase: 'containment'
        },
        constraints: {
          max_duration: 600000, // 10 minutes for planning
          require_approval: true, // Human approval required for destructive actions
          allowed_actions: [
            'assess_impact',
            'identify_scope',
            'plan_containment',
            'query_graphrag',
            'check_similar_incidents',
            'generate_response_plan'
          ]
        }
      };

      const response = await this.executeAutonomousOperation(request);

      this.logger.info('Autonomous incident response plan completed', {
        operation_id: response.operation_id,
        requires_approval: response.status === 'awaiting_approval'
      });

      return response;
    } catch (error) {
      this.logger.error('Failed autonomous incident response', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Autonomous security posture assessment
   */
  async autonomousPostureAssessment(scanHistory: any[]): Promise<AutonomousOperationResponse> {
    try {
      this.logger.info('Starting autonomous security posture assessment', {
        scan_count: scanHistory.length
      });

      const request: AutonomousOperationRequest = {
        objective: `Analyze organization's security posture based on ${scanHistory.length} historical scans.
        Deliver comprehensive assessment:
        1. Current security posture score (0-100)
        2. Trend analysis (improving/degrading)
        3. Attack surface evolution
        4. Recurring vulnerability patterns
        5. Compliance gaps
        6. Comparison with industry benchmarks
        7. Risk prioritization matrix
        8. Strategic security recommendations

        Provide actionable insights for security leadership.`,
        context: {
          scan_history: scanHistory,
          assessment_scope: 'organization_wide'
        },
        constraints: {
          max_duration: 600000, // 10 minutes
          max_tool_calls: 80,
          allowed_actions: [
            'analyze_trends',
            'calculate_scores',
            'query_benchmarks',
            'identify_patterns',
            'assess_compliance',
            'query_graphrag',
            'synthesize_assessment'
          ]
        }
      };

      const response = await this.executeAutonomousOperation(request);

      this.logger.info('Autonomous posture assessment completed', {
        operation_id: response.operation_id,
        steps_executed: response.react_steps.length
      });

      return response;
    } catch (error) {
      this.logger.error('Failed autonomous posture assessment', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Execute autonomous operation
   */
  private async executeAutonomousOperation(request: AutonomousOperationRequest): Promise<AutonomousOperationResponse> {
    try {
      const response = await this.client.post('/api/autonomous/execute', request);

      this.logger.info('Autonomous operation initiated', {
        operation_id: response.data.operation_id,
        objective: request.objective.substring(0, 100) + '...'
      });

      // Poll for completion if not immediately completed
      if (response.data.status !== 'completed' && response.data.status !== 'failed') {
        return await this.waitForCompletion(response.data.operation_id);
      }

      return response.data;
    } catch (error) {
      this.logger.error('Failed to execute autonomous operation', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Wait for autonomous operation to complete
   */
  private async waitForCompletion(
    operationId: string,
    pollInterval: number = 5000,
    maxWaitTime: number = 600000
  ): Promise<AutonomousOperationResponse> {
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      try {
        const status = await this.getOperationStatus(operationId);

        this.logger.debug('Polling autonomous operation', {
          operation_id: operationId,
          status: status.status,
          steps: status.react_steps.length
        });

        if (status.status === 'completed' || status.status === 'failed' || status.status === 'awaiting_approval') {
          return status;
        }

        await this.sleep(pollInterval);
      } catch (error) {
        this.logger.error('Error polling autonomous operation', {
          operation_id: operationId,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
        throw error;
      }
    }

    throw new Error(`Autonomous operation timed out after ${maxWaitTime}ms`);
  }

  /**
   * Get operation status
   */
  async getOperationStatus(operationId: string): Promise<AutonomousOperationResponse> {
    try {
      const response = await this.client.get(`/api/autonomous/status/${operationId}`);
      return response.data;
    } catch (error) {
      this.logger.error('Failed to get operation status', {
        operation_id: operationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Approve autonomous operation
   */
  async approveOperation(operationId: string, approval: boolean): Promise<AutonomousOperationResponse> {
    try {
      const response = await this.client.post(`/api/autonomous/approve/${operationId}`, {
        approved: approval
      });

      this.logger.info('Autonomous operation approval', {
        operation_id: operationId,
        approved: approval
      });

      return response.data;
    } catch (error) {
      this.logger.error('Failed to approve operation', {
        operation_id: operationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
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
let orchestrationAgentClient: OrchestrationAgentClient | null = null;

/**
 * Get OrchestrationAgent client instance
 */
export function getOrchestrationAgentClient(): OrchestrationAgentClient {
  if (!orchestrationAgentClient) {
    orchestrationAgentClient = new OrchestrationAgentClient();
  }
  return orchestrationAgentClient;
}
