/**
 * MageAgent Integration Client
 *
 * Coordinates multiple AI agents for complex security tasks
 * Uses MageAgent's multi-agent orchestration capabilities
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Agent spawn request
 */
export interface SpawnAgentRequest {
  task: string;
  role: 'analyst' | 'researcher' | 'specialist' | 'synthesis';
  context: Record<string, any>;
  priority?: number;
  timeout?: number;
}

/**
 * Multi-agent orchestration request
 */
export interface OrchestrationRequest {
  task: string;
  maxAgents: number;
  timeout?: number;
  context: Record<string, any>;
}

/**
 * Agent response
 */
export interface AgentResponse {
  agent_id: string;
  role: string;
  status: 'spawned' | 'running' | 'completed' | 'failed';
  result?: any;
  error?: string;
}

/**
 * Orchestration response
 */
export interface OrchestrationResponse {
  task_id: string;
  status: 'running' | 'completed' | 'failed';
  agents: AgentResponse[];
  synthesis: any;
  duration_seconds?: number;
}

/**
 * MageAgent Integration Client
 */
export class MageAgentClient {
  private client: AxiosInstance;
  private logger: Logger;
  private mageagentUrl: string;

  constructor() {
    this.mageagentUrl = config.nexus?.mageagent?.url || 'http://nexus-mageagent:8080';
    this.logger = createContextLogger('MageAgentClient');

    this.client = axios.create({
      baseURL: this.mageagentUrl,
      timeout: 120000, // 2 minutes timeout for orchestration
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Nexus-CyberAgent/1.0'
      }
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        this.logger.debug('MageAgent API request', {
          method: config.method,
          url: config.url
        });
        return config;
      },
      (error) => {
        this.logger.error('MageAgent API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        this.logger.debug('MageAgent API response', {
          status: response.status
        });
        return response;
      },
      (error: AxiosError) => {
        this.logger.error('MageAgent API response error', {
          status: error.response?.status,
          message: error.message
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Analyze vulnerability findings with multiple agents
   */
  async analyzeVulnerabilities(vulnerabilities: any[], target: string): Promise<OrchestrationResponse> {
    try {
      this.logger.info('Orchestrating vulnerability analysis', {
        vulnerability_count: vulnerabilities.length,
        target
      });

      const request: OrchestrationRequest = {
        task: `Analyze ${vulnerabilities.length} security vulnerabilities found on ${target}. Provide:
1. Risk assessment and prioritization
2. Exploitation likelihood analysis
3. Remediation recommendations with timeline
4. Potential attack chains
5. Compliance impact (PCI DSS, SOC 2, ISO 27001)`,
        maxAgents: 3, // Analyst, Specialist, Synthesis
        timeout: 180000, // 3 minutes
        context: {
          vulnerabilities,
          target,
          scan_context: 'security_assessment'
        }
      };

      const response = await this.orchestrate(request);

      this.logger.info('Vulnerability analysis completed', {
        task_id: response.task_id,
        agents_used: response.agents.length
      });

      return response;
    } catch (error) {
      this.logger.error('Failed to analyze vulnerabilities', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Analyze malware with multiple specialized agents
   */
  async analyzeMalware(malwareData: {
    sha256: string;
    malware_family?: string;
    threat_level: string;
    iocs: Record<string, string[]>;
    behavioral_analysis: any;
  }): Promise<OrchestrationResponse> {
    try {
      this.logger.info('Orchestrating malware analysis', {
        sha256: malwareData.sha256,
        malware_family: malwareData.malware_family
      });

      const request: OrchestrationRequest = {
        task: `Analyze malware sample (SHA256: ${malwareData.sha256}). Provide:
1. Malware family classification and variants
2. Attack vector and infection chain analysis
3. Persistence mechanisms
4. C2 communication analysis
5. Lateral movement capabilities
6. Data exfiltration techniques
7. Defensive evasion methods
8. Attribution and APT group analysis
9. Similar samples and campaigns
10. Comprehensive remediation plan`,
        maxAgents: 5, // Multiple specialists for comprehensive analysis
        timeout: 300000, // 5 minutes
        context: {
          ...malwareData,
          scan_context: 'malware_analysis'
        }
      };

      const response = await this.orchestrate(request);

      this.logger.info('Malware analysis completed', {
        task_id: response.task_id,
        agents_used: response.agents.length
      });

      return response;
    } catch (error) {
      this.logger.error('Failed to analyze malware', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Generate threat report with multiple agents
   */
  async generateThreatReport(scanResults: {
    scan_type: string;
    target: string;
    findings: any[];
    iocs?: any;
  }): Promise<OrchestrationResponse> {
    try {
      this.logger.info('Orchestrating threat report generation', {
        scan_type: scanResults.scan_type,
        target: scanResults.target,
        findings_count: scanResults.findings.length
      });

      const request: OrchestrationRequest = {
        task: `Generate comprehensive threat intelligence report for ${scanResults.scan_type} scan of ${scanResults.target}. Include:
1. Executive Summary
2. Technical Findings Summary
3. Risk Assessment Matrix
4. Attack Surface Analysis
5. Threat Actor Profile (if applicable)
6. Timeline and Kill Chain Analysis
7. Remediation Roadmap with priorities
8. Compliance Gaps
9. Security Posture Score
10. Recommendations for security improvements`,
        maxAgents: 4, // Analyst, Researcher, Specialist, Synthesis
        timeout: 240000, // 4 minutes
        context: {
          ...scanResults,
          scan_context: 'threat_reporting'
        }
      };

      const response = await this.orchestrate(request);

      this.logger.info('Threat report generated', {
        task_id: response.task_id,
        agents_used: response.agents.length
      });

      return response;
    } catch (error) {
      this.logger.error('Failed to generate threat report', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Correlate findings across multiple scans
   */
  async correlateFindings(scans: any[]): Promise<OrchestrationResponse> {
    try {
      this.logger.info('Orchestrating finding correlation', {
        scan_count: scans.length
      });

      const request: OrchestrationRequest = {
        task: `Correlate findings across ${scans.length} security scans. Identify:
1. Common vulnerabilities and patterns
2. Related attack vectors
3. Persistent threats
4. Infrastructure relationships
5. Timeline of compromise
6. Attack chain reconstruction
7. Shared IOCs and TTPs
8. Attribution clues`,
        maxAgents: 3,
        timeout: 180000,
        context: {
          scans,
          scan_context: 'correlation_analysis'
        }
      };

      const response = await this.orchestrate(request);

      this.logger.info('Finding correlation completed', {
        task_id: response.task_id
      });

      return response;
    } catch (error) {
      this.logger.error('Failed to correlate findings', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Spawn single agent for specific task
   */
  async spawnAgent(request: SpawnAgentRequest): Promise<AgentResponse> {
    try {
      const response = await this.client.post('/api/agents/spawn', request);

      this.logger.info('Agent spawned', {
        agent_id: response.data.agent_id,
        role: request.role
      });

      return response.data;
    } catch (error) {
      this.logger.error('Failed to spawn agent', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Orchestrate multiple agents
   */
  async orchestrate(request: OrchestrationRequest): Promise<OrchestrationResponse> {
    try {
      const response = await this.client.post('/api/orchestrate', request);

      this.logger.info('Orchestration completed', {
        task_id: response.data.task_id,
        status: response.data.status
      });

      return response.data;
    } catch (error) {
      this.logger.error('Failed to orchestrate agents', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get orchestration status
   */
  async getOrchestrationStatus(taskId: string): Promise<OrchestrationResponse> {
    try {
      const response = await this.client.get(`/api/orchestrate/${taskId}`);
      return response.data;
    } catch (error) {
      this.logger.error('Failed to get orchestration status', {
        task_id: taskId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }
}

/**
 * Singleton instance
 */
let mageagentClient: MageAgentClient | null = null;

/**
 * Get MageAgent client instance
 */
export function getMageAgentClient(): MageAgentClient {
  if (!mageagentClient) {
    mageagentClient = new MageAgentClient();
  }
  return mageagentClient;
}
