/**
 * Testing Sandbox Client
 *
 * HTTP client for communicating with Tier 2 Testing Sandbox
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Tool execution request
 */
export interface ToolExecutionRequest {
  tool: string;
  target: string;
  action: string;
  options?: Record<string, any>;
  timeout?: number;
}

/**
 * Tool execution response
 */
export interface ToolExecutionResponse {
  execution_id: string;
  tool: string;
  target: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  results?: Record<string, any>;
  error?: string;
  raw_output?: string;
}

/**
 * Available tool
 */
export interface AvailableTool {
  name: string;
  description: string;
  supported_actions: string[];
  version: string;
}

/**
 * Health response
 */
export interface SandboxHealthResponse {
  status: string;
  version: string;
  available_tools: string[];
  redis_connected: boolean;
  timestamp: string;
}

/**
 * Testing Sandbox Client
 */
export class TestingSandboxClient {
  private client: AxiosInstance;
  private logger: Logger;
  private sandboxUrl: string;

  constructor() {
    this.sandboxUrl = config.sandboxes.tier2.url || 'http://nexus-cyberagent-testing-sandbox:9260';
    this.logger = createContextLogger('TestingSandboxClient');

    this.client = axios.create({
      baseURL: this.sandboxUrl,
      timeout: 5000, // 5 second timeout for API calls (not tool execution)
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Nexus-CyberAgent-API/1.0'
      }
    });

    // Request interceptor for logging
    this.client.interceptors.request.use(
      (config) => {
        this.logger.debug('Sandbox API request', {
          method: config.method,
          url: config.url,
          data: config.data
        });
        return config;
      },
      (error) => {
        this.logger.error('Sandbox API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    // Response interceptor for logging
    this.client.interceptors.response.use(
      (response) => {
        this.logger.debug('Sandbox API response', {
          status: response.status,
          data: response.data
        });
        return response;
      },
      (error: AxiosError) => {
        this.logger.error('Sandbox API response error', {
          status: error.response?.status,
          message: error.message,
          data: error.response?.data
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Check sandbox health
   */
  async checkHealth(): Promise<SandboxHealthResponse> {
    try {
      const response = await this.client.get<SandboxHealthResponse>('/health');
      return response.data;
    } catch (error) {
      this.logger.error('Health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Testing Sandbox is unavailable');
    }
  }

  /**
   * List available tools
   */
  async listTools(): Promise<AvailableTool[]> {
    try {
      const response = await this.client.get<{ tools: AvailableTool[] }>('/tools');
      return response.data.tools;
    } catch (error) {
      this.logger.error('Failed to list tools', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to retrieve tool list from Testing Sandbox');
    }
  }

  /**
   * Execute a tool
   */
  async executeTool(request: ToolExecutionRequest): Promise<ToolExecutionResponse> {
    try {
      this.logger.info('Executing tool in sandbox', {
        tool: request.tool,
        target: request.target,
        action: request.action
      });

      const response = await this.client.post<ToolExecutionResponse>('/execute', request);
      return response.data;
    } catch (error) {
      this.logger.error('Tool execution request failed', {
        tool: request.tool,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error(`Failed to execute ${request.tool}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get execution status and results
   */
  async getExecutionStatus(executionId: string): Promise<ToolExecutionResponse> {
    try {
      const response = await this.client.get<ToolExecutionResponse>(`/execution/${executionId}`);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        throw new Error(`Execution not found: ${executionId}`);
      }

      this.logger.error('Failed to get execution status', {
        execution_id: executionId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to retrieve execution status');
    }
  }

  /**
   * Execute tool and wait for completion
   */
  async executeToolAndWait(
    request: ToolExecutionRequest,
    pollInterval: number = 2000,
    maxWaitTime: number = 3600000 // 1 hour
  ): Promise<ToolExecutionResponse> {
    // Start execution
    const execution = await this.executeTool(request);
    const executionId = execution.execution_id;

    this.logger.info('Tool execution started, waiting for completion', {
      execution_id: executionId,
      tool: request.tool
    });

    // Poll for completion
    const startTime = Date.now();
    let attempts = 0;

    while (Date.now() - startTime < maxWaitTime) {
      attempts++;

      // Check status
      const status = await this.getExecutionStatus(executionId);

      this.logger.debug('Polling execution status', {
        execution_id: executionId,
        status: status.status,
        attempts
      });

      // Check if completed
      if (status.status === 'completed') {
        this.logger.info('Tool execution completed', {
          execution_id: executionId,
          duration: status.duration_seconds
        });
        return status;
      }

      // Check if failed
      if (status.status === 'failed') {
        this.logger.error('Tool execution failed', {
          execution_id: executionId,
          error: status.error
        });
        throw new Error(`Tool execution failed: ${status.error}`);
      }

      // Wait before next poll
      await this.sleep(pollInterval);
    }

    // Timeout
    throw new Error(`Tool execution timed out after ${maxWaitTime}ms`);
  }

  /**
   * Execute multiple tools in parallel
   */
  async executeToolsInParallel(
    requests: ToolExecutionRequest[]
  ): Promise<ToolExecutionResponse[]> {
    this.logger.info('Executing multiple tools in parallel', {
      count: requests.length,
      tools: requests.map(r => r.tool)
    });

    const executions = await Promise.all(
      requests.map(request => this.executeTool(request))
    );

    return executions;
  }

  /**
   * Wait for multiple executions to complete
   */
  async waitForExecutions(
    executionIds: string[],
    pollInterval: number = 2000,
    maxWaitTime: number = 3600000
  ): Promise<ToolExecutionResponse[]> {
    this.logger.info('Waiting for multiple executions', {
      count: executionIds.length,
      execution_ids: executionIds
    });

    const startTime = Date.now();
    const results: Map<string, ToolExecutionResponse> = new Map();
    const pending = new Set(executionIds);

    while (pending.size > 0 && Date.now() - startTime < maxWaitTime) {
      // Check all pending executions
      const statusPromises = Array.from(pending).map(async (executionId) => {
        try {
          const status = await this.getExecutionStatus(executionId);

          if (status.status === 'completed' || status.status === 'failed') {
            results.set(executionId, status);
            pending.delete(executionId);
          }

          return status;
        } catch (error) {
          this.logger.error('Failed to check execution status', {
            execution_id: executionId,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          return null;
        }
      });

      await Promise.all(statusPromises);

      // Wait before next poll if there are still pending
      if (pending.size > 0) {
        await this.sleep(pollInterval);
      }
    }

    // Check for timeouts
    if (pending.size > 0) {
      this.logger.error('Some executions timed out', {
        timed_out: Array.from(pending)
      });
      throw new Error(`${pending.size} executions timed out`);
    }

    return Array.from(results.values());
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
let testingSandboxClient: TestingSandboxClient | null = null;

/**
 * Get Testing Sandbox client instance
 */
export function getTestingSandboxClient(): TestingSandboxClient {
  if (!testingSandboxClient) {
    testingSandboxClient = new TestingSandboxClient();
  }
  return testingSandboxClient;
}
