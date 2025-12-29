/**
 * Detonation Chamber Client
 *
 * HTTP client for communicating with Tier 3 Detonation Chamber (malware analysis)
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import FormData from 'form-data';
import { createReadStream } from 'fs';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Malware submission request
 */
export interface MalwareSubmissionRequest {
  filename: string;
  sha256?: string;
  analysis_timeout?: number;
  vm_profile?: string;
  enable_network?: boolean;
  priority?: number;
}

/**
 * Analysis response
 */
export interface AnalysisResponse {
  analysis_id: string;
  sha256: string;
  status: 'queued' | 'analyzing' | 'completed' | 'failed';
  submitted_at: string;
  completed_at?: string;
  duration_seconds?: number;
  vm_profile: string;
  results?: any;
  error?: string;
}

/**
 * IOC response
 */
export interface IOCResponse {
  analysis_id: string;
  iocs: Record<string, string[]>;
  confidence_scores: Record<string, number>;
  yara_matches: string[];
  malware_family?: string;
  threat_level: string;
}

/**
 * Health response
 */
export interface DetonationChamberHealthResponse {
  status: string;
  version: string;
  cuckoo_available: boolean;
  vm_profiles_available: string[];
  redis_connected: boolean;
  timestamp: string;
}

// ============================================================================
// Decompilation Types
// ============================================================================

/**
 * Radare2 decompilation options
 */
export interface Radare2DecompileOptions {
  extractFunctions?: boolean;
  extractStrings?: boolean;
  extractXrefs?: boolean;
  maxFunctions?: number;
  targetFunctions?: string[];
  timeout?: number;
}

/**
 * Ghidra decompilation options
 */
export interface GhidraDecompileOptions {
  extractFunctions?: boolean;
  extractStrings?: boolean;
  extractXrefs?: boolean;
  maxFunctions?: number;
  targetFunctions?: string[];
  timeout?: number;
}

/**
 * Extracted function from decompilation
 */
export interface ExtractedFunctionResponse {
  name: string;
  address: string;
  size: number;
  disassembly?: string;
  pseudocode?: string;
  calling_convention?: string;
  argc?: number;
  return_type?: string;
  callees?: string[];
  callers?: string[];
  string_refs?: string[];
  cyclomatic_complexity?: number;
}

/**
 * Decompilation response from Detonation Chamber
 */
export interface DecompilationResponse {
  success: boolean;
  error?: string;
  tool: 'radare2' | 'ghidra';
  tool_version?: string;
  total_functions: number;
  architecture?: string;
  format?: string;
  entry_point?: string;
  functions: ExtractedFunctionResponse[];
  strings?: Array<{
    value: string;
    address: string;
    type?: string;
  }>;
  imports?: Array<{
    library: string;
    function: string;
    address: string;
  }>;
  exports?: Array<{
    name: string;
    address: string;
    ordinal?: number;
  }>;
}

/**
 * Detonation Chamber Client
 */
export class DetonationChamberClient {
  private client: AxiosInstance;
  private logger: Logger;
  private chamberUrl: string;

  constructor() {
    this.chamberUrl = config.sandboxes.tier3.url || 'http://nexus-cyberagent-detonation-chamber:9270';
    this.logger = createContextLogger('DetonationChamberClient');

    this.client = axios.create({
      baseURL: this.chamberUrl,
      timeout: 10000, // 10 second timeout for API calls
      headers: {
        'User-Agent': 'Nexus-CyberAgent-API/1.0'
      }
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        this.logger.debug('Detonation Chamber API request', {
          method: config.method,
          url: config.url
        });
        return config;
      },
      (error) => {
        this.logger.error('Detonation Chamber API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        this.logger.debug('Detonation Chamber API response', {
          status: response.status
        });
        return response;
      },
      (error: AxiosError) => {
        this.logger.error('Detonation Chamber API response error', {
          status: error.response?.status,
          message: error.message
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Check detonation chamber health
   */
  async checkHealth(): Promise<DetonationChamberHealthResponse> {
    try {
      const response = await this.client.get<DetonationChamberHealthResponse>('/health');
      return response.data;
    } catch (error) {
      this.logger.error('Health check failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Detonation Chamber is unavailable');
    }
  }

  /**
   * Upload malware sample
   */
  async uploadMalware(filePath: string, filename: string): Promise<{ analysis_id: string; sha256: string }> {
    try {
      const form = new FormData();
      form.append('file', createReadStream(filePath), filename);

      this.logger.info('Uploading malware sample', { filename });

      const response = await this.client.post('/upload', form, {
        headers: form.getHeaders(),
        maxBodyLength: Infinity,
        timeout: 60000 // 60 second timeout for upload
      });

      return response.data;
    } catch (error) {
      this.logger.error('Failed to upload malware sample', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to upload malware sample');
    }
  }

  /**
   * Start malware analysis
   */
  async analyzeMalware(
    analysisId: string,
    request: MalwareSubmissionRequest
  ): Promise<AnalysisResponse> {
    try {
      this.logger.info('Starting malware analysis', {
        analysis_id: analysisId,
        vm_profile: request.vm_profile
      });

      const response = await this.client.post<AnalysisResponse>(
        `/analyze/${analysisId}`,
        request
      );

      return response.data;
    } catch (error) {
      this.logger.error('Failed to start analysis', {
        analysis_id: analysisId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to start malware analysis');
    }
  }

  /**
   * Get analysis status and results
   */
  async getAnalysisStatus(analysisId: string): Promise<AnalysisResponse> {
    try {
      const response = await this.client.get<AnalysisResponse>(`/analysis/${analysisId}`);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        throw new Error(`Analysis not found: ${analysisId}`);
      }

      this.logger.error('Failed to get analysis status', {
        analysis_id: analysisId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to retrieve analysis status');
    }
  }

  /**
   * Get extracted IOCs
   */
  async getIOCs(analysisId: string): Promise<IOCResponse> {
    try {
      const response = await this.client.get<IOCResponse>(`/iocs/${analysisId}`);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        throw new Error(`Analysis not found: ${analysisId}`);
      }

      this.logger.error('Failed to get IOCs', {
        analysis_id: analysisId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to retrieve IOCs');
    }
  }

  /**
   * Upload and analyze malware (convenience method)
   */
  async uploadAndAnalyze(
    filePath: string,
    filename: string,
    analysisOptions: Partial<MalwareSubmissionRequest> = {}
  ): Promise<{ analysisId: string; sha256: string }> {
    // Upload sample
    const uploadResult = await this.uploadMalware(filePath, filename);

    // Start analysis
    await this.analyzeMalware(uploadResult.analysis_id, {
      filename,
      sha256: uploadResult.sha256,
      analysis_timeout: analysisOptions.analysis_timeout || 600,
      vm_profile: analysisOptions.vm_profile || 'win10',
      enable_network: analysisOptions.enable_network || false,
      priority: analysisOptions.priority || 1
    });

    this.logger.info('Malware sample uploaded and analysis started', {
      analysis_id: uploadResult.analysis_id,
      sha256: uploadResult.sha256
    });

    return {
      analysisId: uploadResult.analysis_id,
      sha256: uploadResult.sha256
    };
  }

  /**
   * Wait for analysis to complete
   */
  async waitForAnalysis(
    analysisId: string,
    pollInterval: number = 10000,
    maxWaitTime: number = 3600000 // 1 hour
  ): Promise<AnalysisResponse> {
    this.logger.info('Waiting for analysis completion', {
      analysis_id: analysisId
    });

    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const status = await this.getAnalysisStatus(analysisId);

      this.logger.debug('Polling analysis status', {
        analysis_id: analysisId,
        status: status.status
      });

      if (status.status === 'completed') {
        this.logger.info('Analysis completed', {
          analysis_id: analysisId,
          duration: status.duration_seconds
        });
        return status;
      }

      if (status.status === 'failed') {
        this.logger.error('Analysis failed', {
          analysis_id: analysisId,
          error: status.error
        });
        throw new Error(`Analysis failed: ${status.error}`);
      }

      // Wait before next poll
      await this.sleep(pollInterval);
    }

    throw new Error(`Analysis timed out after ${maxWaitTime}ms`);
  }

  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ==========================================================================
  // Decompilation Methods
  // ==========================================================================

  /**
   * Decompile binary using Radare2 (quick disassembly)
   *
   * Best for:
   * - Quick triage of suspicious binaries
   * - Function enumeration
   * - Basic control flow analysis
   *
   * @param filePath - Path to binary file on the detonation chamber
   * @param options - Radare2 decompilation options
   * @returns DecompilationResponse with disassembled functions
   */
  async decompileRadare2(
    filePath: string,
    options: Radare2DecompileOptions = {}
  ): Promise<DecompilationResponse> {
    try {
      this.logger.info('Starting Radare2 decompilation', {
        file_path: filePath,
        max_functions: options.maxFunctions
      });

      const response = await this.client.post<DecompilationResponse>(
        '/decompile/radare2',
        {
          file_path: filePath,
          extract_functions: options.extractFunctions ?? true,
          extract_strings: options.extractStrings ?? true,
          extract_xrefs: options.extractXrefs ?? false,
          max_functions: options.maxFunctions ?? 100,
          target_functions: options.targetFunctions,
          timeout: options.timeout ?? 120
        },
        {
          timeout: (options.timeout ?? 120) * 1000 + 10000 // Add 10s buffer
        }
      );

      this.logger.info('Radare2 decompilation completed', {
        file_path: filePath,
        functions_found: response.data.total_functions,
        success: response.data.success
      });

      return response.data;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      this.logger.error('Radare2 decompilation failed', {
        file_path: filePath,
        error: errorMessage
      });

      // Return error response instead of throwing
      return {
        success: false,
        error: `Radare2 decompilation failed: ${errorMessage}`,
        tool: 'radare2',
        total_functions: 0,
        functions: []
      };
    }
  }

  /**
   * Decompile binary using Ghidra (full decompilation with pseudocode)
   *
   * Best for:
   * - Deep analysis of malware
   * - Pseudocode generation for understanding logic
   * - Complete cross-reference analysis
   * - High/critical threat samples
   *
   * Note: Slower than Radare2 but provides much more detailed output.
   *
   * @param filePath - Path to binary file on the detonation chamber
   * @param options - Ghidra decompilation options
   * @returns DecompilationResponse with decompiled pseudocode
   */
  async decompileGhidra(
    filePath: string,
    options: GhidraDecompileOptions = {}
  ): Promise<DecompilationResponse> {
    try {
      this.logger.info('Starting Ghidra decompilation', {
        file_path: filePath,
        max_functions: options.maxFunctions
      });

      const response = await this.client.post<DecompilationResponse>(
        '/decompile/ghidra',
        {
          file_path: filePath,
          extract_functions: options.extractFunctions ?? true,
          extract_strings: options.extractStrings ?? true,
          extract_xrefs: options.extractXrefs ?? true,
          max_functions: options.maxFunctions ?? 50,
          target_functions: options.targetFunctions,
          timeout: options.timeout ?? 300
        },
        {
          timeout: (options.timeout ?? 300) * 1000 + 30000 // Add 30s buffer for Ghidra
        }
      );

      this.logger.info('Ghidra decompilation completed', {
        file_path: filePath,
        functions_found: response.data.total_functions,
        success: response.data.success
      });

      return response.data;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      this.logger.error('Ghidra decompilation failed', {
        file_path: filePath,
        error: errorMessage
      });

      // Return error response instead of throwing
      return {
        success: false,
        error: `Ghidra decompilation failed: ${errorMessage}`,
        tool: 'ghidra',
        total_functions: 0,
        functions: []
      };
    }
  }

  /**
   * Smart decompilation - choose tool based on analysis needs
   *
   * @param filePath - Path to binary file
   * @param depth - 'quick' uses Radare2, 'deep' uses Ghidra
   * @param options - Additional options
   * @returns DecompilationResponse
   */
  async decompile(
    filePath: string,
    depth: 'quick' | 'deep' = 'quick',
    options: Partial<Radare2DecompileOptions & GhidraDecompileOptions> = {}
  ): Promise<DecompilationResponse> {
    if (depth === 'quick') {
      return this.decompileRadare2(filePath, options);
    } else {
      return this.decompileGhidra(filePath, options);
    }
  }
}

/**
 * Singleton instance
 */
let detonationChamberClient: DetonationChamberClient | null = null;

/**
 * Get Detonation Chamber client instance
 */
export function getDetonationChamberClient(): DetonationChamberClient {
  if (!detonationChamberClient) {
    detonationChamberClient = new DetonationChamberClient();
  }
  return detonationChamberClient;
}
