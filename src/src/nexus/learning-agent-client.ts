/**
 * LearningAgent Integration Client
 *
 * Enables progressive learning from security scans and malware analysis
 * LearningAgent continuously improves detection capabilities through experience
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Learning trigger request
 */
export interface LearningTriggerRequest {
  topic: string;
  priority: number; // 1-10, 10 = urgent
  trigger_source: 'scan_completion' | 'malware_analysis' | 'vulnerability_discovery' | 'threat_hunting' | 'manual';
  context: {
    scan_id?: string;
    analysis_id?: string;
    findings?: any;
    success_rate?: number;
    false_positives?: number;
    false_negatives?: number;
  };
  learning_objectives?: string[];
}

/**
 * Learning response
 */
export interface LearningResponse {
  learning_id: string;
  topic: string;
  status: 'queued' | 'learning' | 'completed' | 'failed';
  layers_completed?: string[];
  knowledge_gained?: string[];
  improvements_suggested?: string[];
  error?: string;
}

/**
 * Knowledge retrieval request
 */
export interface KnowledgeRetrievalRequest {
  topic: string;
  layer?: 'OVERVIEW' | 'PROCEDURES' | 'TECHNIQUES' | 'EXPERT' | 'all';
  min_confidence?: number;
  max_results?: number;
}

/**
 * Knowledge item
 */
export interface KnowledgeItem {
  id: string;
  topic: string;
  layer: string;
  content: string;
  confidence: number;
  source: string;
  learned_at: Date;
  validation_score?: number;
  related_findings?: string[];
}

/**
 * Pattern recognition request
 */
export interface PatternRecognitionRequest {
  data_type: 'vulnerabilities' | 'malware' | 'iocs' | 'network_traffic' | 'user_behavior';
  data_points: any[];
  historical_context?: any[];
  pattern_types?: ('temporal' | 'spatial' | 'behavioral' | 'structural')[];
}

/**
 * Recognized pattern
 */
export interface RecognizedPattern {
  pattern_id: string;
  pattern_type: string;
  confidence: number;
  description: string;
  occurrences: number;
  first_seen: Date;
  last_seen: Date;
  indicators: any[];
  recommendations?: string[];
  related_threats?: string[];
}

/**
 * Improvement suggestion
 */
export interface ImprovementSuggestion {
  suggestion_id: string;
  category: 'detection_rule' | 'scan_configuration' | 'workflow' | 'coverage' | 'performance';
  priority: number;
  title: string;
  description: string;
  rationale: string;
  expected_impact: {
    false_positive_reduction?: number;
    false_negative_reduction?: number;
    coverage_increase?: number;
    performance_improvement?: number;
  };
  implementation_steps?: string[];
  risk_level: 'low' | 'medium' | 'high';
}

/**
 * Predictive threat model
 */
export interface PredictiveThreatModel {
  model_id: string;
  threat_scenario: string;
  probability: number;
  confidence: number;
  time_horizon: string; // e.g., "7_days", "30_days"
  indicators: string[];
  mitigations: string[];
  evidence: any[];
  related_historical_events?: any[];
}

/**
 * LearningAgent Integration Client
 */
export class LearningAgentClient {
  private client: AxiosInstance;
  private logger: Logger;
  private learningUrl: string;

  constructor() {
    this.learningUrl = config.nexus?.learningAgent?.url || 'http://nexus-learningagent:8093';
    this.logger = createContextLogger('LearningAgentClient');

    this.client = axios.create({
      baseURL: this.learningUrl,
      timeout: 120000, // 2 minutes for learning operations
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Nexus-CyberAgent/1.0'
      }
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        this.logger.debug('LearningAgent API request', {
          method: config.method,
          url: config.url
        });
        return config;
      },
      (error) => {
        this.logger.error('LearningAgent API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        this.logger.debug('LearningAgent API response', {
          status: response.status
        });
        return response;
      },
      (error: AxiosError) => {
        this.logger.error('LearningAgent API response error', {
          status: error.response?.status,
          message: error.message
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Learn from completed security scan
   */
  async learnFromScan(scanResults: {
    scan_id: string;
    target: string;
    scan_type: string;
    findings: any[];
    duration_seconds: number;
    false_positives?: number;
    false_negatives?: number;
  }): Promise<LearningResponse> {
    try {
      this.logger.info('Triggering learning from scan', {
        scan_id: scanResults.scan_id,
        scan_type: scanResults.scan_type,
        findings_count: scanResults.findings.length
      });

      const request: LearningTriggerRequest = {
        topic: `scan_analysis_${scanResults.scan_type}`,
        priority: 7,
        trigger_source: 'scan_completion',
        context: {
          scan_id: scanResults.scan_id,
          findings: scanResults.findings,
          success_rate: this.calculateSuccessRate(scanResults),
          false_positives: scanResults.false_positives || 0,
          false_negatives: scanResults.false_negatives || 0
        },
        learning_objectives: [
          'Improve detection accuracy',
          'Reduce false positives',
          'Optimize scan parameters',
          'Identify recurring patterns'
        ]
      };

      const response = await this.triggerLearning(request);

      this.logger.info('Learning triggered from scan', {
        learning_id: response.learning_id,
        scan_id: scanResults.scan_id
      });

      return response;
    } catch (error) {
      this.logger.error('Failed to learn from scan', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Learn from malware analysis
   */
  async learnFromMalwareAnalysis(analysisResults: {
    analysis_id: string;
    malware_family?: string;
    threat_level: string;
    iocs: any;
    analysis_phases: any;
    detection_rate?: number;
  }): Promise<LearningResponse> {
    try {
      this.logger.info('Triggering learning from malware analysis', {
        analysis_id: analysisResults.analysis_id,
        malware_family: analysisResults.malware_family,
        threat_level: analysisResults.threat_level
      });

      const request: LearningTriggerRequest = {
        topic: `malware_analysis_${analysisResults.malware_family || 'unknown'}`,
        priority: analysisResults.threat_level === 'critical' ? 10 : 8,
        trigger_source: 'malware_analysis',
        context: {
          analysis_id: analysisResults.analysis_id,
          findings: analysisResults,
          success_rate: analysisResults.detection_rate
        },
        learning_objectives: [
          'Improve malware family classification',
          'Enhance IOC extraction',
          'Optimize YARA rules',
          'Identify evasion techniques'
        ]
      };

      const response = await this.triggerLearning(request);

      this.logger.info('Learning triggered from malware analysis', {
        learning_id: response.learning_id,
        analysis_id: analysisResults.analysis_id
      });

      return response;
    } catch (error) {
      this.logger.error('Failed to learn from malware analysis', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Learn from vulnerability discovery
   */
  async learnFromVulnerabilityDiscovery(vulnerability: {
    cve_id?: string;
    severity: string;
    exploitability: string;
    affected_systems: string[];
    detection_method: string;
    false_positive: boolean;
  }): Promise<LearningResponse> {
    try {
      this.logger.info('Triggering learning from vulnerability discovery', {
        cve_id: vulnerability.cve_id,
        severity: vulnerability.severity
      });

      const request: LearningTriggerRequest = {
        topic: `vulnerability_detection_${vulnerability.cve_id || 'custom'}`,
        priority: vulnerability.severity === 'CRITICAL' ? 9 : 6,
        trigger_source: 'vulnerability_discovery',
        context: {
          findings: vulnerability,
          false_positives: vulnerability.false_positive ? 1 : 0
        },
        learning_objectives: [
          'Improve vulnerability detection',
          'Reduce false positives',
          'Enhance severity assessment',
          'Optimize scanning coverage'
        ]
      };

      const response = await this.triggerLearning(request);

      this.logger.info('Learning triggered from vulnerability discovery', {
        learning_id: response.learning_id,
        cve_id: vulnerability.cve_id
      });

      return response;
    } catch (error) {
      this.logger.error('Failed to learn from vulnerability discovery', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Trigger progressive learning
   */
  private async triggerLearning(request: LearningTriggerRequest): Promise<LearningResponse> {
    try {
      const response = await this.client.post('/api/learning/trigger', request);
      return response.data;
    } catch (error) {
      this.logger.error('Failed to trigger learning', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Retrieve learned knowledge
   */
  async retrieveKnowledge(request: KnowledgeRetrievalRequest): Promise<KnowledgeItem[]> {
    try {
      this.logger.debug('Retrieving learned knowledge', {
        topic: request.topic,
        layer: request.layer
      });

      const response = await this.client.post('/api/learning/knowledge', request);

      this.logger.info('Retrieved learned knowledge', {
        topic: request.topic,
        items_count: response.data.items?.length || 0
      });

      return response.data.items || [];
    } catch (error) {
      this.logger.error('Failed to retrieve knowledge', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Recognize patterns in security data
   */
  async recognizePatterns(request: PatternRecognitionRequest): Promise<RecognizedPattern[]> {
    try {
      this.logger.info('Recognizing patterns', {
        data_type: request.data_type,
        data_points_count: request.data_points.length
      });

      const response = await this.client.post('/api/learning/patterns', request);

      this.logger.info('Pattern recognition completed', {
        patterns_found: response.data.patterns?.length || 0
      });

      return response.data.patterns || [];
    } catch (error) {
      this.logger.error('Failed to recognize patterns', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get improvement suggestions
   */
  async getImprovementSuggestions(context: {
    category?: string[];
    min_priority?: number;
    recent_scans?: any[];
    recent_analyses?: any[];
  }): Promise<ImprovementSuggestion[]> {
    try {
      this.logger.info('Requesting improvement suggestions', {
        categories: context.category,
        min_priority: context.min_priority
      });

      const response = await this.client.post('/api/learning/suggestions', context);

      this.logger.info('Improvement suggestions retrieved', {
        suggestions_count: response.data.suggestions?.length || 0
      });

      return response.data.suggestions || [];
    } catch (error) {
      this.logger.error('Failed to get improvement suggestions', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Generate predictive threat model
   */
  async generateThreatModel(context: {
    target?: string;
    historical_scans: any[];
    current_vulnerabilities: any[];
    known_threats: any[];
    time_horizon?: string;
  }): Promise<PredictiveThreatModel[]> {
    try {
      this.logger.info('Generating predictive threat model', {
        target: context.target,
        historical_scans_count: context.historical_scans.length
      });

      const response = await this.client.post('/api/learning/predict', context);

      this.logger.info('Predictive threat models generated', {
        models_count: response.data.models?.length || 0
      });

      return response.data.models || [];
    } catch (error) {
      this.logger.error('Failed to generate threat model', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Validate and apply learning
   */
  async validateLearning(learningId: string, validation: {
    validated_by: string;
    approved: boolean;
    feedback?: string;
    apply_improvements?: boolean;
  }): Promise<{ success: boolean; improvements_applied?: string[] }> {
    try {
      this.logger.info('Validating learning', {
        learning_id: learningId,
        approved: validation.approved
      });

      const response = await this.client.post(`/api/learning/validate/${learningId}`, validation);

      this.logger.info('Learning validation completed', {
        learning_id: learningId,
        success: response.data.success
      });

      return response.data;
    } catch (error) {
      this.logger.error('Failed to validate learning', {
        learning_id: learningId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Get learning status
   */
  async getLearningStatus(learningId: string): Promise<LearningResponse> {
    try {
      const response = await this.client.get(`/api/learning/status/${learningId}`);
      return response.data;
    } catch (error) {
      this.logger.error('Failed to get learning status', {
        learning_id: learningId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Calculate success rate from scan results
   */
  private calculateSuccessRate(scanResults: any): number {
    const totalFindings = scanResults.findings.length;
    if (totalFindings === 0) return 1.0;

    const falsePositives = scanResults.false_positives || 0;
    const falseNegatives = scanResults.false_negatives || 0;
    const errors = falsePositives + falseNegatives;

    return Math.max(0, (totalFindings - errors) / totalFindings);
  }
}

/**
 * Singleton instance
 */
let learningAgentClient: LearningAgentClient | null = null;

/**
 * Get LearningAgent client instance
 */
export function getLearningAgentClient(): LearningAgentClient {
  if (!learningAgentClient) {
    learningAgentClient = new LearningAgentClient();
  }
  return learningAgentClient;
}
