/**
 * GraphRAG Integration Client
 *
 * Stores security scan results, vulnerabilities, IOCs, and threat intelligence
 * in the GraphRAG knowledge graph for persistent memory and correlation
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import { Logger, createContextLogger } from '../utils/logger';
import config from '../config';

/**
 * Document storage request
 */
export interface StoreDocumentRequest {
  content: string;
  title: string;
  metadata: {
    type: 'vulnerability' | 'ioc' | 'scan_result' | 'malware_analysis' | 'threat_intel';
    scan_type?: string;
    job_id?: string;
    severity?: string;
    target?: string;
    tags?: string[];
    [key: string]: any;
  };
}

/**
 * Entity storage request
 */
export interface StoreEntityRequest {
  domain: 'security' | 'threat_intel' | 'malware' | 'vulnerability';
  entityType: string;
  textContent: string;
  tags: string[];
  hierarchyLevel?: number;
  metadata?: Record<string, any>;
}

/**
 * Memory storage request
 */
export interface StoreMemoryRequest {
  content: string;
  tags: string[];
  metadata: {
    importance: number; // 0.0 - 1.0
    context: string;
    job_id?: string;
    [key: string]: any;
  };
}

/**
 * Query request
 */
export interface QueryRequest {
  query: string;
  limit?: number;
  score_threshold?: number;
  filter?: Record<string, any>;
}

/**
 * GraphRAG Integration Client
 */
export class GraphRAGClient {
  private client: AxiosInstance;
  private logger: Logger;
  private graphragUrl: string;

  constructor() {
    this.graphragUrl = config.nexus?.graphrag?.url || 'http://nexus-graphrag:8090';
    this.logger = createContextLogger('GraphRAGClient');

    this.client = axios.create({
      baseURL: this.graphragUrl,
      timeout: 30000, // 30 second timeout
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Nexus-CyberAgent/1.0'
      }
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        this.logger.debug('GraphRAG API request', {
          method: config.method,
          url: config.url
        });
        return config;
      },
      (error) => {
        this.logger.error('GraphRAG API request error', { error: error.message });
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        this.logger.debug('GraphRAG API response', {
          status: response.status
        });
        return response;
      },
      (error: AxiosError) => {
        this.logger.error('GraphRAG API response error', {
          status: error.response?.status,
          message: error.message
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Store vulnerability finding
   */
  async storeVulnerability(vulnerability: {
    job_id: string;
    title: string;
    description: string;
    severity: string;
    target: string;
    cve_id?: string;
    cvss_score?: number;
    remediation?: string;
    evidence: any;
  }): Promise<string> {
    try {
      const document: StoreDocumentRequest = {
        content: this.formatVulnerability(vulnerability),
        title: `Vulnerability: ${vulnerability.title}`,
        metadata: {
          type: 'vulnerability',
          job_id: vulnerability.job_id,
          severity: vulnerability.severity,
          target: vulnerability.target,
          cve_id: vulnerability.cve_id,
          cvss_score: vulnerability.cvss_score,
          tags: ['vulnerability', vulnerability.severity, vulnerability.target]
        }
      };

      const response = await this.storeDocument(document);

      this.logger.info('Vulnerability stored in GraphRAG', {
        job_id: vulnerability.job_id,
        title: vulnerability.title,
        severity: vulnerability.severity
      });

      return response.document_id;
    } catch (error) {
      this.logger.error('Failed to store vulnerability in GraphRAG', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Store IOCs (Indicators of Compromise)
   */
  async storeIOCs(iocs: {
    analysis_id: string;
    malware_family?: string;
    threat_level: string;
    iocs: Record<string, string[]>;
    confidence_scores: Record<string, number>;
    yara_matches: string[];
  }): Promise<string> {
    try {
      const document: StoreDocumentRequest = {
        content: this.formatIOCs(iocs),
        title: `IOCs: ${iocs.malware_family || 'Unknown'} (${iocs.analysis_id})`,
        metadata: {
          type: 'ioc',
          job_id: iocs.analysis_id,
          malware_family: iocs.malware_family,
          threat_level: iocs.threat_level,
          tags: [
            'ioc',
            iocs.threat_level,
            iocs.malware_family || 'unknown',
            ...iocs.yara_matches.slice(0, 5)
          ]
        }
      };

      const response = await this.storeDocument(document);

      // Store individual IOCs as entities for better graph correlation
      await this.storeIOCEntities(iocs);

      this.logger.info('IOCs stored in GraphRAG', {
        analysis_id: iocs.analysis_id,
        malware_family: iocs.malware_family,
        total_iocs: Object.values(iocs.iocs).reduce((sum, arr) => sum + arr.length, 0)
      });

      return response.document_id;
    } catch (error) {
      this.logger.error('Failed to store IOCs in GraphRAG', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Store scan results
   */
  async storeScanResults(results: {
    job_id: string;
    scan_type: string;
    target: string;
    findings_count: number;
    summary: any;
  }): Promise<string> {
    try {
      const document: StoreDocumentRequest = {
        content: JSON.stringify(results.summary, null, 2),
        title: `Scan Results: ${results.scan_type} - ${results.target}`,
        metadata: {
          type: 'scan_result',
          scan_type: results.scan_type,
          job_id: results.job_id,
          target: results.target,
          findings_count: results.findings_count,
          tags: ['scan_result', results.scan_type, results.target]
        }
      };

      const response = await this.storeDocument(document);

      this.logger.info('Scan results stored in GraphRAG', {
        job_id: results.job_id,
        scan_type: results.scan_type,
        findings: results.findings_count
      });

      return response.document_id;
    } catch (error) {
      this.logger.error('Failed to store scan results in GraphRAG', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Store malware analysis results
   */
  async storeMalwareAnalysis(analysis: {
    analysis_id: string;
    sha256: string;
    malware_family?: string;
    threat_level: string;
    overall_score: number;
    key_findings: any[];
    recommendations: string[];
  }): Promise<string> {
    try {
      const document: StoreDocumentRequest = {
        content: this.formatMalwareAnalysis(analysis),
        title: `Malware Analysis: ${analysis.malware_family || analysis.sha256.substring(0, 16)}`,
        metadata: {
          type: 'malware_analysis',
          job_id: analysis.analysis_id,
          sha256: analysis.sha256,
          malware_family: analysis.malware_family,
          threat_level: analysis.threat_level,
          overall_score: analysis.overall_score,
          tags: [
            'malware',
            analysis.threat_level,
            analysis.malware_family || 'unknown'
          ]
        }
      };

      const response = await this.storeDocument(document);

      this.logger.info('Malware analysis stored in GraphRAG', {
        analysis_id: analysis.analysis_id,
        malware_family: analysis.malware_family,
        threat_level: analysis.threat_level
      });

      return response.document_id;
    } catch (error) {
      this.logger.error('Failed to store malware analysis in GraphRAG', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Query threat intelligence
   */
  async queryThreatIntel(query: string, limit: number = 10): Promise<any[]> {
    try {
      const response = await this.client.post('/api/query', {
        query,
        limit,
        score_threshold: 0.3,
        filter: {
          type: ['vulnerability', 'ioc', 'malware_analysis', 'threat_intel']
        }
      });

      this.logger.info('Threat intelligence queried', {
        query,
        results: response.data.results?.length || 0
      });

      return response.data.results || [];
    } catch (error) {
      this.logger.error('Failed to query threat intelligence', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Check if target has known vulnerabilities
   */
  async checkKnownVulnerabilities(target: string): Promise<any[]> {
    try {
      return await this.queryThreatIntel(
        `Known vulnerabilities or previous security findings for ${target}`,
        20
      );
    } catch (error) {
      this.logger.error('Failed to check known vulnerabilities', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Check if IOC is known malicious
   */
  async checkKnownIOC(ioc: string, iocType: string): Promise<any[]> {
    try {
      return await this.queryThreatIntel(
        `Known malicious ${iocType}: ${ioc}`,
        10
      );
    } catch (error) {
      this.logger.error('Failed to check known IOC', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Store document in GraphRAG
   */
  private async storeDocument(document: StoreDocumentRequest): Promise<{ document_id: string }> {
    try {
      const response = await this.client.post('/api/documents', document);
      return response.data;
    } catch (error) {
      this.logger.error('Failed to store document', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Store entity in knowledge graph
   */
  private async storeEntity(entity: StoreEntityRequest): Promise<{ entity_id: string }> {
    try {
      const response = await this.client.post('/api/entities', entity);
      return response.data;
    } catch (error) {
      this.logger.error('Failed to store entity', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Store IOCs as graph entities for correlation
   */
  private async storeIOCEntities(iocs: any): Promise<void> {
    try {
      // Store IP addresses
      for (const ip of iocs.iocs.ip || []) {
        await this.storeEntity({
          domain: 'threat_intel',
          entityType: 'malicious_ip',
          textContent: ip,
          tags: ['ioc', 'ip', iocs.threat_level],
          metadata: {
            malware_family: iocs.malware_family,
            confidence: iocs.confidence_scores.ip || 0.5
          }
        });
      }

      // Store domains
      for (const domain of iocs.iocs.domain || []) {
        await this.storeEntity({
          domain: 'threat_intel',
          entityType: 'malicious_domain',
          textContent: domain,
          tags: ['ioc', 'domain', iocs.threat_level],
          metadata: {
            malware_family: iocs.malware_family,
            confidence: iocs.confidence_scores.domain || 0.5
          }
        });
      }

      // Store hashes
      for (const hash of iocs.iocs.sha256 || []) {
        await this.storeEntity({
          domain: 'malware',
          entityType: 'malware_hash',
          textContent: hash,
          tags: ['ioc', 'hash', 'sha256', iocs.threat_level],
          metadata: {
            malware_family: iocs.malware_family,
            threat_level: iocs.threat_level
          }
        });
      }
    } catch (error) {
      this.logger.error('Failed to store IOC entities', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      // Don't throw - entity storage is supplementary
    }
  }

  /**
   * Format vulnerability for storage
   */
  private formatVulnerability(vuln: any): string {
    return `# ${vuln.title}

**Severity**: ${vuln.severity}
**Target**: ${vuln.target}
${vuln.cve_id ? `**CVE**: ${vuln.cve_id}` : ''}
${vuln.cvss_score ? `**CVSS Score**: ${vuln.cvss_score}` : ''}

## Description

${vuln.description || 'No description available'}

## Evidence

\`\`\`json
${JSON.stringify(vuln.evidence, null, 2)}
\`\`\`

${vuln.remediation ? `## Remediation\n\n${vuln.remediation}` : ''}
`;
  }

  /**
   * Format IOCs for storage
   */
  private formatIOCs(iocs: any): string {
    let content = `# Indicators of Compromise

**Malware Family**: ${iocs.malware_family || 'Unknown'}
**Threat Level**: ${iocs.threat_level}
**Analysis ID**: ${iocs.analysis_id}

## YARA Matches

${iocs.yara_matches.length > 0 ? iocs.yara_matches.join('\n- ') : 'None'}

## IOCs by Type

`;

    for (const [type, values] of Object.entries(iocs.iocs)) {
      if ((values as string[]).length > 0) {
        content += `### ${type.toUpperCase()}\n\n`;
        content += `- ${(values as string[]).join('\n- ')}\n\n`;
        content += `**Confidence**: ${iocs.confidence_scores[type] || 0.5}\n\n`;
      }
    }

    return content;
  }

  /**
   * Format malware analysis for storage
   */
  private formatMalwareAnalysis(analysis: any): string {
    return `# Malware Analysis Report

**SHA256**: ${analysis.sha256}
**Malware Family**: ${analysis.malware_family || 'Unknown'}
**Threat Level**: ${analysis.threat_level}
**Overall Score**: ${analysis.overall_score}/100

## Key Findings

${analysis.key_findings.map((f: any) => `- **${f.type}** (${f.severity}): ${f.description}`).join('\n')}

## Recommendations

${analysis.recommendations.map((r: string) => `- ${r}`).join('\n')}
`;
  }
}

/**
 * Singleton instance
 */
let graphragClient: GraphRAGClient | null = null;

/**
 * Get GraphRAG client instance
 */
export function getGraphRAGClient(): GraphRAGClient {
  if (!graphragClient) {
    graphragClient = new GraphRAGClient();
  }
  return graphragClient;
}
