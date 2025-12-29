/**
 * GraphRAG Client Unit Tests
 *
 * Tests for GraphRAG knowledge graph integration
 */

import axios from 'axios';
import { GraphRAGClient } from '../../../src/nexus/graphrag-client';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('GraphRAGClient', () => {
  let client: GraphRAGClient;
  const mockBaseUrl = 'http://localhost:9001';

  beforeEach(() => {
    client = new GraphRAGClient(mockBaseUrl);
    jest.clearAllMocks();
  });

  describe('Health Check', () => {
    it('should return healthy status when GraphRAG is available', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        status: 200,
        data: {
          status: 'healthy',
          version: '1.0.0'
        }
      });

      const health = await client.checkHealth();

      expect(health.healthy).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledWith(`${mockBaseUrl}/health`, {
        timeout: 5000
      });
    });

    it('should return unhealthy status when GraphRAG is unavailable', async () => {
      mockedAxios.get.mockRejectedValueOnce(new Error('Connection refused'));

      const health = await client.checkHealth();

      expect(health.healthy).toBe(false);
      expect(health.error).toContain('Connection refused');
    });
  });

  describe('Store Vulnerability', () => {
    it('should store vulnerability data successfully', async () => {
      const vulnerability = {
        id: 'vuln-123',
        name: 'SQL Injection',
        severity: 'critical',
        description: 'SQL injection vulnerability in login form',
        cvss_score: 9.8,
        affected_asset: 'web-app.example.com',
        remediation: 'Use parameterized queries'
      };

      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          entity_id: 'entity-vuln-123',
          success: true
        }
      });

      const entityId = await client.storeVulnerability(vulnerability);

      expect(entityId).toBe('entity-vuln-123');
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/entities`,
        expect.objectContaining({
          domain: 'security',
          entityType: 'vulnerability',
          textContent: expect.stringContaining('SQL Injection')
        }),
        expect.any(Object)
      );
    });

    it('should throw error when storage fails', async () => {
      const vulnerability = {
        id: 'vuln-456',
        name: 'XSS',
        severity: 'high'
      };

      mockedAxios.post.mockRejectedValueOnce(new Error('Storage failed'));

      await expect(client.storeVulnerability(vulnerability))
        .rejects
        .toThrow('Failed to store vulnerability');
    });
  });

  describe('Store IOCs', () => {
    it('should store indicators of compromise successfully', async () => {
      const iocs = {
        scan_id: 'scan-123',
        target: '192.168.1.100',
        iocs: [
          {
            type: 'ip',
            value: '10.0.0.5',
            confidence: 0.95,
            context: 'Suspicious outbound connection'
          },
          {
            type: 'domain',
            value: 'malicious.example.com',
            confidence: 0.98,
            context: 'Known C2 domain'
          }
        ],
        timestamp: new Date().toISOString()
      };

      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          entity_id: 'entity-iocs-123',
          success: true
        }
      });

      const entityId = await client.storeIOCs(iocs);

      expect(entityId).toBe('entity-iocs-123');
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/entities`,
        expect.objectContaining({
          domain: 'security',
          entityType: 'iocs',
          tags: expect.arrayContaining(['ip', 'domain'])
        }),
        expect.any(Object)
      );
    });
  });

  describe('Store Scan Results', () => {
    it('should store comprehensive scan results', async () => {
      const scanResults = {
        scan_id: 'scan-789',
        scan_type: 'port_scan',
        target: 'example.com',
        findings: [
          {
            title: 'Open SSH Port',
            severity: 'info',
            description: 'Port 22 is open'
          }
        ],
        statistics: {
          total_findings: 1,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 1
        }
      };

      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          entity_id: 'entity-scan-789',
          success: true
        }
      });

      const entityId = await client.storeScanResults(scanResults);

      expect(entityId).toBe('entity-scan-789');
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/entities`,
        expect.objectContaining({
          domain: 'security',
          entityType: 'scan_results'
        }),
        expect.any(Object)
      );
    });
  });

  describe('Store Malware Analysis', () => {
    it('should store malware analysis results', async () => {
      const malwareAnalysis = {
        sample_hash: 'abc123def456',
        file_name: 'malware.exe',
        file_type: 'PE32 executable',
        file_size: 1024000,
        analysis_results: {
          is_malicious: true,
          confidence: 0.95,
          malware_family: 'TrickBot',
          threat_level: 'critical'
        },
        static_analysis: {
          suspicious_imports: ['CreateRemoteThread', 'VirtualAllocEx']
        },
        dynamic_analysis: {
          network_connections: [
            { ip: '10.0.0.1', port: 443, protocol: 'TCP' }
          ]
        }
      };

      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          entity_id: 'entity-malware-abc123',
          success: true
        }
      });

      const entityId = await client.storeMalwareAnalysis(malwareAnalysis);

      expect(entityId).toBe('entity-malware-abc123');
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/entities`,
        expect.objectContaining({
          domain: 'security',
          entityType: 'malware_analysis',
          tags: expect.arrayContaining(['TrickBot', 'critical'])
        }),
        expect.any(Object)
      );
    });
  });

  describe('Query Threat Intelligence', () => {
    it('should retrieve relevant threat intelligence', async () => {
      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          results: [
            {
              entity_id: 'entity-1',
              content: 'Known malware family: TrickBot',
              score: 0.95,
              metadata: {
                entity_type: 'malware_analysis',
                malware_family: 'TrickBot'
              }
            },
            {
              entity_id: 'entity-2',
              content: 'C2 domain: malicious.example.com',
              score: 0.88,
              metadata: {
                entity_type: 'iocs',
                ioc_type: 'domain'
              }
            }
          ]
        }
      });

      const results = await client.queryThreatIntel('TrickBot malware', 10);

      expect(results).toHaveLength(2);
      expect(results[0].content).toContain('TrickBot');
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/query`,
        expect.objectContaining({
          query: 'TrickBot malware',
          limit: 10
        }),
        expect.any(Object)
      );
    });

    it('should return empty array when no results found', async () => {
      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          results: []
        }
      });

      const results = await client.queryThreatIntel('nonexistent threat', 10);

      expect(results).toHaveLength(0);
    });

    it('should handle query errors gracefully', async () => {
      mockedAxios.post.mockRejectedValueOnce(new Error('Query failed'));

      await expect(client.queryThreatIntel('test query', 10))
        .rejects
        .toThrow('Failed to query threat intelligence');
    });
  });

  describe('Create Relationships', () => {
    it('should create relationships between entities', async () => {
      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          relationship_id: 'rel-123',
          success: true
        }
      });

      const relationshipId = await client.createRelationship(
        'entity-vuln-1',
        'entity-scan-1',
        'FOUND_IN',
        0.9
      );

      expect(relationshipId).toBe('rel-123');
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/relationships`,
        expect.objectContaining({
          source_entity_id: 'entity-vuln-1',
          target_entity_id: 'entity-scan-1',
          relationship_type: 'FOUND_IN',
          weight: 0.9
        }),
        expect.any(Object)
      );
    });
  });

  describe('Graph Traversal', () => {
    it('should traverse entity relationships', async () => {
      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          entities: [
            {
              entity_id: 'entity-1',
              content: 'Related entity 1',
              relationship: 'RELATED_TO'
            },
            {
              entity_id: 'entity-2',
              content: 'Related entity 2',
              relationship: 'CONNECTED_TO'
            }
          ]
        }
      });

      const results = await client.traverseGraph('entity-root', 2);

      expect(results).toHaveLength(2);
      expect(results[0].entity_id).toBe('entity-1');
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/graph/traverse`,
        expect.objectContaining({
          entity_id: 'entity-root',
          max_depth: 2
        }),
        expect.any(Object)
      );
    });
  });

  describe('Batch Operations', () => {
    it('should handle batch entity storage', async () => {
      const entities = [
        {
          domain: 'security',
          entityType: 'vulnerability',
          textContent: 'Vuln 1'
        },
        {
          domain: 'security',
          entityType: 'vulnerability',
          textContent: 'Vuln 2'
        }
      ];

      mockedAxios.post.mockResolvedValueOnce({
        status: 200,
        data: {
          entity_ids: ['entity-1', 'entity-2'],
          success: true
        }
      });

      const entityIds = await client.storeBatch(entities);

      expect(entityIds).toHaveLength(2);
      expect(mockedAxios.post).toHaveBeenCalledWith(
        `${mockBaseUrl}/api/v1/entities/batch`,
        expect.objectContaining({
          entities
        }),
        expect.any(Object)
      );
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      mockedAxios.post.mockRejectedValueOnce({
        code: 'ECONNREFUSED',
        message: 'Connection refused'
      });

      await expect(client.storeVulnerability({ id: 'test', name: 'test' }))
        .rejects
        .toThrow('Failed to store vulnerability');
    });

    it('should handle timeout errors', async () => {
      mockedAxios.post.mockRejectedValueOnce({
        code: 'ECONNABORTED',
        message: 'Timeout'
      });

      await expect(client.queryThreatIntel('test', 10))
        .rejects
        .toThrow();
    });

    it('should handle API errors with proper messages', async () => {
      mockedAxios.post.mockRejectedValueOnce({
        response: {
          status: 400,
          data: {
            error: 'Invalid entity data'
          }
        }
      });

      await expect(client.storeVulnerability({ id: 'invalid' }))
        .rejects
        .toThrow();
    });
  });
});
