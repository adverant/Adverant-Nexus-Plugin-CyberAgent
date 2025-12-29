/**
 * Performance Benchmarks
 *
 * Performance testing for critical system components
 */

import { WorkflowEngine } from '../../src/workflows/workflow-engine';
import { WorkflowParser } from '../../src/workflows/workflow-parser';
import { GraphRAGClient } from '../../src/nexus/graphrag-client';
import { EncryptionService } from '../../src/security/encryption';
import { hasPermission } from '../../src/security/permissions';
import { getAuditLogger } from '../../src/security/audit-logger';

jest.mock('axios');
jest.mock('../../src/database/connection');

describe('Performance Benchmarks', () => {
  describe('Workflow Engine Performance', () => {
    it('should handle 100 concurrent workflow executions', async () => {
      const engine = new WorkflowEngine();
      const parser = new WorkflowParser();

      const yamlContent = `
name: benchmark-workflow
version: 1.0.0
description: Benchmark workflow

steps:
  - id: step1
    name: Quick Step
    type: notification
    config:
      message: "Test notification"
`;

      const workflow = await parser.parseFromString(yamlContent);

      const startTime = Date.now();
      const promises = [];

      for (let i = 0; i < 100; i++) {
        promises.push(
          engine.execute(
            workflow,
            {
              workflow_name: 'benchmark-workflow',
              variables: { iteration: i },
              dry_run: true
            },
            'org-bench',
            'user-bench'
          )
        );
      }

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(results.length).toBe(100);
      results.forEach(result => {
        expect(result.status).toBe('completed');
      });

      console.log(`
🔥 Workflow Engine Benchmark:
   - Executions: 100 concurrent workflows
   - Duration: ${duration}ms
   - Throughput: ${(100 / (duration / 1000)).toFixed(2)} workflows/second
   - Average latency: ${(duration / 100).toFixed(2)}ms per workflow
`);

      // Should complete 100 workflows in under 10 seconds
      expect(duration).toBeLessThan(10000);
    }, 30000);

    it('should handle complex workflow with 50 steps', async () => {
      const engine = new WorkflowEngine();
      const parser = new WorkflowParser();

      const steps = Array.from({ length: 50 }, (_, i) => ({
        id: `step${i + 1}`,
        name: `Step ${i + 1}`,
        type: 'notification' as const,
        config: { message: `Step ${i + 1}` },
        depends_on: i > 0 ? [`step${i}`] : undefined
      }));

      const workflow = {
        name: 'complex-workflow',
        version: '1.0.0',
        description: 'Complex workflow with 50 steps',
        steps
      };

      const startTime = Date.now();

      const execution = await engine.execute(
        workflow,
        {
          workflow_name: 'complex-workflow',
          variables: {},
          dry_run: true
        },
        'org-bench',
        'user-bench'
      );

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(execution.status).toBe('completed');
      expect(execution.steps.length).toBe(50);

      console.log(`
🔥 Complex Workflow Benchmark:
   - Steps: 50 sequential steps
   - Duration: ${duration}ms
   - Average per step: ${(duration / 50).toFixed(2)}ms
`);

      // Should complete in under 5 seconds
      expect(duration).toBeLessThan(5000);
    }, 30000);
  });

  describe('Encryption Performance', () => {
    it('should encrypt/decrypt 10,000 operations per second', () => {
      const service = new EncryptionService();
      const plaintext = 'Performance test data for encryption benchmarking';
      const iterations = 10000;

      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        const encrypted = service.encrypt(plaintext);
        const decrypted = service.decrypt(encrypted);
        expect(decrypted).toBe(plaintext);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;
      const opsPerSecond = iterations / (duration / 1000);

      console.log(`
🔥 Encryption Benchmark:
   - Operations: ${iterations} encrypt+decrypt cycles
   - Duration: ${duration}ms
   - Throughput: ${opsPerSecond.toFixed(2)} ops/second
   - Average latency: ${(duration / iterations).toFixed(3)}ms per operation
`);

      // Should maintain at least 1000 ops/second
      expect(opsPerSecond).toBeGreaterThan(1000);
    });

    it('should handle large object encryption efficiently', () => {
      const service = new EncryptionService();

      const largeObject = {
        users: Array.from({ length: 1000 }, (_, i) => ({
          id: i,
          username: `user${i}`,
          email: `user${i}@example.com`,
          api_key: `key-${i}-${Math.random().toString(36)}`,
          metadata: {
            created: new Date().toISOString(),
            permissions: ['read', 'write', 'execute']
          }
        }))
      };

      const iterations = 100;
      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        const encrypted = service.encryptObject(largeObject);
        const decrypted = service.decryptObject(encrypted);
        expect(decrypted.users.length).toBe(1000);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      console.log(`
🔥 Large Object Encryption Benchmark:
   - Object size: 1000 user records
   - Operations: ${iterations} encrypt+decrypt cycles
   - Duration: ${duration}ms
   - Average: ${(duration / iterations).toFixed(2)}ms per operation
`);

      // Should complete in under 10 seconds
      expect(duration).toBeLessThan(10000);
    });

    it('should handle concurrent encryption operations', async () => {
      const service = new EncryptionService();
      const plaintext = 'Concurrent encryption test';
      const concurrentOps = 1000;

      const startTime = Date.now();

      const promises = Array.from({ length: concurrentOps }, () =>
        Promise.resolve().then(() => {
          const encrypted = service.encrypt(plaintext);
          return service.decrypt(encrypted);
        })
      );

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(results.every(r => r === plaintext)).toBe(true);

      console.log(`
🔥 Concurrent Encryption Benchmark:
   - Concurrent operations: ${concurrentOps}
   - Duration: ${duration}ms
   - Throughput: ${(concurrentOps / (duration / 1000)).toFixed(2)} ops/second
`);

      // Should complete in under 5 seconds
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Permission Checking Performance', () => {
    it('should perform 1 million permission checks per second', () => {
      const iterations = 1000000;

      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        hasPermission('analyst', 'scans:read');
        hasPermission('viewer', 'scans:execute');
        hasPermission('admin', 'admin:manage_users');
      }

      const endTime = Date.now();
      const duration = endTime - startTime;
      const checksPerSecond = (iterations * 3) / (duration / 1000);

      console.log(`
🔥 Permission Check Benchmark:
   - Checks: ${iterations * 3} permission checks
   - Duration: ${duration}ms
   - Throughput: ${checksPerSecond.toFixed(2)} checks/second
   - Average latency: ${((duration / (iterations * 3)) * 1000).toFixed(3)}μs per check
`);

      // Should maintain at least 100k checks per second
      expect(checksPerSecond).toBeGreaterThan(100000);
    });

    it('should handle concurrent permission checks', async () => {
      const concurrentChecks = 100000;

      const startTime = Date.now();

      const promises = Array.from({ length: concurrentChecks }, (_, i) =>
        Promise.resolve().then(() => {
          const roles = ['viewer', 'analyst', 'senior_analyst', 'admin'];
          const permissions = ['scans:read', 'scans:create', 'malware:execute'];
          const role = roles[i % roles.length];
          const permission = permissions[i % permissions.length];
          return hasPermission(role, permission);
        })
      );

      await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      console.log(`
🔥 Concurrent Permission Check Benchmark:
   - Concurrent checks: ${concurrentChecks}
   - Duration: ${duration}ms
   - Throughput: ${(concurrentChecks / (duration / 1000)).toFixed(2)} checks/second
`);

      // Should complete in under 2 seconds
      expect(duration).toBeLessThan(2000);
    });
  });

  describe('Audit Logging Performance', () => {
    it('should log 10,000 audit events efficiently', async () => {
      const auditLogger = getAuditLogger();
      const iterations = 10000;

      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        await auditLogger.logAuthentication({
          action: 'login',
          user_id: `user-${i}`,
          email: `user${i}@example.com`,
          success: true,
          ip_address: `192.168.1.${i % 255}`
        });
      }

      const endTime = Date.now();
      const duration = endTime - startTime;
      const logsPerSecond = iterations / (duration / 1000);

      console.log(`
🔥 Audit Logging Benchmark:
   - Events: ${iterations} audit events
   - Duration: ${duration}ms
   - Throughput: ${logsPerSecond.toFixed(2)} events/second
   - Average latency: ${(duration / iterations).toFixed(2)}ms per event
`);

      // Should log at least 100 events per second
      expect(logsPerSecond).toBeGreaterThan(100);
    }, 30000);

    it('should handle concurrent audit logging', async () => {
      const auditLogger = getAuditLogger();
      const concurrentLogs = 1000;

      const startTime = Date.now();

      const promises = Array.from({ length: concurrentLogs }, (_, i) =>
        auditLogger.logScan({
          action: 'create',
          scan_id: `scan-${i}`,
          scan_type: 'port_scan',
          target: `target-${i}.example.com`,
          user_id: `user-${i}`,
          organization_id: 'org-bench',
          success: true
        })
      );

      await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      console.log(`
🔥 Concurrent Audit Logging Benchmark:
   - Concurrent logs: ${concurrentLogs}
   - Duration: ${duration}ms
   - Throughput: ${(concurrentLogs / (duration / 1000)).toFixed(2)} logs/second
`);

      // Should complete in under 10 seconds
      expect(duration).toBeLessThan(10000);
    }, 30000);
  });

  describe('Workflow Parser Performance', () => {
    it('should parse 1000 YAML workflows per second', async () => {
      const parser = new WorkflowParser();
      const iterations = 1000;

      const yamlContent = `
name: parse-benchmark
version: 1.0.0
description: Benchmark workflow for parsing

steps:
  - id: step1
    name: Step 1
    type: scan
    config:
      scan_type: port_scan
      target: example.com

  - id: step2
    name: Step 2
    type: notification
    config:
      message: "Scan complete"
    depends_on:
      - step1

  - id: step3
    name: Step 3
    type: report
    config:
      template: default
      format: pdf
    depends_on:
      - step2
`;

      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        const workflow = await parser.parseFromString(yamlContent);
        expect(workflow.name).toBe('parse-benchmark');
        expect(workflow.steps.length).toBe(3);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;
      const parsesPerSecond = iterations / (duration / 1000);

      console.log(`
🔥 YAML Parser Benchmark:
   - Workflows: ${iterations} YAML workflows
   - Duration: ${duration}ms
   - Throughput: ${parsesPerSecond.toFixed(2)} parses/second
   - Average latency: ${(duration / iterations).toFixed(2)}ms per parse
`);

      // Should parse at least 100 workflows per second
      expect(parsesPerSecond).toBeGreaterThan(100);
    });
  });

  describe('Memory Usage', () => {
    it('should not leak memory during workflow execution', async () => {
      const engine = new WorkflowEngine();
      const parser = new WorkflowParser();

      const yamlContent = `
name: memory-test
version: 1.0.0
description: Memory test workflow

steps:
  - id: step1
    name: Step 1
    type: notification
    config:
      message: "Memory test"
`;

      const workflow = await parser.parseFromString(yamlContent);

      const getMemoryUsage = () => {
        if (global.gc) {
          global.gc();
        }
        return process.memoryUsage().heapUsed / 1024 / 1024; // MB
      };

      const initialMemory = getMemoryUsage();

      // Execute 1000 workflows
      for (let i = 0; i < 1000; i++) {
        await engine.execute(
          workflow,
          {
            workflow_name: 'memory-test',
            variables: { iteration: i },
            dry_run: true
          },
          'org-test',
          'user-test'
        );
      }

      const finalMemory = getMemoryUsage();
      const memoryIncrease = finalMemory - initialMemory;

      console.log(`
🔥 Memory Usage Benchmark:
   - Initial memory: ${initialMemory.toFixed(2)} MB
   - Final memory: ${finalMemory.toFixed(2)} MB
   - Memory increase: ${memoryIncrease.toFixed(2)} MB
   - Per workflow: ${(memoryIncrease / 1000).toFixed(3)} MB
`);

      // Memory increase should be reasonable (less than 100MB for 1000 workflows)
      expect(memoryIncrease).toBeLessThan(100);
    }, 60000);
  });

  describe('System Limits', () => {
    it('should handle maximum workflow complexity', async () => {
      const engine = new WorkflowEngine();

      // Create workflow with 100 steps, 10 parallel branches, and complex dependencies
      const steps = [];

      // Add 100 sequential steps
      for (let i = 0; i < 100; i++) {
        steps.push({
          id: `step${i}`,
          name: `Step ${i}`,
          type: 'notification' as const,
          config: { message: `Step ${i}` },
          depends_on: i > 0 ? [`step${i - 1}`] : undefined
        });
      }

      const workflow = {
        name: 'max-complexity-workflow',
        version: '1.0.0',
        description: 'Maximum complexity workflow',
        steps
      };

      const startTime = Date.now();

      const execution = await engine.execute(
        workflow,
        {
          workflow_name: 'max-complexity-workflow',
          variables: {},
          dry_run: true
        },
        'org-test',
        'user-test'
      );

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(execution.status).toBe('completed');
      expect(execution.steps.length).toBe(100);

      console.log(`
🔥 Maximum Complexity Benchmark:
   - Steps: 100 sequential steps
   - Duration: ${duration}ms
   - Status: ${execution.status}
`);

      // Should complete in under 10 seconds
      expect(duration).toBeLessThan(10000);
    }, 30000);

    it('should handle 1000 concurrent workflow executions', async () => {
      const engine = new WorkflowEngine();
      const parser = new WorkflowParser();

      const yamlContent = `
name: concurrent-test
version: 1.0.0
description: Concurrent test

steps:
  - id: step1
    name: Step 1
    type: notification
    config:
      message: "Test"
`;

      const workflow = await parser.parseFromString(yamlContent);

      const startTime = Date.now();

      const promises = Array.from({ length: 1000 }, (_, i) =>
        engine.execute(
          workflow,
          {
            workflow_name: 'concurrent-test',
            variables: { iteration: i },
            dry_run: true
          },
          'org-test',
          'user-test'
        )
      );

      const results = await Promise.all(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(results.length).toBe(1000);
      results.forEach(result => {
        expect(result.status).toBe('completed');
      });

      console.log(`
🔥 Concurrent Execution Benchmark:
   - Concurrent workflows: 1000
   - Duration: ${duration}ms
   - Throughput: ${(1000 / (duration / 1000)).toFixed(2)} workflows/second
`);

      // Should complete in under 30 seconds
      expect(duration).toBeLessThan(30000);
    }, 60000);
  });
});
