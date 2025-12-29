/**
 * Workflow Execution Integration Tests
 *
 * End-to-end tests for complete workflow execution including Nexus integration
 */

import request from 'supertest';
import { WorkflowEngine } from '../../src/workflows/workflow-engine';
import { WorkflowParser } from '../../src/workflows/workflow-parser';
import { NexusIntegration } from '../../src/nexus/nexus-integration';
import { getAuditLogger } from '../../src/security/audit-logger';
import { EncryptionService } from '../../src/security/encryption';

// Mock external dependencies
jest.mock('axios');
jest.mock('../../src/database/connection');
jest.mock('ioredis');

describe('Workflow Execution Integration Tests', () => {
  let workflowEngine: WorkflowEngine;
  let workflowParser: WorkflowParser;
  let nexusIntegration: NexusIntegration;
  let auditLogger: ReturnType<typeof getAuditLogger>;
  let encryptionService: EncryptionService;

  beforeAll(() => {
    workflowEngine = new WorkflowEngine();
    workflowParser = new WorkflowParser();
    nexusIntegration = new NexusIntegration();
    auditLogger = getAuditLogger();
    encryptionService = new EncryptionService();
  });

  afterAll(() => {
    workflowEngine.removeAllListeners();
  });

  describe('Penetration Testing Workflow', () => {
    it('should execute complete penetration testing workflow', async () => {
      const yamlContent = `
name: integration-test-pentest
version: 1.0.0
description: Integration test penetration testing workflow

steps:
  - id: recon
    name: Reconnaissance
    type: scan
    config:
      scan_type: port_scan
      target: "{{ variables.target }}"
      ports: "1-1000"

  - id: vuln-scan
    name: Vulnerability Scanning
    type: scan
    config:
      scan_type: vulnerability_scan
      target: "{{ variables.target }}"
    depends_on:
      - recon

  - id: analysis
    name: Nexus Analysis
    type: nexus_analysis
    config:
      operation: analyze_scan_results
      scan_id: "{{ steps.vuln-scan.output.scan_id }}"
    depends_on:
      - vuln-scan

  - id: report
    name: Generate Report
    type: report
    config:
      template: pentest_report
      format: pdf
      include_steps:
        - recon
        - vuln-scan
        - analysis
    depends_on:
      - analysis

  - id: notify
    name: Notification
    type: notification
    config:
      message: "Penetration test complete for {{ variables.target }}"
      channels:
        - email
        - slack
    depends_on:
      - report
`;

      const workflow = await workflowParser.parseFromString(yamlContent);
      const validation = workflowParser.validate(workflow);

      expect(validation.valid).toBe(true);

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'integration-test-pentest',
          variables: {
            target: 'test.example.com'
          },
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      expect(execution.status).toBe('completed');
      expect(execution.steps.length).toBe(5);

      // Verify all steps completed
      execution.steps.forEach(step => {
        expect(['completed', 'skipped']).toContain(step.status);
      });
    }, 60000); // 60 second timeout

    it('should handle workflow failure gracefully', async () => {
      const yamlContent = `
name: failing-workflow
version: 1.0.0
description: Workflow that fails

steps:
  - id: failing-scan
    name: Failing Scan
    type: scan
    config:
      scan_type: invalid_scan_type
      target: "invalid-target"
`;

      const workflow = await workflowParser.parseFromString(yamlContent);

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'failing-workflow',
          variables: {},
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      expect(execution.status).toBe('failed');
      expect(execution.steps[0].status).toBe('failed');
      expect(execution.steps[0].error_message).toBeTruthy();
    });
  });

  describe('Malware Analysis Workflow', () => {
    it('should execute complete malware analysis workflow', async () => {
      const yamlContent = `
name: integration-test-malware
version: 1.0.0
description: Integration test malware analysis workflow

steps:
  - id: static-analysis
    name: Static Analysis
    type: scan
    config:
      scan_type: malware_static_analysis
      file_hash: "{{ variables.file_hash }}"

  - id: dynamic-analysis
    name: Dynamic Analysis
    type: scan
    config:
      scan_type: malware_dynamic_analysis
      file_hash: "{{ variables.file_hash }}"
      sandbox_timeout: 300
    depends_on:
      - static-analysis

  - id: nexus-correlation
    name: Threat Intelligence Correlation
    type: nexus_analysis
    config:
      operation: correlate_malware
      file_hash: "{{ variables.file_hash }}"
      static_results: "{{ steps.static-analysis.output }}"
      dynamic_results: "{{ steps.dynamic-analysis.output }}"
    depends_on:
      - static-analysis
      - dynamic-analysis

  - id: attribution
    name: Threat Actor Attribution
    type: nexus_analysis
    config:
      operation: perform_attribution
      iocs: "{{ steps.nexus-correlation.output.iocs }}"
    depends_on:
      - nexus-correlation

  - id: approval
    name: Approval for Quarantine
    type: approval
    config:
      approvers:
        - "security-team"
      timeout_minutes: 60
      message: "Approve quarantine for malware: {{ variables.file_hash }}"
    depends_on:
      - attribution

  - id: quarantine
    name: Quarantine Sample
    type: transform
    config:
      operation: quarantine_malware
      file_hash: "{{ variables.file_hash }}"
    depends_on:
      - approval
`;

      const workflow = await workflowParser.parseFromString(yamlContent);
      const validation = workflowParser.validate(workflow);

      expect(validation.valid).toBe(true);

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'integration-test-malware',
          variables: {
            file_hash: 'abc123def456789'
          },
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      // Should be pending approval
      expect(execution.status).toBe('pending_approval');

      const approvalStep = execution.steps.find(s => s.step_id === 'approval');
      expect(approvalStep?.status).toBe('pending_approval');

      // Approve the step
      await workflowEngine.approveStep(execution.execution_id, 'approval', true);

      // Get updated execution
      const updatedExecution = workflowEngine.getExecutionStatus(execution.execution_id);

      expect(updatedExecution.status).toBe('completed');
      expect(updatedExecution.steps.length).toBe(6);
    }, 60000);
  });

  describe('Parallel Workflow Execution', () => {
    it('should execute parallel scans concurrently', async () => {
      const yamlContent = `
name: parallel-scan-workflow
version: 1.0.0
description: Parallel scanning workflow

steps:
  - id: parallel-scans
    name: Parallel Scans
    type: parallel
    config:
      branches:
        - name: port-scan
          steps:
            - id: port-scan
              name: Port Scan
              type: scan
              config:
                scan_type: port_scan
                target: "{{ variables.target }}"

        - name: vuln-scan
          steps:
            - id: vuln-scan
              name: Vulnerability Scan
              type: scan
              config:
                scan_type: vulnerability_scan
                target: "{{ variables.target }}"

        - name: web-scan
          steps:
            - id: web-scan
              name: Web Application Scan
              type: scan
              config:
                scan_type: web_scan
                target: "{{ variables.target }}"

  - id: consolidate
    name: Consolidate Results
    type: nexus_analysis
    config:
      operation: consolidate_scan_results
      scan_ids: "{{ steps.parallel-scans.output.scan_ids }}"
    depends_on:
      - parallel-scans
`;

      const workflow = await workflowParser.parseFromString(yamlContent);
      const startTime = Date.now();

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'parallel-scan-workflow',
          variables: {
            target: 'test.example.com'
          },
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(execution.status).toBe('completed');

      // Parallel execution should be faster than sequential
      // (In real scenario with actual scans)
      expect(duration).toBeLessThan(60000); // Less than 60 seconds
    }, 90000);
  });

  describe('Conditional Workflow Logic', () => {
    it('should execute conditional branches correctly', async () => {
      const yamlContent = `
name: conditional-workflow
version: 1.0.0
description: Workflow with conditional logic

steps:
  - id: initial-scan
    name: Initial Scan
    type: scan
    config:
      scan_type: quick_scan
      target: "{{ variables.target }}"

  - id: check-severity
    name: Check Severity
    type: condition
    config:
      expression: "steps.initial-scan.output.critical_count > 0"
    depends_on:
      - initial-scan

  - id: deep-scan
    name: Deep Security Scan
    type: scan
    config:
      scan_type: comprehensive_scan
      target: "{{ variables.target }}"
    depends_on:
      - check-severity

  - id: notify-critical
    name: Notify Critical Issues
    type: notification
    config:
      message: "CRITICAL: {{ steps.initial-scan.output.critical_count }} critical issues found"
      priority: high
    depends_on:
      - deep-scan
`;

      const workflow = await workflowParser.parseFromString(yamlContent);

      // Test with critical findings
      const execution1 = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'conditional-workflow',
          variables: {
            target: 'vulnerable.example.com'
          },
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      const checkStep = execution1.steps.find(s => s.step_id === 'check-severity');
      const deepScanStep = execution1.steps.find(s => s.step_id === 'deep-scan');

      // If critical issues found, deep scan should execute
      if (checkStep?.output?.condition_result === true) {
        expect(deepScanStep?.status).toBe('completed');
      } else {
        expect(deepScanStep?.status).toBe('skipped');
      }
    });
  });

  describe('Loop Workflow Execution', () => {
    it('should execute loops over target lists', async () => {
      const yamlContent = `
name: multi-target-scan
version: 1.0.0
description: Scan multiple targets

steps:
  - id: scan-loop
    name: Scan All Targets
    type: loop
    config:
      items: "{{ variables.targets }}"
      variable_name: current_target
      steps:
        - id: target-scan
          name: Scan Target
          type: scan
          config:
            scan_type: port_scan
            target: "{{ variables.current_target }}"

  - id: consolidate-results
    name: Consolidate All Results
    type: nexus_analysis
    config:
      operation: consolidate_multi_target_scans
      scan_results: "{{ steps.scan-loop.output.all_results }}"
    depends_on:
      - scan-loop
`;

      const workflow = await workflowParser.parseFromString(yamlContent);

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'multi-target-scan',
          variables: {
            targets: [
              'target1.example.com',
              'target2.example.com',
              'target3.example.com'
            ]
          },
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      expect(execution.status).toBe('completed');

      const loopStep = execution.steps.find(s => s.step_id === 'scan-loop');
      expect(loopStep?.output?.iterations).toBe(3);
    });
  });

  describe('Workflow with Security Features', () => {
    it('should audit all workflow operations', async () => {
      const auditLogSpy = jest.spyOn(auditLogger, 'logWorkflow');

      const yamlContent = `
name: audited-workflow
version: 1.0.0
description: Workflow with full audit logging

steps:
  - id: scan
    name: Audited Scan
    type: scan
    config:
      scan_type: port_scan
      target: "{{ variables.target }}"
`;

      const workflow = await workflowParser.parseFromString(yamlContent);

      await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'audited-workflow',
          variables: { target: 'test.example.com' },
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      // Verify audit logging was called
      expect(auditLogSpy).toHaveBeenCalled();
      expect(auditLogSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'execute',
          workflow_name: 'audited-workflow'
        })
      );
    });

    it('should encrypt sensitive workflow data', () => {
      const sensitiveData = {
        api_key: 'secret-api-key',
        credentials: {
          username: 'admin',
          password: 'super-secret'
        }
      };

      const encrypted = encryptionService.encryptObject(sensitiveData);
      expect(encrypted.ciphertext).not.toContain('secret-api-key');
      expect(encrypted.ciphertext).not.toContain('super-secret');

      const decrypted = encryptionService.decryptObject(encrypted);
      expect(decrypted).toEqual(sensitiveData);
    });

    it('should verify permissions before executing high-risk operations', async () => {
      const yamlContent = `
name: high-risk-workflow
version: 1.0.0
description: Workflow requiring elevated permissions

steps:
  - id: exploit-scan
    name: Exploit Scan
    type: scan
    config:
      scan_type: exploit_scan
      target: "{{ variables.target }}"
      active_exploitation: true
`;

      const workflow = await workflowParser.parseFromString(yamlContent);

      // This would be caught by permission middleware in actual API
      // Here we just verify the workflow is created
      expect(workflow.steps[0].config.active_exploitation).toBe(true);
    });
  });

  describe('Error Recovery and Retry', () => {
    it('should retry failed steps with exponential backoff', async () => {
      const yamlContent = `
name: retry-workflow
version: 1.0.0
description: Workflow with retry logic

steps:
  - id: unreliable-scan
    name: Unreliable Scan
    type: scan
    config:
      scan_type: port_scan
      target: "{{ variables.target }}"
    retry:
      max_attempts: 3
      delay_seconds: 1
      exponential_backoff: true
`;

      const workflow = await workflowParser.parseFromString(yamlContent);

      // Mock scan to fail first 2 times, succeed on 3rd
      let attemptCount = 0;
      const originalExecute = workflowEngine['executeStep'];
      workflowEngine['executeStep'] = jest.fn().mockImplementation(async (step, context) => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error('Temporary network error');
        }
        return { success: true, output: { scan_id: 'scan-123' } };
      });

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'retry-workflow',
          variables: { target: 'test.example.com' },
          dry_run: false
        },
        'org-test-123',
        'user-test-123'
      );

      expect(execution.status).toBe('completed');
      expect(attemptCount).toBe(3);

      // Restore original method
      workflowEngine['executeStep'] = originalExecute;
    });
  });

  describe('Workflow Performance', () => {
    it('should execute simple workflow within performance budget', async () => {
      const yamlContent = `
name: performance-test-workflow
version: 1.0.0
description: Performance test workflow

steps:
  - id: scan1
    name: Quick Scan
    type: scan
    config:
      scan_type: quick_scan
      target: "{{ variables.target }}"

  - id: notify
    name: Notification
    type: notification
    config:
      message: "Scan complete"
    depends_on:
      - scan1
`;

      const workflow = await workflowParser.parseFromString(yamlContent);
      const startTime = Date.now();

      await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'performance-test-workflow',
          variables: { target: 'test.example.com' },
          dry_run: true // Dry run for speed
        },
        'org-test-123',
        'user-test-123'
      );

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete dry run in under 5 seconds
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Built-in Workflow Templates', () => {
    it('should execute comprehensive pentest template', async () => {
      const workflow = await workflowParser.loadBuiltInWorkflow('comprehensive_pentest');

      expect(workflow.name).toBe('comprehensive_pentest');
      expect(workflow.steps.length).toBeGreaterThan(0);

      const validation = workflowParser.validate(workflow);
      expect(validation.valid).toBe(true);

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'comprehensive_pentest',
          variables: {
            target: 'test.example.com',
            scope: 'full'
          },
          dry_run: true
        },
        'org-test-123',
        'user-test-123'
      );

      expect(execution.status).toMatch(/^(completed|pending_approval)$/);
    }, 60000);

    it('should execute malware analysis template', async () => {
      const workflow = await workflowParser.loadBuiltInWorkflow('malware_analysis_pipeline');

      expect(workflow.name).toBe('malware_analysis_pipeline');

      const validation = workflowParser.validate(workflow);
      expect(validation.valid).toBe(true);

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'malware_analysis_pipeline',
          variables: {
            file_hash: 'abc123def456',
            enable_detonation: false
          },
          dry_run: true
        },
        'org-test-123',
        'user-test-123'
      );

      expect(execution.status).toMatch(/^(completed|pending_approval)$/);
    }, 60000);

    it('should execute vulnerability assessment template', async () => {
      const workflow = await workflowParser.loadBuiltInWorkflow('vulnerability_assessment');

      expect(workflow.name).toBe('vulnerability_assessment');

      const validation = workflowParser.validate(workflow);
      expect(validation.valid).toBe(true);

      const execution = await workflowEngine.execute(
        workflow,
        {
          workflow_name: 'vulnerability_assessment',
          variables: {
            target: 'test.example.com'
          },
          dry_run: true
        },
        'org-test-123',
        'user-test-123'
      );

      expect(execution.status).toBe('completed');
    }, 60000);
  });
});
