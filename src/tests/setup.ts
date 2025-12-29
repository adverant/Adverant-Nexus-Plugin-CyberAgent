/**
 * Jest Test Setup
 *
 * Global test setup and teardown
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';
process.env.ENCRYPTION_MASTER_KEY = 'test-master-key-32-bytes-long!!';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/nexus_test';
process.env.REDIS_URL = 'redis://localhost:6379/1';
process.env.GRAPHRAG_API_URL = 'http://localhost:9001';
process.env.MAGEAGENT_API_URL = 'http://localhost:9002';
process.env.ORCHESTRATIONAGENT_API_URL = 'http://localhost:9003';
process.env.LEARNINGAGENT_API_URL = 'http://localhost:9004';
process.env.SPECTRUMAGENT_API_URL = 'http://localhost:9005';

// Mock external services by default
jest.mock('axios');
jest.mock('bullmq');
jest.mock('pg');
jest.mock('ioredis');

// Global test timeout
jest.setTimeout(30000);

// Setup global test utilities
global.console = {
  ...console,
  error: jest.fn(),
  warn: jest.fn(),
  log: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

// Clean up after all tests
afterAll(async () => {
  // Close any open connections
  await new Promise(resolve => setTimeout(resolve, 500));
});
