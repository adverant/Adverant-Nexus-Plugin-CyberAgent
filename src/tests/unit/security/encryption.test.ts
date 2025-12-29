/**
 * Encryption Service Unit Tests
 *
 * Tests for AES-256-GCM encryption and hashing
 */

import { EncryptionService } from '../../../src/security/encryption';

describe('EncryptionService', () => {
  let service: EncryptionService;

  beforeEach(() => {
    // Use a test key
    process.env.ENCRYPTION_MASTER_KEY = 'test-master-key-32-bytes-long!!';
    service = new EncryptionService();
  });

  describe('Encryption and Decryption', () => {
    it('should encrypt and decrypt plaintext successfully', () => {
      const plaintext = 'Sensitive data that needs encryption';

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext for same plaintext', () => {
      const plaintext = 'Same plaintext';

      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      // Different IVs should produce different ciphertext
      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);

      // But both should decrypt to same plaintext
      expect(service.decrypt(encrypted1)).toBe(plaintext);
      expect(service.decrypt(encrypted2)).toBe(plaintext);
    });

    it('should handle empty string encryption', () => {
      const plaintext = '';

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle unicode characters', () => {
      const plaintext = '🔒 Encrypted: 日本語 中文 العربية';

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle very long strings', () => {
      const plaintext = 'A'.repeat(100000); // 100KB of data

      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should include authentication tag', () => {
      const plaintext = 'Authenticated encryption';

      const encrypted = service.encrypt(plaintext);

      expect(encrypted).toHaveProperty('auth_tag');
      expect(encrypted.auth_tag).toBeTruthy();
      expect(encrypted.auth_tag.length).toBeGreaterThan(0);
    });

    it('should fail decryption with tampered ciphertext', () => {
      const plaintext = 'Original message';
      const encrypted = service.encrypt(plaintext);

      // Tamper with ciphertext
      const tamperedData = {
        ...encrypted,
        ciphertext: Buffer.from(encrypted.ciphertext, 'base64')
          .toString('hex')
          .replace('a', 'b')
      };

      expect(() => service.decrypt(tamperedData as any)).toThrow();
    });

    it('should fail decryption with tampered auth tag', () => {
      const plaintext = 'Original message';
      const encrypted = service.encrypt(plaintext);

      // Tamper with auth tag
      const tamperedData = {
        ...encrypted,
        auth_tag: encrypted.auth_tag.replace('a', 'b')
      };

      expect(() => service.decrypt(tamperedData)).toThrow();
    });
  });

  describe('Object Encryption', () => {
    it('should encrypt and decrypt objects', () => {
      const obj = {
        username: 'testuser',
        password: 'secret123',
        api_key: 'abc-def-ghi',
        metadata: {
          created_at: new Date().toISOString(),
          permissions: ['read', 'write']
        }
      };

      const encrypted = service.encryptObject(obj);
      const decrypted = service.decryptObject(encrypted);

      expect(decrypted).toEqual(obj);
    });

    it('should handle nested objects', () => {
      const obj = {
        level1: {
          level2: {
            level3: {
              secret: 'deeply nested secret'
            }
          }
        }
      };

      const encrypted = service.encryptObject(obj);
      const decrypted = service.decryptObject(encrypted);

      expect(decrypted).toEqual(obj);
    });

    it('should handle arrays in objects', () => {
      const obj = {
        items: ['item1', 'item2', 'item3'],
        numbers: [1, 2, 3, 4, 5]
      };

      const encrypted = service.encryptObject(obj);
      const decrypted = service.decryptObject(encrypted);

      expect(decrypted).toEqual(obj);
    });

    it('should handle null and undefined values', () => {
      const obj = {
        null_value: null,
        undefined_value: undefined,
        normal_value: 'test'
      };

      const encrypted = service.encryptObject(obj);
      const decrypted = service.decryptObject(encrypted);

      expect(decrypted.null_value).toBeNull();
      expect(decrypted.undefined_value).toBeUndefined();
      expect(decrypted.normal_value).toBe('test');
    });

    it('should preserve data types', () => {
      const obj = {
        string: 'text',
        number: 42,
        boolean: true,
        null_val: null,
        array: [1, 2, 3],
        nested: { key: 'value' }
      };

      const encrypted = service.encryptObject(obj);
      const decrypted = service.decryptObject(encrypted);

      expect(typeof decrypted.string).toBe('string');
      expect(typeof decrypted.number).toBe('number');
      expect(typeof decrypted.boolean).toBe('boolean');
      expect(decrypted.null_val).toBeNull();
      expect(Array.isArray(decrypted.array)).toBe(true);
      expect(typeof decrypted.nested).toBe('object');
    });
  });

  describe('Hashing', () => {
    it('should hash data consistently', () => {
      const data = 'password123';

      const hash1 = service.hash(data);
      const hash2 = service.hash(data, hash1.salt);

      expect(hash1.hash).toBe(hash2.hash);
      expect(hash1.salt).toBe(hash2.salt);
    });

    it('should produce different hashes with different salts', () => {
      const data = 'password123';

      const hash1 = service.hash(data);
      const hash2 = service.hash(data);

      expect(hash1.hash).not.toBe(hash2.hash);
      expect(hash1.salt).not.toBe(hash2.salt);
    });

    it('should verify correct hash', () => {
      const data = 'correct_password';
      const { hash, salt } = service.hash(data);

      const isValid = service.verifyHash(data, hash, salt);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect hash', () => {
      const data = 'correct_password';
      const { hash, salt } = service.hash(data);

      const isValid = service.verifyHash('wrong_password', hash, salt);

      expect(isValid).toBe(false);
    });

    it('should produce fixed-length hashes', () => {
      const data1 = 'short';
      const data2 = 'A'.repeat(10000);

      const hash1 = service.hash(data1);
      const hash2 = service.hash(data2);

      // Both should produce same length hashes
      expect(hash1.hash.length).toBe(hash2.hash.length);
    });

    it('should handle empty string hashing', () => {
      const data = '';
      const { hash, salt } = service.hash(data);

      expect(hash).toBeTruthy();
      expect(salt).toBeTruthy();
      expect(service.verifyHash(data, hash, salt)).toBe(true);
    });

    it('should handle unicode characters in hashing', () => {
      const data = '🔐 パスワード 密码';
      const { hash, salt } = service.hash(data);

      expect(service.verifyHash(data, hash, salt)).toBe(true);
    });
  });

  describe('Key Derivation', () => {
    it('should derive encryption key from master key', () => {
      // This is tested indirectly through encryption/decryption
      const plaintext = 'Test data';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should use consistent key derivation', () => {
      const plaintext = 'Test data';

      // Create two service instances with same master key
      const service1 = new EncryptionService();
      const service2 = new EncryptionService();

      const encrypted = service1.encrypt(plaintext);
      const decrypted = service2.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('Error Handling', () => {
    it('should throw error when decrypting invalid data', () => {
      const invalidData = {
        ciphertext: 'invalid',
        iv: 'invalid',
        auth_tag: 'invalid'
      };

      expect(() => service.decrypt(invalidData)).toThrow();
    });

    it('should throw error when decrypting with wrong key', () => {
      const plaintext = 'Secret data';
      const encrypted = service.encrypt(plaintext);

      // Change master key
      process.env.ENCRYPTION_MASTER_KEY = 'different-master-key-32-bytes!';
      const service2 = new EncryptionService();

      expect(() => service2.decrypt(encrypted)).toThrow();
    });

    it('should handle missing encryption fields', () => {
      const incompleteData = {
        ciphertext: 'test'
        // Missing iv and auth_tag
      };

      expect(() => service.decrypt(incompleteData as any)).toThrow();
    });

    it('should handle malformed base64 data', () => {
      const malformedData = {
        ciphertext: 'not-valid-base64!!!',
        iv: 'also-invalid!!!',
        auth_tag: 'invalid!!!'
      };

      expect(() => service.decrypt(malformedData)).toThrow();
    });
  });

  describe('Master Key Management', () => {
    it('should throw error when master key is missing', () => {
      delete process.env.ENCRYPTION_MASTER_KEY;

      expect(() => new EncryptionService()).toThrow('ENCRYPTION_MASTER_KEY environment variable is required');
    });

    it('should accept master key from environment', () => {
      process.env.ENCRYPTION_MASTER_KEY = 'env-master-key-32-bytes-long!!';

      const service = new EncryptionService();
      const plaintext = 'Test data';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should use provided master key over environment', () => {
      process.env.ENCRYPTION_MASTER_KEY = 'env-key-32-bytes-long-string!!';
      const customKey = 'custom-key-32-bytes-long-str!!';

      const service = new EncryptionService(customKey);
      const plaintext = 'Test data';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('Performance', () => {
    it('should encrypt/decrypt reasonably fast', () => {
      const plaintext = 'Performance test data';
      const iterations = 1000;

      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        const encrypted = service.encrypt(plaintext);
        service.decrypt(encrypted);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete 1000 iterations in under 5 seconds
      expect(duration).toBeLessThan(5000);
    });

    it('should handle bulk object encryption', () => {
      const objects = Array.from({ length: 100 }, (_, i) => ({
        id: i,
        data: `Secret data ${i}`,
        metadata: { index: i }
      }));

      const startTime = Date.now();

      const encrypted = objects.map(obj => service.encryptObject(obj));
      const decrypted = encrypted.map(enc => service.decryptObject(enc));

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete in reasonable time (under 1 second)
      expect(duration).toBeLessThan(1000);
      expect(decrypted).toEqual(objects);
    });
  });

  describe('Security Properties', () => {
    it('should use different IV for each encryption', () => {
      const plaintext = 'Same data';
      const encryptions = Array.from({ length: 100 }, () => service.encrypt(plaintext));

      const ivs = new Set(encryptions.map(e => e.iv));

      // All IVs should be unique
      expect(ivs.size).toBe(100);
    });

    it('should produce non-deterministic ciphertext', () => {
      const plaintext = 'Deterministic test';
      const encryptions = Array.from({ length: 100 }, () => service.encrypt(plaintext));

      const ciphertexts = new Set(encryptions.map(e => e.ciphertext));

      // All ciphertexts should be unique due to random IVs
      expect(ciphertexts.size).toBe(100);
    });

    it('should include authentication in encryption', () => {
      const plaintext = 'Authenticated encryption test';
      const encrypted = service.encrypt(plaintext);

      // Auth tag should be present
      expect(encrypted.auth_tag).toBeTruthy();

      // Auth tag should be base64 encoded
      expect(() => Buffer.from(encrypted.auth_tag, 'base64')).not.toThrow();
    });
  });
});
