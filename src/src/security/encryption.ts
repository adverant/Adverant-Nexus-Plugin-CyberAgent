/**
 * Encryption Service
 *
 * Provides encryption/decryption for sensitive data at rest
 * Uses AES-256-GCM for symmetric encryption
 */

import * as crypto from 'crypto';
import { Logger, createContextLogger} from '../utils/logger';

const logger = createContextLogger('EncryptionService');

/**
 * Encryption algorithm
 */
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // For GCM mode
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 64;

/**
 * Encryption result
 */
export interface EncryptedData {
  encrypted: string; // Base64 encoded
  iv: string; // Base64 encoded initialization vector
  authTag: string; // Base64 encoded authentication tag
  salt: string; // Base64 encoded salt
}

/**
 * Encryption Service
 */
export class EncryptionService {
  private masterKey: Buffer;

  constructor(masterKeyHex?: string) {
    // In production, master key should come from environment variable or key management service
    this.masterKey = masterKeyHex
      ? Buffer.from(masterKeyHex, 'hex')
      : Buffer.from(process.env.ENCRYPTION_MASTER_KEY || this.generateMasterKey(), 'hex');

    if (this.masterKey.length !== 32) {
      throw new Error('Master key must be 256 bits (32 bytes)');
    }

    logger.info('Encryption service initialized', {
      algorithm: ALGORITHM,
      key_length: this.masterKey.length * 8
    });
  }

  /**
   * Encrypt sensitive data
   */
  encrypt(plaintext: string): EncryptedData {
    try {
      // Generate random IV
      const iv = crypto.randomBytes(IV_LENGTH);

      // Generate random salt
      const salt = crypto.randomBytes(SALT_LENGTH);

      // Derive encryption key from master key and salt
      const key = this.deriveKey(salt);

      // Create cipher
      const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

      // Encrypt data
      let encrypted = cipher.update(plaintext, 'utf8', 'base64');
      encrypted += cipher.final('base64');

      // Get authentication tag
      const authTag = cipher.getAuthTag();

      return {
        encrypted,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        salt: salt.toString('base64')
      };
    } catch (error) {
      logger.error('Encryption failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypt encrypted data
   */
  decrypt(encryptedData: EncryptedData): string {
    try {
      // Decode base64 values
      const encrypted = encryptedData.encrypted;
      const iv = Buffer.from(encryptedData.iv, 'base64');
      const authTag = Buffer.from(encryptedData.authTag, 'base64');
      const salt = Buffer.from(encryptedData.salt, 'base64');

      // Derive encryption key from master key and salt
      const key = this.deriveKey(salt);

      // Create decipher
      const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);

      // Decrypt data
      let decrypted = decipher.update(encrypted, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      logger.error('Decryption failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Encrypt object (serialize to JSON first)
   */
  encryptObject(obj: any): EncryptedData {
    const jsonString = JSON.stringify(obj);
    return this.encrypt(jsonString);
  }

  /**
   * Decrypt object (parse JSON after decryption)
   */
  decryptObject<T = any>(encryptedData: EncryptedData): T {
    const decrypted = this.decrypt(encryptedData);
    return JSON.parse(decrypted);
  }

  /**
   * Hash sensitive data (one-way, for comparison)
   */
  hash(data: string, salt?: string): { hash: string; salt: string } {
    const saltBuffer = salt ? Buffer.from(salt, 'hex') : crypto.randomBytes(32);
    const hash = crypto.scryptSync(data, saltBuffer, 64).toString('hex');

    return {
      hash,
      salt: saltBuffer.toString('hex')
    };
  }

  /**
   * Verify hashed data
   */
  verifyHash(data: string, hash: string, salt: string): boolean {
    const computed = this.hash(data, salt);
    return computed.hash === hash;
  }

  /**
   * Generate random token (for API keys, etc.)
   */
  generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Derive encryption key from master key and salt
   */
  private deriveKey(salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(this.masterKey, salt, 100000, 32, 'sha256');
  }

  /**
   * Generate new master key (for initialization)
   */
  private generateMasterKey(): string {
    const key = crypto.randomBytes(32);
    logger.warn('Generated new master key - SAVE THIS KEY SECURELY', {
      key: key.toString('hex')
    });
    return key.toString('hex');
  }
}

/**
 * Field-level encryption for database models
 */
export class FieldEncryption {
  private encryptionService: EncryptionService;

  constructor(encryptionService?: EncryptionService) {
    this.encryptionService = encryptionService || new EncryptionService();
  }

  /**
   * Encrypt field before storage
   */
  encryptField(value: string): string {
    if (!value) return value;

    const encrypted = this.encryptionService.encrypt(value);
    // Store as JSON string
    return JSON.stringify(encrypted);
  }

  /**
   * Decrypt field after retrieval
   */
  decryptField(encryptedValue: string): string {
    if (!encryptedValue) return encryptedValue;

    try {
      const encrypted: EncryptedData = JSON.parse(encryptedValue);
      return this.encryptionService.decrypt(encrypted);
    } catch (error) {
      logger.error('Failed to decrypt field', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return '';
    }
  }

  /**
   * Check if field is encrypted
   */
  isEncrypted(value: string): boolean {
    if (!value) return false;

    try {
      const parsed = JSON.parse(value);
      return parsed.encrypted && parsed.iv && parsed.authTag && parsed.salt;
    } catch {
      return false;
    }
  }
}

/**
 * Sensitive data fields that should be encrypted
 */
export const SENSITIVE_FIELDS = {
  // User data
  user_email: true,
  user_phone: true,
  user_address: true,

  // Credentials
  api_key: true,
  api_secret: true,
  password: true, // Should be hashed, not encrypted
  token: true,

  // Scan data
  scan_credentials: true,
  ssh_key: true,
  private_key: true,

  // Malware samples
  malware_sample: true, // Binary data

  // Reports with PII
  report_content: false, // Usually not needed unless contains PII

  // Workflow secrets
  workflow_credentials: true,
  webhook_secret: true
};

/**
 * Singleton instance
 */
let encryptionService: EncryptionService | null = null;

/**
 * Get encryption service instance
 */
export function getEncryptionService(): EncryptionService {
  if (!encryptionService) {
    encryptionService = new EncryptionService();
  }
  return encryptionService;
}

/**
 * Singleton field encryption instance
 */
let fieldEncryption: FieldEncryption | null = null;

/**
 * Get field encryption instance
 */
export function getFieldEncryption(): FieldEncryption {
  if (!fieldEncryption) {
    fieldEncryption = new FieldEncryption();
  }
  return fieldEncryption;
}
