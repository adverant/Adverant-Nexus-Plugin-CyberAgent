/**
 * Base Repository
 *
 * Abstract base class for all database repositories with common CRUD operations
 * Includes automatic JSONB column serialization/deserialization
 */

import { PoolClient, QueryResult } from 'pg';
import { getDatabase } from '../connection';
import { QueryOptions, PaginationMetadata } from '../../types';
import { logger } from '../../utils/logger';

/**
 * Base Repository Abstract Class
 *
 * Provides common CRUD operations with automatic JSONB column handling.
 * Subclasses MUST implement getJsonbColumns() to declare which columns
 * need JSON serialization for PostgreSQL JSONB type.
 */
export abstract class BaseRepository<T> {
  protected tableName: string;

  constructor(tableName: string) {
    this.tableName = tableName;
  }

  /**
   * Subclasses MUST override to declare JSONB columns
   *
   * Returns array of column names that require JSON serialization.
   * These columns will be automatically JSON.stringify'd on write
   * and JSON.parse'd on read (if returned as string).
   *
   * @example
   * protected getJsonbColumns(): string[] {
   *   return ['tools', 'config', 'metadata'];
   * }
   */
  protected abstract getJsonbColumns(): string[];

  /**
   * Serialize a value for PostgreSQL if it's a JSONB column
   *
   * Arrays and objects are serialized to JSON strings for JSONB columns.
   * Other values pass through unchanged.
   */
  private serializeValue(key: string, value: any): any {
    if (value === null || value === undefined) {
      return value;
    }

    const jsonbColumns = this.getJsonbColumns();

    // Check if this column needs JSONB serialization
    if (jsonbColumns.includes(key)) {
      if (typeof value === 'object') {
        return JSON.stringify(value);
      }
    }

    return value;
  }

  /**
   * Deserialize JSONB columns from database results
   *
   * The pg driver may already parse JSONB to objects, but we handle
   * the string case for safety (e.g., when using raw queries).
   */
  protected deserializeRow(row: any): T {
    if (!row) return row;

    const jsonbColumns = this.getJsonbColumns();
    const result = { ...row };

    for (const column of jsonbColumns) {
      if (result[column] !== undefined && result[column] !== null) {
        // pg driver may already parse JSONB, but handle string case
        if (typeof result[column] === 'string') {
          try {
            result[column] = JSON.parse(result[column]);
          } catch (e) {
            // Keep as-is if not valid JSON (shouldn't happen for JSONB columns)
            logger.warn(`Failed to parse JSONB column ${column}`, {
              table: this.tableName,
              value: String(result[column]).substring(0, 50)
            });
          }
        }
      }
    }

    return result as T;
  }

  /**
   * Deserialize multiple rows
   */
  protected deserializeRows(rows: any[]): T[] {
    return rows.map(row => this.deserializeRow(row));
  }

  /**
   * Execute a query with automatic error handling
   */
  protected async query<R = any>(text: string, params?: any[]): Promise<QueryResult<R>> {
    const db = getDatabase();
    return db.query<R>(text, params);
  }

  /**
   * Execute queries within a transaction
   */
  protected async transaction<R>(callback: (client: PoolClient) => Promise<R>): Promise<R> {
    const db = getDatabase();
    return db.transaction(callback);
  }

  /**
   * Find record by ID
   */
  async findById(id: string): Promise<T | null> {
    try {
      const result = await this.query<T>(
        `SELECT * FROM ${this.tableName} WHERE id = $1 LIMIT 1`,
        [id]
      );

      return result.rows[0] ? this.deserializeRow(result.rows[0]) : null;
    } catch (error) {
      logger.error(`Error finding record by ID in ${this.tableName}`, {
        id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Find all records with optional filtering and pagination
   */
  async findAll(options: QueryOptions = {}): Promise<T[]> {
    try {
      const { limit = 20, offset = 0, orderBy = 'created_at', orderDirection = 'DESC' } = options;

      const query = `
        SELECT * FROM ${this.tableName}
        ORDER BY ${orderBy} ${orderDirection}
        LIMIT $1 OFFSET $2
      `;

      const result = await this.query<T>(query, [limit, offset]);
      return this.deserializeRows(result.rows);
    } catch (error) {
      logger.error(`Error finding all records in ${this.tableName}`, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Count total records
   */
  async count(whereClause?: string, params?: any[]): Promise<number> {
    try {
      const query = whereClause
        ? `SELECT COUNT(*) FROM ${this.tableName} WHERE ${whereClause}`
        : `SELECT COUNT(*) FROM ${this.tableName}`;

      const result = await this.query<{ count: string }>(query, params);
      return parseInt(result.rows[0].count, 10);
    } catch (error) {
      logger.error(`Error counting records in ${this.tableName}`, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Create a new record
   *
   * Automatically serializes JSONB columns before INSERT
   */
  async create(data: Partial<T>): Promise<T> {
    try {
      const keys = Object.keys(data).filter(key => data[key as keyof T] !== undefined);

      // Serialize JSONB columns
      const values = keys.map(key => this.serializeValue(key, data[key as keyof T]));
      const placeholders = keys.map((_, index) => `$${index + 1}`);

      const query = `
        INSERT INTO ${this.tableName} (${keys.join(', ')})
        VALUES (${placeholders.join(', ')})
        RETURNING *
      `;

      const jsonbColumnsUsed = this.getJsonbColumns().filter(c => keys.includes(c));
      if (jsonbColumnsUsed.length > 0) {
        logger.debug('BaseRepository.create with JSONB columns', {
          table: this.tableName,
          jsonbColumns: jsonbColumnsUsed
        });
      }

      const result = await this.query<T>(query, values);
      return this.deserializeRow(result.rows[0]);
    } catch (error) {
      logger.error(`Error creating record in ${this.tableName}`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        data: JSON.stringify(data).substring(0, 200)
      });
      throw error;
    }
  }

  /**
   * Update a record by ID
   *
   * Automatically serializes JSONB columns before UPDATE
   */
  async update(id: string, data: Partial<T>): Promise<T | null> {
    try {
      const keys = Object.keys(data).filter(key => data[key as keyof T] !== undefined);

      // Serialize JSONB columns
      const values = keys.map(key => this.serializeValue(key, data[key as keyof T]));
      const setClause = keys.map((key, index) => `${key} = $${index + 2}`).join(', ');

      if (keys.length === 0) {
        return this.findById(id);
      }

      const query = `
        UPDATE ${this.tableName}
        SET ${setClause}
        WHERE id = $1
        RETURNING *
      `;

      const result = await this.query<T>(query, [id, ...values]);
      return result.rows[0] ? this.deserializeRow(result.rows[0]) : null;
    } catch (error) {
      logger.error(`Error updating record in ${this.tableName}`, {
        id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Delete a record by ID
   */
  async delete(id: string): Promise<boolean> {
    try {
      const result = await this.query(
        `DELETE FROM ${this.tableName} WHERE id = $1`,
        [id]
      );

      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      logger.error(`Error deleting record in ${this.tableName}`, {
        id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Find records with custom WHERE clause
   */
  async findWhere(whereClause: string, params: any[], options: QueryOptions = {}): Promise<T[]> {
    try {
      const { limit = 20, offset = 0, orderBy = 'created_at', orderDirection = 'DESC' } = options;

      const query = `
        SELECT * FROM ${this.tableName}
        WHERE ${whereClause}
        ORDER BY ${orderBy} ${orderDirection}
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
      `;

      const result = await this.query<T>(query, [...params, limit, offset]);
      return this.deserializeRows(result.rows);
    } catch (error) {
      logger.error(`Error finding records with WHERE clause in ${this.tableName}`, {
        whereClause,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Build pagination metadata
   */
  protected buildPaginationMetadata(
    total: number,
    limit: number,
    offset: number
  ): PaginationMetadata {
    return {
      total,
      limit,
      offset,
      hasMore: offset + limit < total
    };
  }

  /**
   * Check if record exists
   */
  async exists(id: string): Promise<boolean> {
    try {
      const result = await this.query<{ exists: boolean }>(
        `SELECT EXISTS(SELECT 1 FROM ${this.tableName} WHERE id = $1)`,
        [id]
      );

      return result.rows[0].exists;
    } catch (error) {
      logger.error(`Error checking record existence in ${this.tableName}`, {
        id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Bulk insert records
   *
   * Automatically serializes JSONB columns for each record
   */
  async bulkCreate(records: Partial<T>[]): Promise<T[]> {
    if (records.length === 0) return [];

    try {
      return await this.transaction(async (client) => {
        const results: T[] = [];

        for (const record of records) {
          const keys = Object.keys(record).filter(key => record[key as keyof T] !== undefined);

          // Serialize JSONB columns
          const values = keys.map(key => this.serializeValue(key, record[key as keyof T]));
          const placeholders = keys.map((_, index) => `$${index + 1}`);

          const query = `
            INSERT INTO ${this.tableName} (${keys.join(', ')})
            VALUES (${placeholders.join(', ')})
            RETURNING *
          `;

          const result = await client.query<T>(query, values);
          results.push(this.deserializeRow(result.rows[0]));
        }

        return results;
      });
    } catch (error) {
      logger.error(`Error bulk creating records in ${this.tableName}`, {
        count: records.length,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }
}
