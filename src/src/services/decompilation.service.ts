/**
 * Decompilation Service
 *
 * Provides binary reverse engineering and decompilation capabilities
 * using Radare2 (quick disassembly) and Ghidra (deep decompilation).
 *
 * Features:
 * - Function extraction and analysis
 * - Cross-reference analysis
 * - YARA match correlation to specific functions
 * - Control flow graph extraction
 * - String reference mapping
 */

import { Logger, createContextLogger } from '../utils/logger';
import { getDetonationChamberClient } from '../sandbox/detonation-chamber-client';
import config from '../config';

// ============================================================================
// Types
// ============================================================================

/**
 * Decompilation options
 */
export interface DecompilationOptions {
  /** Analysis depth: 'quick' uses Radare2, 'deep' uses Ghidra */
  depth: 'quick' | 'deep';
  /** Extract function list */
  extractFunctions?: boolean;
  /** Extract string references */
  extractStrings?: boolean;
  /** Extract cross-references */
  extractXrefs?: boolean;
  /** Timeout in seconds */
  timeout?: number;
  /** Maximum functions to analyze (for performance) */
  maxFunctions?: number;
  /** Specific function addresses to analyze (optional) */
  targetFunctions?: string[];
}

/**
 * Extracted function information
 */
export interface ExtractedFunction {
  /** Function name (or auto-generated) */
  name: string;
  /** Function address (hex) */
  address: string;
  /** Function size in bytes */
  size: number;
  /** Decompiled/disassembled code */
  code: string;
  /** Type of code: 'disassembly' or 'pseudocode' */
  codeType: 'disassembly' | 'pseudocode';
  /** Calling convention if detected */
  callingConvention?: string;
  /** Number of arguments */
  argumentCount?: number;
  /** Return type if detected */
  returnType?: string;
  /** Functions called by this function */
  callees?: string[];
  /** Functions that call this function */
  callers?: string[];
  /** String references within this function */
  stringRefs?: string[];
  /** Cyclomatic complexity estimate */
  complexity?: number;
  /** Suspicious indicators in this function */
  suspiciousIndicators?: string[];
}

/**
 * Malicious indicator location mapping
 */
export interface MaliciousLocation {
  /** YARA rule name or indicator type */
  indicator: string;
  /** Description of the malicious behavior */
  description: string;
  /** Severity level */
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Address where the indicator was found */
  address: string;
  /** Function containing this indicator (if resolved) */
  functionName?: string;
  /** Function address */
  functionAddress?: string;
  /** Matched content or pattern */
  matchedContent?: string;
  /** Confidence score (0-1) */
  confidence: number;
  /** Context snippet from decompiled code */
  codeContext?: string;
}

/**
 * Decompilation metadata
 */
export interface DecompilationMetadata {
  /** Tool used for decompilation */
  tool: 'radare2' | 'ghidra';
  /** Tool version */
  toolVersion?: string;
  /** Analysis duration in milliseconds */
  duration_ms: number;
  /** Total functions found */
  totalFunctions: number;
  /** Functions successfully analyzed */
  analyzedFunctions: number;
  /** Total string references found */
  totalStrings: number;
  /** Binary architecture */
  architecture?: string;
  /** Binary format (PE, ELF, etc.) */
  format?: string;
  /** Entry point address */
  entryPoint?: string;
  /** Analysis timestamp */
  timestamp: string;
}

/**
 * Complete decompilation result
 */
export interface DecompilationResult {
  /** Whether decompilation was successful */
  success: boolean;
  /** Error message if failed */
  error?: string;
  /** Decompilation metadata */
  metadata: DecompilationMetadata;
  /** Extracted functions */
  functions: ExtractedFunction[];
  /** Malicious indicator locations */
  maliciousLocations: MaliciousLocation[];
  /** All string references with their locations */
  strings?: Array<{
    value: string;
    address: string;
    referencedBy?: string[];
    type?: string;
  }>;
  /** Import table */
  imports?: Array<{
    library: string;
    function: string;
    address: string;
  }>;
  /** Export table */
  exports?: Array<{
    name: string;
    address: string;
    ordinal?: number;
  }>;
}

/**
 * YARA match for correlation
 */
export interface YaraMatch {
  rule: string;
  description?: string;
  severity?: string;
  offset?: number;
  matched?: string;
  strings?: Array<{
    identifier: string;
    offset: number;
    data: string;
  }>;
}

// ============================================================================
// Decompilation Service
// ============================================================================

/**
 * Decompilation Service
 *
 * Orchestrates binary analysis using Radare2 and Ghidra through
 * the Detonation Chamber API.
 */
export class DecompilationService {
  private logger: Logger;
  private detonationChamberUrl: string;

  constructor(detonationChamberUrl?: string) {
    this.logger = createContextLogger('DecompilationService');
    this.detonationChamberUrl = detonationChamberUrl ||
      config.sandboxes.tier3.url ||
      'http://nexus-cyberagent-detonation-chamber:9270';
  }

  /**
   * Decompile a binary file
   *
   * @param filePath - Path to the binary file (on the detonation chamber)
   * @param options - Decompilation options
   * @returns DecompilationResult with extracted functions and malicious locations
   */
  async decompileBinary(
    filePath: string,
    options: DecompilationOptions
  ): Promise<DecompilationResult> {
    const startTime = Date.now();

    this.logger.info('Starting binary decompilation', {
      filePath,
      depth: options.depth,
      maxFunctions: options.maxFunctions
    });

    try {
      const client = getDetonationChamberClient();
      let result: DecompilationResult;

      if (options.depth === 'quick') {
        // Use Radare2 for quick disassembly
        result = await this.decompileWithRadare2(filePath, options);
      } else {
        // Use Ghidra for deep decompilation
        result = await this.decompileWithGhidra(filePath, options);
      }

      const duration = Date.now() - startTime;
      result.metadata.duration_ms = duration;

      this.logger.info('Binary decompilation completed', {
        filePath,
        tool: result.metadata.tool,
        functionsAnalyzed: result.metadata.analyzedFunctions,
        maliciousLocations: result.maliciousLocations.length,
        duration_ms: duration
      });

      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      this.logger.error('Binary decompilation failed', {
        filePath,
        error: errorMessage,
        duration_ms: duration
      });

      return {
        success: false,
        error: errorMessage,
        metadata: {
          tool: options.depth === 'quick' ? 'radare2' : 'ghidra',
          duration_ms: duration,
          totalFunctions: 0,
          analyzedFunctions: 0,
          totalStrings: 0,
          timestamp: new Date().toISOString()
        },
        functions: [],
        maliciousLocations: []
      };
    }
  }

  /**
   * Decompile using Radare2 (quick disassembly)
   */
  private async decompileWithRadare2(
    filePath: string,
    options: DecompilationOptions
  ): Promise<DecompilationResult> {
    const client = getDetonationChamberClient();

    this.logger.debug('Calling Radare2 decompilation', { filePath });

    // Call detonation chamber Radare2 endpoint
    const response = await client.decompileRadare2(filePath, {
      extractFunctions: options.extractFunctions ?? true,
      extractStrings: options.extractStrings ?? true,
      extractXrefs: options.extractXrefs ?? false,
      maxFunctions: options.maxFunctions ?? 100,
      targetFunctions: options.targetFunctions,
      timeout: options.timeout ?? 120
    });

    // Transform response to our format
    const functions: ExtractedFunction[] = (response.functions || []).map((f: any) => ({
      name: f.name || `sub_${f.address}`,
      address: f.address,
      size: f.size || 0,
      code: f.disassembly || '',
      codeType: 'disassembly' as const,
      callingConvention: f.calling_convention,
      argumentCount: f.argc,
      callees: f.callees || [],
      callers: f.callers || [],
      stringRefs: f.string_refs || [],
      complexity: f.cyclomatic_complexity,
      suspiciousIndicators: this.detectSuspiciousIndicators(f.disassembly || '')
    }));

    return {
      success: true,
      metadata: {
        tool: 'radare2',
        toolVersion: response.tool_version,
        duration_ms: 0, // Will be set by caller
        totalFunctions: response.total_functions || functions.length,
        analyzedFunctions: functions.length,
        totalStrings: response.strings?.length || 0,
        architecture: response.architecture,
        format: response.format,
        entryPoint: response.entry_point,
        timestamp: new Date().toISOString()
      },
      functions,
      maliciousLocations: [], // Will be populated by correlation
      strings: response.strings,
      imports: response.imports,
      exports: response.exports
    };
  }

  /**
   * Decompile using Ghidra (deep decompilation with pseudocode)
   */
  private async decompileWithGhidra(
    filePath: string,
    options: DecompilationOptions
  ): Promise<DecompilationResult> {
    const client = getDetonationChamberClient();

    this.logger.debug('Calling Ghidra decompilation', { filePath });

    // Call detonation chamber Ghidra endpoint
    const response = await client.decompileGhidra(filePath, {
      extractFunctions: options.extractFunctions ?? true,
      extractStrings: options.extractStrings ?? true,
      extractXrefs: options.extractXrefs ?? true,
      maxFunctions: options.maxFunctions ?? 50,
      targetFunctions: options.targetFunctions,
      timeout: options.timeout ?? 300
    });

    // Transform response to our format
    const functions: ExtractedFunction[] = (response.functions || []).map((f: any) => ({
      name: f.name || `FUN_${f.address}`,
      address: f.address,
      size: f.size || 0,
      code: f.pseudocode || f.decompiled || '',
      codeType: 'pseudocode' as const,
      callingConvention: f.calling_convention,
      argumentCount: f.parameters?.length || 0,
      returnType: f.return_type,
      callees: f.callees || [],
      callers: f.callers || [],
      stringRefs: f.string_refs || [],
      complexity: f.cyclomatic_complexity,
      suspiciousIndicators: this.detectSuspiciousIndicators(f.pseudocode || f.decompiled || '')
    }));

    return {
      success: true,
      metadata: {
        tool: 'ghidra',
        toolVersion: response.tool_version,
        duration_ms: 0, // Will be set by caller
        totalFunctions: response.total_functions || functions.length,
        analyzedFunctions: functions.length,
        totalStrings: response.strings?.length || 0,
        architecture: response.architecture,
        format: response.format,
        entryPoint: response.entry_point,
        timestamp: new Date().toISOString()
      },
      functions,
      maliciousLocations: [], // Will be populated by correlation
      strings: response.strings,
      imports: response.imports,
      exports: response.exports
    };
  }

  /**
   * Correlate YARA matches to specific functions
   *
   * Maps YARA rule matches (with offsets) to the functions containing them,
   * creating a detailed map of malicious code locations.
   *
   * @param functions - Extracted functions from decompilation
   * @param yaraMatches - YARA matches from static analysis
   * @returns Array of malicious locations with function context
   */
  correlateYaraToFunctions(
    functions: ExtractedFunction[],
    yaraMatches: YaraMatch[]
  ): MaliciousLocation[] {
    const locations: MaliciousLocation[] = [];

    this.logger.debug('Correlating YARA matches to functions', {
      functionCount: functions.length,
      yaraMatchCount: yaraMatches.length
    });

    for (const match of yaraMatches) {
      // If we have string matches with offsets, try to correlate
      if (match.strings && match.strings.length > 0) {
        for (const stringMatch of match.strings) {
          const offset = stringMatch.offset;
          const containingFunction = this.findFunctionByOffset(functions, offset);

          locations.push({
            indicator: match.rule,
            description: match.description || `YARA rule ${match.rule} matched`,
            severity: this.mapSeverity(match.severity),
            address: `0x${offset.toString(16)}`,
            functionName: containingFunction?.name,
            functionAddress: containingFunction?.address,
            matchedContent: stringMatch.data,
            confidence: containingFunction ? 0.95 : 0.7,
            codeContext: containingFunction ?
              this.extractCodeContext(containingFunction.code, offset) : undefined
          });
        }
      } else if (match.offset !== undefined) {
        // Single offset match
        const containingFunction = this.findFunctionByOffset(functions, match.offset);

        locations.push({
          indicator: match.rule,
          description: match.description || `YARA rule ${match.rule} matched`,
          severity: this.mapSeverity(match.severity),
          address: `0x${match.offset.toString(16)}`,
          functionName: containingFunction?.name,
          functionAddress: containingFunction?.address,
          matchedContent: match.matched,
          confidence: containingFunction ? 0.95 : 0.7,
          codeContext: containingFunction ?
            this.extractCodeContext(containingFunction.code, match.offset) : undefined
        });
      } else {
        // No offset - try to match by content in function code
        for (const func of functions) {
          if (match.matched && func.code.includes(match.matched)) {
            locations.push({
              indicator: match.rule,
              description: match.description || `YARA rule ${match.rule} matched`,
              severity: this.mapSeverity(match.severity),
              address: func.address,
              functionName: func.name,
              functionAddress: func.address,
              matchedContent: match.matched,
              confidence: 0.8,
              codeContext: this.extractCodeContextByContent(func.code, match.matched)
            });
          }
        }
      }
    }

    // Also add locations for functions with suspicious indicators
    for (const func of functions) {
      if (func.suspiciousIndicators && func.suspiciousIndicators.length > 0) {
        for (const indicator of func.suspiciousIndicators) {
          // Check if this indicator is not already covered by a YARA match
          const alreadyCovered = locations.some(
            loc => loc.functionAddress === func.address &&
                   loc.indicator.toLowerCase().includes(indicator.toLowerCase())
          );

          if (!alreadyCovered) {
            locations.push({
              indicator: `SUSPICIOUS_${indicator.toUpperCase().replace(/\s+/g, '_')}`,
              description: `Suspicious pattern detected: ${indicator}`,
              severity: this.getSuspiciousIndicatorSeverity(indicator),
              address: func.address,
              functionName: func.name,
              functionAddress: func.address,
              confidence: 0.75
            });
          }
        }
      }
    }

    this.logger.info('YARA correlation completed', {
      totalLocations: locations.length,
      criticalCount: locations.filter(l => l.severity === 'critical').length,
      highCount: locations.filter(l => l.severity === 'high').length
    });

    return locations;
  }

  /**
   * Find the function containing a given offset
   */
  private findFunctionByOffset(
    functions: ExtractedFunction[],
    offset: number
  ): ExtractedFunction | undefined {
    // Convert hex address to number for comparison
    return functions.find(func => {
      const funcStart = parseInt(func.address.replace('0x', ''), 16);
      const funcEnd = funcStart + func.size;
      return offset >= funcStart && offset < funcEnd;
    });
  }

  /**
   * Extract code context around an offset
   */
  private extractCodeContext(code: string, offset: number): string {
    // Try to find a relevant section of code
    // This is approximate since we're working with decompiled output
    const lines = code.split('\n');
    const contextLines = 5;

    // Return first N lines as context if we can't pinpoint exact location
    return lines.slice(0, contextLines * 2).join('\n');
  }

  /**
   * Extract code context around matched content
   */
  private extractCodeContextByContent(code: string, content: string): string {
    const index = code.indexOf(content);
    if (index === -1) return code.substring(0, 200);

    const start = Math.max(0, index - 100);
    const end = Math.min(code.length, index + content.length + 100);
    return code.substring(start, end);
  }

  /**
   * Detect suspicious indicators in code
   */
  private detectSuspiciousIndicators(code: string): string[] {
    const indicators: string[] = [];
    const lowerCode = code.toLowerCase();

    // Process injection
    if (/createremotethread|virtualallocex|writeprocessmemory/i.test(code)) {
      indicators.push('process_injection');
    }

    // Anti-debugging
    if (/isdebuggerpresent|ntqueryinformationprocess|checkremotedebugger/i.test(code)) {
      indicators.push('anti_debugging');
    }

    // Registry manipulation
    if (/regsetvalue|regcreatekey|regdeletekey/i.test(code)) {
      indicators.push('registry_manipulation');
    }

    // Network operations
    if (/wsastartup|socket|connect|send|recv|internetopen|httpsendrequestx/i.test(code)) {
      indicators.push('network_activity');
    }

    // Cryptography
    if (/cryptencrypt|cryptdecrypt|bcrypt|aes|rijndael/i.test(code)) {
      indicators.push('cryptographic_operations');
    }

    // File operations
    if (/createfile|writefile|deletefile|copyfile|movefile/i.test(code)) {
      indicators.push('file_operations');
    }

    // Service manipulation
    if (/createservice|startservice|openscmanager/i.test(code)) {
      indicators.push('service_manipulation');
    }

    // Shellcode patterns
    if (/\x90\x90\x90|\xcc\xcc\xcc|nop.*nop.*nop/i.test(code)) {
      indicators.push('possible_shellcode');
    }

    // Dynamic loading
    if (/loadlibrary|getprocaddress|ntdll|kernel32/i.test(code)) {
      indicators.push('dynamic_loading');
    }

    return indicators;
  }

  /**
   * Map severity string to type
   */
  private mapSeverity(severity?: string): MaliciousLocation['severity'] {
    if (!severity) return 'medium';

    const lower = severity.toLowerCase();
    if (lower === 'critical') return 'critical';
    if (lower === 'high') return 'high';
    if (lower === 'medium') return 'medium';
    if (lower === 'low') return 'low';
    return 'info';
  }

  /**
   * Get severity for suspicious indicators
   */
  private getSuspiciousIndicatorSeverity(indicator: string): MaliciousLocation['severity'] {
    const highSeverity = ['process_injection', 'anti_debugging', 'possible_shellcode'];
    const mediumSeverity = ['registry_manipulation', 'service_manipulation', 'cryptographic_operations'];

    if (highSeverity.includes(indicator)) return 'high';
    if (mediumSeverity.includes(indicator)) return 'medium';
    return 'low';
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let decompilationServiceInstance: DecompilationService | null = null;

/**
 * Get DecompilationService singleton instance
 */
export function getDecompilationService(): DecompilationService {
  if (!decompilationServiceInstance) {
    decompilationServiceInstance = new DecompilationService();
  }
  return decompilationServiceInstance;
}
