/**
 * Static Analyzer Service
 *
 * Built-in file analysis capabilities that don't require external sandbox.
 * Provides lightweight security analysis using Node.js native capabilities.
 *
 * Features:
 * - File type detection via magic bytes
 * - Entropy analysis (detect packed/encrypted content)
 * - String extraction
 * - Hash calculation (MD5, SHA1, SHA256)
 * - Suspicious pattern detection
 * - PE/ELF header parsing (basic)
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { createContextLogger, Logger } from '../utils/logger';

// ============================================================================
// Types
// ============================================================================

export interface FileAnalysisResult {
  success: boolean;
  file: {
    path: string;
    name: string;
    size: number;
    hashes: FileHashes;
  };
  detection: {
    fileType: DetectedFileType;
    isSuspicious: boolean;
    suspicionReasons: string[];
    threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  };
  analysis: {
    entropy: EntropyAnalysis;
    strings: StringAnalysis;
    headers: HeaderAnalysis | null;
    patterns: PatternMatch[];
  };
  metadata: {
    analyzedAt: string;
    duration_ms: number;
    analyzerVersion: string;
  };
}

export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface DetectedFileType {
  mime: string;
  extension: string;
  description: string;
  category: 'executable' | 'document' | 'archive' | 'script' | 'data' | 'unknown';
}

export interface EntropyAnalysis {
  overall: number;
  sections: SectionEntropy[];
  isPacked: boolean;
  isEncrypted: boolean;
}

export interface SectionEntropy {
  offset: number;
  size: number;
  entropy: number;
}

export interface StringAnalysis {
  totalStrings: number;
  suspiciousStrings: SuspiciousString[];
  urls: string[];
  ips: string[];
  emails: string[];
  registryKeys: string[];
  filePaths: string[];
}

export interface SuspiciousString {
  value: string;
  type: string;
  context: string;
}

export interface HeaderAnalysis {
  type: 'pe' | 'elf' | 'macho' | 'unknown';
  architecture?: string;
  timestamp?: string;
  sections?: string[];
  imports?: string[];
  exports?: string[];
}

export interface PatternMatch {
  rule: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  offset?: number;
  matched?: string;
}

// ============================================================================
// Magic Bytes Database
// ============================================================================

const MAGIC_SIGNATURES: Array<{
  bytes: number[];
  mime: string;
  extension: string;
  description: string;
  category: DetectedFileType['category'];
}> = [
  // Executables
  { bytes: [0x4D, 0x5A], mime: 'application/x-msdownload', extension: 'exe', description: 'Windows Executable', category: 'executable' },
  { bytes: [0x7F, 0x45, 0x4C, 0x46], mime: 'application/x-elf', extension: 'elf', description: 'ELF Executable', category: 'executable' },
  { bytes: [0xCF, 0xFA, 0xED, 0xFE], mime: 'application/x-mach-binary', extension: 'macho', description: 'Mach-O Executable (64-bit)', category: 'executable' },
  { bytes: [0xCE, 0xFA, 0xED, 0xFE], mime: 'application/x-mach-binary', extension: 'macho', description: 'Mach-O Executable (32-bit)', category: 'executable' },
  { bytes: [0xCA, 0xFE, 0xBA, 0xBE], mime: 'application/x-mach-binary', extension: 'macho', description: 'Mach-O Universal Binary', category: 'executable' },

  // Archives
  { bytes: [0x50, 0x4B, 0x03, 0x04], mime: 'application/zip', extension: 'zip', description: 'ZIP Archive', category: 'archive' },
  { bytes: [0x50, 0x4B, 0x05, 0x06], mime: 'application/zip', extension: 'zip', description: 'ZIP Archive (empty)', category: 'archive' },
  { bytes: [0x50, 0x4B, 0x07, 0x08], mime: 'application/zip', extension: 'zip', description: 'ZIP Archive (spanned)', category: 'archive' },
  { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], mime: 'application/x-rar-compressed', extension: 'rar', description: 'RAR Archive', category: 'archive' },
  { bytes: [0x1F, 0x8B], mime: 'application/gzip', extension: 'gz', description: 'GZIP Archive', category: 'archive' },
  { bytes: [0x42, 0x5A, 0x68], mime: 'application/x-bzip2', extension: 'bz2', description: 'BZIP2 Archive', category: 'archive' },
  { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], mime: 'application/x-7z-compressed', extension: '7z', description: '7-Zip Archive', category: 'archive' },
  { bytes: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], mime: 'application/x-xz', extension: 'xz', description: 'XZ Archive', category: 'archive' },

  // Documents
  { bytes: [0x25, 0x50, 0x44, 0x46], mime: 'application/pdf', extension: 'pdf', description: 'PDF Document', category: 'document' },
  { bytes: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], mime: 'application/msword', extension: 'doc', description: 'Microsoft Office Document', category: 'document' },

  // Scripts
  { bytes: [0x23, 0x21], mime: 'text/x-shellscript', extension: 'sh', description: 'Shell Script', category: 'script' },

  // Java
  { bytes: [0xCA, 0xFE, 0xBA, 0xBE], mime: 'application/java-archive', extension: 'class', description: 'Java Class File', category: 'executable' },

  // Images (could contain embedded malware)
  { bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], mime: 'image/png', extension: 'png', description: 'PNG Image', category: 'data' },
  { bytes: [0xFF, 0xD8, 0xFF], mime: 'image/jpeg', extension: 'jpg', description: 'JPEG Image', category: 'data' },
  { bytes: [0x47, 0x49, 0x46, 0x38], mime: 'image/gif', extension: 'gif', description: 'GIF Image', category: 'data' },
];

// ============================================================================
// Suspicious Patterns
// ============================================================================

const SUSPICIOUS_PATTERNS: Array<{
  pattern: RegExp;
  rule: string;
  description: string;
  severity: PatternMatch['severity'];
}> = [
  // Network indicators
  { pattern: /\b(?:powershell|cmd)\.exe\b/gi, rule: 'SHELL_COMMAND', description: 'Windows shell command reference', severity: 'medium' },
  { pattern: /\b(?:wget|curl)\s+http/gi, rule: 'DOWNLOAD_COMMAND', description: 'Download command detected', severity: 'medium' },
  { pattern: /base64\s*[_-]?(?:decode|encode)/gi, rule: 'BASE64_USAGE', description: 'Base64 encoding/decoding', severity: 'low' },
  { pattern: /eval\s*\(/gi, rule: 'EVAL_FUNCTION', description: 'Dynamic code execution (eval)', severity: 'high' },
  { pattern: /exec\s*\(/gi, rule: 'EXEC_FUNCTION', description: 'Process execution function', severity: 'high' },

  // Registry manipulation
  { pattern: /HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)/gi, rule: 'REGISTRY_ACCESS', description: 'Windows Registry access', severity: 'medium' },
  { pattern: /RegSetValue|RegCreateKey|RegDeleteKey/gi, rule: 'REGISTRY_MODIFICATION', description: 'Registry modification API', severity: 'high' },

  // Process manipulation
  { pattern: /CreateRemoteThread|VirtualAllocEx|WriteProcessMemory/gi, rule: 'PROCESS_INJECTION', description: 'Process injection technique', severity: 'critical' },
  { pattern: /NtCreateThreadEx|RtlCreateUserThread/gi, rule: 'THREAD_CREATION', description: 'Low-level thread creation', severity: 'high' },

  // Anti-analysis
  { pattern: /IsDebuggerPresent|CheckRemoteDebugger/gi, rule: 'ANTI_DEBUG', description: 'Anti-debugging technique', severity: 'high' },
  { pattern: /VirtualBox|VMware|QEMU|Xen/gi, rule: 'VM_DETECTION', description: 'Virtual machine detection', severity: 'medium' },

  // Persistence mechanisms
  { pattern: /\\CurrentVersion\\Run\\?/gi, rule: 'AUTORUN_REGISTRY', description: 'Autorun registry key', severity: 'high' },
  { pattern: /schtasks\s+\/create/gi, rule: 'SCHEDULED_TASK', description: 'Scheduled task creation', severity: 'high' },

  // Crypto indicators
  { pattern: /AES|DES|RSA|Rijndael|CryptoAPI/gi, rule: 'CRYPTO_USAGE', description: 'Cryptographic API usage', severity: 'low' },
  { pattern: /bitcoin|monero|ethereum|wallet/gi, rule: 'CRYPTO_CURRENCY', description: 'Cryptocurrency reference', severity: 'medium' },

  // C2 indicators
  { pattern: /beacon|callback|c2|command.{0,20}control/gi, rule: 'C2_INDICATOR', description: 'Command and control indicator', severity: 'critical' },
  { pattern: /mimikatz|lazagne|hashdump/gi, rule: 'CREDENTIAL_TOOL', description: 'Credential harvesting tool reference', severity: 'critical' },

  // Data exfiltration
  { pattern: /exfil|upload.{0,20}data|send.{0,20}file/gi, rule: 'EXFILTRATION', description: 'Data exfiltration indicator', severity: 'high' },

  // Obfuscation
  { pattern: /(?:[A-Za-z0-9+\/]{50,}={0,2})/g, rule: 'LONG_BASE64', description: 'Long Base64 string (possible obfuscation)', severity: 'low' },

  // ============================================================================
  // C2 Framework Detection Patterns
  // ============================================================================

  // Cobalt Strike indicators
  { pattern: /sleeptime|sleep_time|SLEEP_TIME/gi, rule: 'CS_SLEEPTIME', description: 'Cobalt Strike beacon sleep configuration', severity: 'critical' },
  { pattern: /\bjitter\b/gi, rule: 'CS_JITTER', description: 'Cobalt Strike beacon jitter configuration', severity: 'high' },
  { pattern: /beacon\.dll|beacon64\.dll/gi, rule: 'CS_BEACON_DLL', description: 'Cobalt Strike beacon DLL reference', severity: 'critical' },
  { pattern: /\bwatermark\b.*\d{8,}/gi, rule: 'CS_WATERMARK', description: 'Cobalt Strike watermark identifier', severity: 'critical' },
  { pattern: /cobaltstrike|cobalt.strike/gi, rule: 'CS_DIRECT', description: 'Direct Cobalt Strike reference', severity: 'critical' },
  { pattern: /\.\/\.\.\/\.\.\/\.\.\//gi, rule: 'CS_PATH_TRAVERSAL', description: 'Cobalt Strike path traversal pattern', severity: 'high' },
  { pattern: /ReflectiveLoader|reflective_load/gi, rule: 'CS_REFLECTIVE', description: 'Cobalt Strike reflective loader', severity: 'critical' },
  { pattern: /spawn(?:to|as)|spawnto_x86|spawnto_x64/gi, rule: 'CS_SPAWNTO', description: 'Cobalt Strike spawnto configuration', severity: 'high' },

  // Metasploit/Meterpreter indicators
  { pattern: /\bmeterpreter\b/gi, rule: 'MSF_METERPRETER', description: 'Metasploit Meterpreter reference', severity: 'critical' },
  { pattern: /\bmetsrv\b|metsrv\.dll/gi, rule: 'MSF_METSRV', description: 'Metasploit Meterpreter server DLL', severity: 'critical' },
  { pattern: /stdapi_/gi, rule: 'MSF_STDAPI', description: 'Metasploit standard API reference', severity: 'critical' },
  { pattern: /reverse_tcp|reverse_http|reverse_https/gi, rule: 'MSF_REVERSE', description: 'Metasploit reverse shell payload', severity: 'critical' },
  { pattern: /bind_tcp|bind_shell/gi, rule: 'MSF_BIND', description: 'Metasploit bind shell payload', severity: 'critical' },
  { pattern: /msfvenom|msfconsole|msfpayload/gi, rule: 'MSF_TOOL', description: 'Metasploit tool reference', severity: 'critical' },
  { pattern: /payload\/windows\/|payload\/linux\//gi, rule: 'MSF_PAYLOAD_PATH', description: 'Metasploit payload path pattern', severity: 'high' },

  // Empire indicators
  { pattern: /invoke-empire|invoke_empire/gi, rule: 'EMPIRE_INVOKE', description: 'Empire PowerShell C2 framework', severity: 'critical' },
  { pattern: /stager\.ps1|launcher\.ps1/gi, rule: 'EMPIRE_STAGER', description: 'Empire stager script reference', severity: 'critical' },
  { pattern: /empire\.db|empire_db/gi, rule: 'EMPIRE_DB', description: 'Empire database reference', severity: 'critical' },
  { pattern: /\[System\.Convert\]::FromBase64String\s*\(/gi, rule: 'EMPIRE_B64_DECODE', description: 'Empire-style Base64 PowerShell decode', severity: 'high' },
  { pattern: /Start-Negotiate|New-GPOImmediateTask/gi, rule: 'EMPIRE_MODULE', description: 'Empire module reference', severity: 'high' },

  // Sliver C2 indicators
  { pattern: /sliver-client|sliver_client/gi, rule: 'SLIVER_CLIENT', description: 'Sliver C2 client reference', severity: 'critical' },
  { pattern: /implant\.config|\.implant/gi, rule: 'SLIVER_IMPLANT', description: 'Sliver implant configuration', severity: 'critical' },
  { pattern: /mtls|wg|dns.*c2|http.*c2/gi, rule: 'SLIVER_TRANSPORT', description: 'Sliver transport protocol indicator', severity: 'high' },
  { pattern: /sliverarmory|sliver-armory/gi, rule: 'SLIVER_ARMORY', description: 'Sliver armory reference', severity: 'high' },

  // Brute Ratel C4 indicators
  { pattern: /bruteratel|brute.ratel|BRc4/gi, rule: 'BRC4_DIRECT', description: 'Brute Ratel C4 framework reference', severity: 'critical' },
  { pattern: /badger|bofloader/gi, rule: 'BRC4_COMPONENT', description: 'Brute Ratel component reference', severity: 'high' },

  // Havoc C2 indicators
  { pattern: /\bhavoc\b.*demon|demon.*havoc/gi, rule: 'HAVOC_C2', description: 'Havoc C2 framework reference', severity: 'critical' },
  { pattern: /teamserver.*havoc|havoc.*teamserver/gi, rule: 'HAVOC_TEAMSERVER', description: 'Havoc teamserver reference', severity: 'critical' },

  // Generic C2 network patterns
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b/g, rule: 'IP_PORT_COMBO', description: 'IP:Port combination (potential C2)', severity: 'medium' },
  { pattern: /\b[A-Za-z0-9-]+\.(?:duckdns|no-ip|ddns|dynu|freedns)\.[a-z]+\b/gi, rule: 'DDNS_C2', description: 'Dynamic DNS domain (common C2 technique)', severity: 'high' },
  { pattern: /\b[A-Za-z0-9]{20,}\.(?:com|net|org|io)\b/gi, rule: 'DGA_DOMAIN', description: 'Possible DGA-generated domain', severity: 'medium' },

  // DNS-based C2 patterns
  { pattern: /dns.{0,20}tunnel|tunnel.{0,20}dns/gi, rule: 'DNS_TUNNEL', description: 'DNS tunneling indicator', severity: 'critical' },
  { pattern: /\bTXT\b.*record.*data|dnscat|iodine|dns2tcp/gi, rule: 'DNS_C2_TOOL', description: 'DNS C2 tool reference', severity: 'critical' },
  { pattern: /(?:[A-Za-z0-9+\/]{50,})\.[a-z]{2,10}\.[a-z]{2,6}/gi, rule: 'DNS_ENCODED_DATA', description: 'Encoded data in DNS subdomain', severity: 'high' },

  // Paste site C2 patterns
  { pattern: /pastebin\.com\/raw|hastebin\.com\/raw|paste\.ee\/r/gi, rule: 'PASTE_C2_RAW', description: 'Paste site raw content URL (C2 technique)', severity: 'high' },
  { pattern: /ghostbin\.co|termbin\.com|dpaste\.org/gi, rule: 'PASTE_C2_SITE', description: 'Alternative paste site (C2 technique)', severity: 'high' },
  { pattern: /gist\.githubusercontent\.com.*raw/gi, rule: 'GIST_C2', description: 'GitHub Gist raw content (potential C2)', severity: 'medium' },
  { pattern: /transfer\.sh|file\.io|0x0\.st/gi, rule: 'FILE_SHARE_C2', description: 'File sharing service (potential C2 staging)', severity: 'medium' },

  // Cloud service C2 indicators
  { pattern: /discord(?:app)?\.com\/api\/webhooks/gi, rule: 'DISCORD_C2', description: 'Discord webhook C2 channel', severity: 'high' },
  { pattern: /api\.telegram\.org\/bot/gi, rule: 'TELEGRAM_C2', description: 'Telegram bot C2 channel', severity: 'high' },
  { pattern: /slack\.com\/api|hooks\.slack\.com/gi, rule: 'SLACK_C2', description: 'Slack webhook C2 channel', severity: 'high' },

  // HTTP-based C2 indicators
  { pattern: /\/check-in|\/beacon|\/heartbeat|\/callback/gi, rule: 'HTTP_C2_ENDPOINT', description: 'Common HTTP C2 endpoint pattern', severity: 'medium' },
  { pattern: /User-Agent.*(?:Mozilla\/4\.0|MSIE\s*6)/gi, rule: 'LEGACY_UA_C2', description: 'Suspicious legacy User-Agent (C2 indicator)', severity: 'medium' },
  { pattern: /\bpoll\b.*interval|\bbeacon\b.*interval/gi, rule: 'C2_POLLING', description: 'C2 polling interval configuration', severity: 'high' },
];

// ============================================================================
// Static Analyzer Service
// ============================================================================

export class StaticAnalyzerService {
  private logger: Logger;
  private readonly ANALYZER_VERSION = '1.0.0';
  private readonly ENTROPY_PACKED_THRESHOLD = 7.2;
  private readonly ENTROPY_ENCRYPTED_THRESHOLD = 7.8;
  private readonly STRING_MIN_LENGTH = 4;
  private readonly STRING_MAX_LENGTH = 500;

  constructor() {
    this.logger = createContextLogger('StaticAnalyzer');
  }

  /**
   * Analyze a file without requiring external sandbox
   */
  async analyzeFile(filePath: string): Promise<FileAnalysisResult> {
    const startTime = Date.now();
    this.logger.info('Starting static analysis', { filePath });

    try {
      // Verify file exists and is readable
      await fs.promises.access(filePath, fs.constants.R_OK);
      const stats = await fs.promises.stat(filePath);

      if (!stats.isFile()) {
        throw new Error(`Path is not a file: ${filePath}`);
      }

      // Read file content
      const buffer = await fs.promises.readFile(filePath);

      // Perform analysis
      const hashes = this.calculateHashes(buffer);
      const fileType = this.detectFileType(buffer);
      const entropy = this.analyzeEntropy(buffer);
      const strings = this.extractStrings(buffer);
      const headers = this.parseHeaders(buffer, fileType);
      const patterns = this.detectPatterns(buffer);

      // Determine threat level
      const { isSuspicious, suspicionReasons, threatLevel } = this.assessThreat(
        fileType,
        entropy,
        strings,
        patterns
      );

      const duration = Date.now() - startTime;

      const result: FileAnalysisResult = {
        success: true,
        file: {
          path: filePath,
          name: path.basename(filePath),
          size: stats.size,
          hashes,
        },
        detection: {
          fileType,
          isSuspicious,
          suspicionReasons,
          threatLevel,
        },
        analysis: {
          entropy,
          strings,
          headers,
          patterns,
        },
        metadata: {
          analyzedAt: new Date().toISOString(),
          duration_ms: duration,
          analyzerVersion: this.ANALYZER_VERSION,
        },
      };

      this.logger.info('Static analysis completed', {
        filePath,
        fileType: fileType.mime,
        threatLevel,
        isSuspicious,
        duration_ms: duration,
      });

      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      this.logger.error('Static analysis failed', {
        filePath,
        error: error instanceof Error ? error.message : 'Unknown error',
        duration_ms: duration,
      });

      throw error;
    }
  }

  /**
   * Calculate file hashes
   */
  private calculateHashes(buffer: Buffer): FileHashes {
    return {
      md5: crypto.createHash('md5').update(buffer).digest('hex'),
      sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
      sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    };
  }

  /**
   * Detect file type from magic bytes
   */
  private detectFileType(buffer: Buffer): DetectedFileType {
    for (const sig of MAGIC_SIGNATURES) {
      if (buffer.length >= sig.bytes.length) {
        let match = true;
        for (let i = 0; i < sig.bytes.length; i++) {
          if (buffer[i] !== sig.bytes[i]) {
            match = false;
            break;
          }
        }
        if (match) {
          return {
            mime: sig.mime,
            extension: sig.extension,
            description: sig.description,
            category: sig.category,
          };
        }
      }
    }

    // Fallback: check if it's likely text/ASCII
    const textChars = buffer.slice(0, Math.min(512, buffer.length))
      .filter(b => (b >= 0x20 && b <= 0x7E) || b === 0x09 || b === 0x0A || b === 0x0D);

    if (textChars.length > buffer.slice(0, 512).length * 0.85) {
      return {
        mime: 'text/plain',
        extension: 'txt',
        description: 'Text File',
        category: 'data',
      };
    }

    return {
      mime: 'application/octet-stream',
      extension: 'bin',
      description: 'Binary Data',
      category: 'unknown',
    };
  }

  /**
   * Analyze entropy (randomness) of file content
   */
  private analyzeEntropy(buffer: Buffer): EntropyAnalysis {
    const overall = this.calculateEntropy(buffer);
    const sections: SectionEntropy[] = [];

    // Analyze in 1KB sections
    const sectionSize = 1024;
    for (let offset = 0; offset < buffer.length; offset += sectionSize) {
      const section = buffer.slice(offset, offset + sectionSize);
      if (section.length >= 64) { // Only analyze sections >= 64 bytes
        sections.push({
          offset,
          size: section.length,
          entropy: this.calculateEntropy(section),
        });
      }
    }

    // Determine if packed or encrypted based on entropy
    const highEntropySections = sections.filter(s => s.entropy > this.ENTROPY_PACKED_THRESHOLD);
    const isPacked = highEntropySections.length > sections.length * 0.5;
    const isEncrypted = overall > this.ENTROPY_ENCRYPTED_THRESHOLD;

    return {
      overall,
      sections,
      isPacked,
      isEncrypted,
    };
  }

  /**
   * Calculate Shannon entropy
   */
  private calculateEntropy(buffer: Buffer): number {
    if (buffer.length === 0) return 0;

    const frequency = new Array(256).fill(0);
    for (const byte of buffer) {
      frequency[byte]++;
    }

    let entropy = 0;
    const len = buffer.length;
    for (const count of frequency) {
      if (count > 0) {
        const p = count / len;
        entropy -= p * Math.log2(p);
      }
    }

    return Math.round(entropy * 1000) / 1000; // Round to 3 decimal places
  }

  /**
   * Extract printable strings from buffer
   */
  private extractStrings(buffer: Buffer): StringAnalysis {
    const strings: string[] = [];
    const suspiciousStrings: SuspiciousString[] = [];
    const urls: string[] = [];
    const ips: string[] = [];
    const emails: string[] = [];
    const registryKeys: string[] = [];
    const filePaths: string[] = [];

    // Extract ASCII strings
    let currentString = '';
    for (let i = 0; i < buffer.length; i++) {
      const byte = buffer[i];
      if (byte >= 0x20 && byte <= 0x7E) {
        currentString += String.fromCharCode(byte);
      } else {
        if (currentString.length >= this.STRING_MIN_LENGTH &&
            currentString.length <= this.STRING_MAX_LENGTH) {
          strings.push(currentString);
          this.classifyString(currentString, urls, ips, emails, registryKeys, filePaths, suspiciousStrings);
        }
        currentString = '';
      }
    }

    // Don't forget the last string
    if (currentString.length >= this.STRING_MIN_LENGTH &&
        currentString.length <= this.STRING_MAX_LENGTH) {
      strings.push(currentString);
      this.classifyString(currentString, urls, ips, emails, registryKeys, filePaths, suspiciousStrings);
    }

    // Also extract wide (Unicode) strings
    for (let i = 0; i < buffer.length - 1; i += 2) {
      const byte = buffer[i];
      const nextByte = buffer[i + 1];
      if (nextByte === 0 && byte >= 0x20 && byte <= 0x7E) {
        currentString += String.fromCharCode(byte);
      } else {
        if (currentString.length >= this.STRING_MIN_LENGTH &&
            currentString.length <= this.STRING_MAX_LENGTH) {
          strings.push(currentString);
          this.classifyString(currentString, urls, ips, emails, registryKeys, filePaths, suspiciousStrings);
        }
        currentString = '';
      }
    }

    return {
      totalStrings: strings.length,
      suspiciousStrings: suspiciousStrings.slice(0, 100), // Limit to 100
      urls: [...new Set(urls)].slice(0, 50),
      ips: [...new Set(ips)].slice(0, 50),
      emails: [...new Set(emails)].slice(0, 50),
      registryKeys: [...new Set(registryKeys)].slice(0, 50),
      filePaths: [...new Set(filePaths)].slice(0, 50),
    };
  }

  /**
   * Classify extracted strings
   */
  private classifyString(
    str: string,
    urls: string[],
    ips: string[],
    emails: string[],
    registryKeys: string[],
    filePaths: string[],
    suspiciousStrings: SuspiciousString[]
  ): void {
    // URL pattern
    const urlMatch = str.match(/https?:\/\/[^\s"'<>]+/gi);
    if (urlMatch) {
      urls.push(...urlMatch);
    }

    // IP address pattern
    const ipMatch = str.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
    if (ipMatch) {
      ips.push(...ipMatch.filter(ip => {
        const parts = ip.split('.').map(Number);
        return parts.every(p => p >= 0 && p <= 255);
      }));
    }

    // Email pattern
    const emailMatch = str.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi);
    if (emailMatch) {
      emails.push(...emailMatch);
    }

    // Registry key pattern
    if (/HKEY_|HKLM|HKCU|HKCR/i.test(str)) {
      registryKeys.push(str);
    }

    // File path patterns
    if (/^[A-Z]:\\|^\/(?:usr|etc|var|tmp|home)/i.test(str)) {
      filePaths.push(str);
    }

    // Check against suspicious patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.pattern.test(str)) {
        suspiciousStrings.push({
          value: str.substring(0, 200),
          type: pattern.rule,
          context: pattern.description,
        });
        break; // Only match first pattern per string
      }
    }
  }

  /**
   * Parse file headers (PE, ELF, etc.)
   */
  private parseHeaders(buffer: Buffer, fileType: DetectedFileType): HeaderAnalysis | null {
    if (buffer.length < 64) return null;

    // PE (Windows executable)
    if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
      return this.parsePEHeader(buffer);
    }

    // ELF (Linux executable)
    if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
      return this.parseELFHeader(buffer);
    }

    return null;
  }

  /**
   * Parse PE header (basic)
   */
  private parsePEHeader(buffer: Buffer): HeaderAnalysis {
    try {
      // Get PE header offset from DOS header
      const peOffset = buffer.readUInt32LE(0x3C);

      if (peOffset + 24 > buffer.length) {
        return { type: 'pe', architecture: 'unknown' };
      }

      // Verify PE signature
      if (buffer.readUInt32LE(peOffset) !== 0x00004550) { // "PE\0\0"
        return { type: 'pe', architecture: 'unknown' };
      }

      // Machine type
      const machine = buffer.readUInt16LE(peOffset + 4);
      let architecture = 'unknown';
      switch (machine) {
        case 0x014c: architecture = 'x86 (32-bit)'; break;
        case 0x8664: architecture = 'x64 (64-bit)'; break;
        case 0x01c4: architecture = 'ARM'; break;
        case 0xAA64: architecture = 'ARM64'; break;
      }

      // Timestamp
      const timestamp = buffer.readUInt32LE(peOffset + 8);
      const timestampDate = new Date(timestamp * 1000).toISOString();

      // Number of sections
      const numberOfSections = buffer.readUInt16LE(peOffset + 6);
      const sections: string[] = [];

      // Read section names (basic)
      const sectionTableOffset = peOffset + 24 + buffer.readUInt16LE(peOffset + 20);
      for (let i = 0; i < Math.min(numberOfSections, 20); i++) {
        const sectionOffset = sectionTableOffset + (i * 40);
        if (sectionOffset + 8 > buffer.length) break;
        const name = buffer.slice(sectionOffset, sectionOffset + 8).toString('ascii').replace(/\0/g, '');
        if (name) sections.push(name);
      }

      return {
        type: 'pe',
        architecture,
        timestamp: timestampDate,
        sections,
      };
    } catch {
      return { type: 'pe', architecture: 'parse_error' };
    }
  }

  /**
   * Parse ELF header (basic)
   */
  private parseELFHeader(buffer: Buffer): HeaderAnalysis {
    try {
      const is64bit = buffer[4] === 2;
      let architecture = 'unknown';

      // Machine type (at offset 18 for 32-bit, 18 for 64-bit)
      const machine = buffer.readUInt16LE(18);
      switch (machine) {
        case 0x03: architecture = 'x86 (32-bit)'; break;
        case 0x3E: architecture = 'x64 (64-bit)'; break;
        case 0x28: architecture = 'ARM'; break;
        case 0xB7: architecture = 'ARM64'; break;
      }

      return {
        type: 'elf',
        architecture: `${architecture}${is64bit ? ' (64-bit)' : ' (32-bit)'}`,
      };
    } catch {
      return { type: 'elf', architecture: 'parse_error' };
    }
  }

  /**
   * Detect suspicious patterns in buffer
   */
  private detectPatterns(buffer: Buffer): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1024 * 1024)); // Limit to 1MB

    for (const pattern of SUSPICIOUS_PATTERNS) {
      // Reset lastIndex for global patterns
      pattern.pattern.lastIndex = 0;

      const match = pattern.pattern.exec(content);
      if (match) {
        matches.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          offset: match.index,
          matched: match[0].substring(0, 100),
        });
      }
    }

    return matches;
  }

  /**
   * Assess overall threat level
   */
  private assessThreat(
    fileType: DetectedFileType,
    entropy: EntropyAnalysis,
    strings: StringAnalysis,
    patterns: PatternMatch[]
  ): { isSuspicious: boolean; suspicionReasons: string[]; threatLevel: FileAnalysisResult['detection']['threatLevel'] } {
    const reasons: string[] = [];
    let score = 0;

    // File type scoring
    if (fileType.category === 'executable') {
      score += 2;
      reasons.push(`Executable file type: ${fileType.description}`);
    }

    // Entropy scoring
    if (entropy.isPacked) {
      score += 3;
      reasons.push(`High entropy suggests packed/compressed content (${entropy.overall.toFixed(2)})`);
    }
    if (entropy.isEncrypted) {
      score += 4;
      reasons.push(`Very high entropy suggests encryption (${entropy.overall.toFixed(2)})`);
    }

    // String analysis scoring
    if (strings.suspiciousStrings.length > 10) {
      score += 3;
      reasons.push(`Many suspicious strings found (${strings.suspiciousStrings.length})`);
    } else if (strings.suspiciousStrings.length > 0) {
      score += 1;
      reasons.push(`Suspicious strings found (${strings.suspiciousStrings.length})`);
    }

    // Pattern scoring
    for (const pattern of patterns) {
      switch (pattern.severity) {
        case 'critical':
          score += 5;
          reasons.push(`Critical pattern: ${pattern.description}`);
          break;
        case 'high':
          score += 3;
          reasons.push(`High severity pattern: ${pattern.description}`);
          break;
        case 'medium':
          score += 2;
          reasons.push(`Medium severity pattern: ${pattern.description}`);
          break;
        case 'low':
          score += 1;
          break;
      }
    }

    // Determine threat level
    let threatLevel: FileAnalysisResult['detection']['threatLevel'] = 'none';
    if (score >= 15) threatLevel = 'critical';
    else if (score >= 10) threatLevel = 'high';
    else if (score >= 5) threatLevel = 'medium';
    else if (score >= 2) threatLevel = 'low';

    return {
      isSuspicious: score >= 5,
      suspicionReasons: reasons.slice(0, 20), // Limit reasons
      threatLevel,
    };
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let staticAnalyzerInstance: StaticAnalyzerService | null = null;

export function getStaticAnalyzer(): StaticAnalyzerService {
  if (!staticAnalyzerInstance) {
    staticAnalyzerInstance = new StaticAnalyzerService();
  }
  return staticAnalyzerInstance;
}
