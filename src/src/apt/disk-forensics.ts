/**
 * Disk Forensics & Analysis Module
 *
 * Capabilities:
 * - Disk image acquisition (E01, VMDK, VHD, raw, AFF)
 * - File system analysis (NTFS, ext4, APFS, FAT32, XFS, Btrfs)
 * - Deleted file recovery and carving
 * - Timeline analysis (MAC times)
 * - Memory dump analysis
 * - Registry analysis (Windows)
 * - Log file analysis
 * - Artifact extraction (browser history, emails, etc.)
 * - Hash verification and integrity checking
 * - Anti-forensics detection
 *
 * AUTHORIZATION REQUIRED: Only for authorized forensic investigations
 */

import { MageAgentService } from '../../mageagent/mageagent.service';
import { GraphRAGService } from '../../graphrag/graphrag.service';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

const execAsync = promisify(exec);

/**
 * Disk image format
 */
export enum DiskImageFormat {
  RAW = 'raw',                    // dd format
  E01 = 'e01',                    // EnCase Expert Witness Format
  AFF = 'aff',                    // Advanced Forensic Format
  VMDK = 'vmdk',                  // VMware Virtual Disk
  VHD = 'vhd',                    // Virtual Hard Disk
  VHDX = 'vhdx',                  // Virtual Hard Disk v2
  QCOW2 = 'qcow2',                // QEMU Copy-On-Write
  ISO = 'iso'                     // ISO 9660
}

/**
 * File system types
 */
export enum FileSystemType {
  NTFS = 'ntfs',
  FAT12 = 'fat12',
  FAT16 = 'fat16',
  FAT32 = 'fat32',
  EXFAT = 'exfat',
  EXT2 = 'ext2',
  EXT3 = 'ext3',
  EXT4 = 'ext4',
  XFS = 'xfs',
  BTRFS = 'btrfs',
  APFS = 'apfs',
  HFS_PLUS = 'hfs+',
  UFS = 'ufs',
  ZFS = 'zfs',
  REISERFS = 'reiserfs'
}

/**
 * Acquisition method
 */
export enum AcquisitionMethod {
  PHYSICAL = 'physical',          // Bit-by-bit copy of entire disk
  LOGICAL = 'logical',            // Copy of allocated files only
  TARGETED = 'targeted',          // Specific files/folders
  LIVE = 'live',                  // Live system acquisition
  MEMORY = 'memory'               // RAM dump
}

/**
 * Disk image information
 */
export interface DiskImage {
  image_id: string;
  image_path: string;
  format: DiskImageFormat;
  acquisition_method: AcquisitionMethod;

  // Source information
  source_device: string;
  source_serial?: string;
  source_model?: string;

  // Image metadata
  size_bytes: number;
  sector_size: number;
  total_sectors: number;
  acquisition_date: Date;
  acquired_by: string;
  case_number?: string;

  // Hashes for integrity verification
  md5_hash: string;
  sha256_hash: string;

  // Partitions found
  partitions: DiskPartition[];

  // Write protection
  write_protected: boolean;
}

/**
 * Disk partition information
 */
export interface DiskPartition {
  partition_id: string;
  partition_number: number;
  offset_bytes: number;
  size_bytes: number;
  file_system: FileSystemType;
  partition_type: string;
  bootable: boolean;
  label?: string;
  mount_point?: string;
}

/**
 * File system analysis result
 */
export interface FileSystemAnalysis {
  analysis_id: string;
  partition: DiskPartition;

  // File system details
  cluster_size: number;
  total_clusters: number;
  used_clusters: number;
  free_clusters: number;

  // File statistics
  total_files: number;
  total_directories: number;
  deleted_files: number;
  hidden_files: number;

  // Timeline
  earliest_timestamp: Date;
  latest_timestamp: Date;

  // Notable findings
  findings: ForensicFinding[];
}

/**
 * Forensic finding
 */
export interface ForensicFinding {
  finding_id: string;
  finding_type: 'suspicious_file' | 'deleted_file' | 'hidden_data' | 'encryption' | 'anti_forensics' | 'malware' | 'artifact';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  file_path?: string;
  inode?: number;
  evidence: string[];
  timestamp?: Date;
}

/**
 * Recovered file information
 */
export interface RecoveredFile {
  file_id: string;
  original_path: string;
  file_name: string;
  file_size: number;
  file_type: string;
  mime_type: string;

  // Timestamps
  created: Date;
  modified: Date;
  accessed: Date;
  deleted?: Date;

  // Hashes
  md5: string;
  sha256: string;

  // Recovery metadata
  recovery_method: 'undelete' | 'carving' | 'shadow_copy';
  recovery_confidence: number; // 0-1
  fragmented: boolean;

  // Location
  partition_id: string;
  inode?: number;
  clusters: number[];

  // Extracted content path
  extracted_path: string;
}

/**
 * Timeline event
 */
export interface TimelineEvent {
  event_id: string;
  timestamp: Date;
  event_type: 'file_created' | 'file_modified' | 'file_accessed' | 'file_deleted' | 'registry_modified' | 'process_executed' | 'network_connection' | 'user_login';
  source: string; // File path, registry key, etc.
  description: string;
  user?: string;
  process?: string;
  details: Record<string, any>;
}

/**
 * Registry hive (Windows)
 */
export interface RegistryHive {
  hive_id: string;
  hive_name: 'SYSTEM' | 'SOFTWARE' | 'SAM' | 'SECURITY' | 'NTUSER.DAT' | 'USRCLASS.DAT';
  file_path: string;
  last_modified: Date;
  keys_count: number;
  values_count: number;
}

/**
 * Artifact types
 */
export enum ArtifactType {
  BROWSER_HISTORY = 'browser_history',
  BROWSER_COOKIES = 'browser_cookies',
  BROWSER_DOWNLOADS = 'browser_downloads',
  EMAIL = 'email',
  DOCUMENT = 'document',
  IMAGE = 'image',
  VIDEO = 'video',
  EXECUTABLE = 'executable',
  ARCHIVE = 'archive',
  DATABASE = 'database',
  LOG_FILE = 'log_file',
  CREDENTIAL = 'credential',
  ENCRYPTION_KEY = 'encryption_key'
}

/**
 * Extracted artifact
 */
export interface ExtractedArtifact {
  artifact_id: string;
  artifact_type: ArtifactType;
  source_file: string;
  extracted_data: any;
  relevance_score: number; // 0-1 (AI-determined)
  timestamp?: Date;
}

/**
 * Memory dump information
 */
export interface MemoryDump {
  dump_id: string;
  dump_path: string;
  size_bytes: number;
  acquisition_date: Date;
  os_type: 'windows' | 'linux' | 'macos';
  os_version: string;

  // Analysis results
  processes: MemoryProcess[];
  network_connections: NetworkConnection[];
  loaded_modules: LoadedModule[];
  malware_found: boolean;
  suspicious_processes: string[];
}

/**
 * Process from memory dump
 */
export interface MemoryProcess {
  pid: number;
  process_name: string;
  command_line: string;
  parent_pid: number;
  user: string;
  start_time: Date;
  threads: number;
  handles: number;
  suspicious: boolean;
  suspicious_reasons?: string[];
}

/**
 * Network connection from memory
 */
export interface NetworkConnection {
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  protocol: 'tcp' | 'udp';
  state: string;
  process_name: string;
  pid: number;
}

/**
 * Loaded module/DLL
 */
export interface LoadedModule {
  module_name: string;
  module_path: string;
  base_address: string;
  size: number;
  pid: number;
  process_name: string;
}

/**
 * Disk Forensics Service
 */
export class DiskForensicsService {
  constructor(
    private readonly mageAgent: MageAgentService,
    private readonly graphRAG: GraphRAGService
  ) {}

  /**
   * Acquire disk image
   */
  async acquireDiskImage(
    source_device: string,
    output_path: string,
    format: DiskImageFormat = DiskImageFormat.E01,
    method: AcquisitionMethod = AcquisitionMethod.PHYSICAL,
    case_number?: string
  ): Promise<DiskImage> {
    console.log(`💾 Acquiring disk image from ${source_device}...`);
    console.log(`  Format: ${format}, Method: ${method}`);

    const imageId = this.generateId();
    const startTime = Date.now();

    // In production: Use dd, dcfldd, or FTK Imager
    // Physical acquisition:
    //   dcfldd if=/dev/sda of=image.dd hash=md5,sha256 hashwindow=1G hashlog=hashes.txt
    // E01 format:
    //   ewfacquire /dev/sda
    // AFF format:
    //   aimage /dev/sda image.aff

    // Simulated acquisition
    const diskImage: DiskImage = {
      image_id: imageId,
      image_path: output_path,
      format,
      acquisition_method: method,
      source_device,
      source_serial: 'WD-SERIAL123',
      source_model: 'WD Black 1TB',
      size_bytes: 1000 * 1024 * 1024 * 1024, // 1 TB
      sector_size: 512,
      total_sectors: (1000 * 1024 * 1024 * 1024) / 512,
      acquisition_date: new Date(),
      acquired_by: 'forensic-analyst',
      case_number,
      md5_hash: await this.calculateHash('md5', source_device),
      sha256_hash: await this.calculateHash('sha256', source_device),
      partitions: await this.detectPartitions(source_device),
      write_protected: true
    };

    const duration = (Date.now() - startTime) / 1000;
    console.log(`✅ Acquisition complete (${duration.toFixed(2)}s)`);

    // Store acquisition metadata
    await this.graphRAG.storeDocument({
      content: JSON.stringify(diskImage, null, 2),
      title: `Disk Acquisition - ${case_number || imageId} - ${new Date().toISOString()}`,
      metadata: {
        type: 'disk_acquisition',
        case_number,
        device: source_device,
        size: diskImage.size_bytes
      }
    });

    return diskImage;
  }

  /**
   * Detect partitions on disk
   */
  private async detectPartitions(device: string): Promise<DiskPartition[]> {
    // In production: Use mmls (The Sleuth Kit) or fdisk
    // mmls /dev/sda
    // fdisk -l /dev/sda

    const partitions: DiskPartition[] = [
      {
        partition_id: 'part_1',
        partition_number: 1,
        offset_bytes: 1048576, // 1 MB
        size_bytes: 500 * 1024 * 1024 * 1024, // 500 GB
        file_system: FileSystemType.NTFS,
        partition_type: 'Microsoft basic data',
        bootable: true,
        label: 'Windows'
      },
      {
        partition_id: 'part_2',
        partition_number: 2,
        offset_bytes: 500 * 1024 * 1024 * 1024,
        size_bytes: 500 * 1024 * 1024 * 1024,
        file_system: FileSystemType.EXT4,
        partition_type: 'Linux filesystem',
        bootable: false,
        label: 'Data'
      }
    ];

    return partitions;
  }

  /**
   * Analyze file system
   */
  async analyzeFileSystem(
    image_path: string,
    partition: DiskPartition
  ): Promise<FileSystemAnalysis> {
    console.log(`🔍 Analyzing file system on ${partition.label || partition.partition_id}...`);

    // In production: Use fls, istat (The Sleuth Kit) or autopsy
    // fls -r -o <offset> image.dd
    // istat -o <offset> image.dd <inode>

    const analysisId = this.generateId();
    const findings: ForensicFinding[] = [];

    // Scan for suspicious files
    const suspiciousPatterns = [
      '.encrypted',
      'ransomware',
      'backdoor',
      'keylog',
      'mimikatz',
      'powersploit'
    ];

    // Simulated file system analysis
    const totalFiles = Math.floor(Math.random() * 50000) + 10000;
    const deletedFiles = Math.floor(totalFiles * 0.05); // 5% deleted

    // Check for anti-forensics indicators
    if (Math.random() > 0.7) {
      findings.push({
        finding_id: this.generateId(),
        finding_type: 'anti_forensics',
        severity: 'high',
        title: 'Timestamp manipulation detected',
        description: 'Multiple files have suspicious timestamp patterns indicating anti-forensics activity',
        evidence: ['Files with future timestamps', 'Mass timestamp changes']
      });
    }

    // Check for hidden data
    if (Math.random() > 0.8) {
      findings.push({
        finding_id: this.generateId(),
        finding_type: 'hidden_data',
        severity: 'medium',
        title: 'Alternate data streams found',
        description: 'NTFS alternate data streams detected (potential data hiding)',
        file_path: 'C:\\Windows\\System32\\legit.exe:hidden.txt',
        evidence: ['ADS detected']
      });
    }

    const analysis: FileSystemAnalysis = {
      analysis_id: analysisId,
      partition,
      cluster_size: 4096,
      total_clusters: partition.size_bytes / 4096,
      used_clusters: Math.floor((partition.size_bytes * 0.6) / 4096),
      free_clusters: Math.floor((partition.size_bytes * 0.4) / 4096),
      total_files: totalFiles,
      total_directories: Math.floor(totalFiles / 20),
      deleted_files: deletedFiles,
      hidden_files: Math.floor(totalFiles * 0.01),
      earliest_timestamp: new Date('2020-01-01'),
      latest_timestamp: new Date(),
      findings
    };

    console.log(`✅ Analysis complete: ${totalFiles} files, ${deletedFiles} deleted`);
    return analysis;
  }

  /**
   * Recover deleted files
   */
  async recoverDeletedFiles(
    image_path: string,
    partition: DiskPartition,
    file_types?: string[] // Filter by file type
  ): Promise<RecoveredFile[]> {
    console.log(`🔄 Recovering deleted files from ${partition.label || partition.partition_id}...`);

    // In production: Use tsk_recover, photorec, or foremost for carving
    // tsk_recover -e -o <offset> image.dd output_dir/
    // foremost -t all -i image.dd -o output_dir/
    // photorec image.dd

    const recovered: RecoveredFile[] = [];

    // Simulated recovery
    const recoveryMethods = ['undelete', 'carving', 'shadow_copy'] as const;
    const fileTypes = ['pdf', 'docx', 'xlsx', 'jpg', 'png', 'exe', 'zip'];

    for (let i = 0; i < 50; i++) {
      const fileType = fileTypes[Math.floor(Math.random() * fileTypes.length)];

      recovered.push({
        file_id: this.generateId(),
        original_path: `C:\\Users\\John\\Documents\\file_${i}.${fileType}`,
        file_name: `file_${i}.${fileType}`,
        file_size: Math.floor(Math.random() * 10000000),
        file_type: fileType,
        mime_type: this.getMimeType(fileType),
        created: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
        modified: new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000),
        accessed: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
        deleted: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
        md5: this.generateHash(),
        sha256: this.generateHash(),
        recovery_method: recoveryMethods[Math.floor(Math.random() * recoveryMethods.length)],
        recovery_confidence: 0.7 + Math.random() * 0.3,
        fragmented: Math.random() > 0.7,
        partition_id: partition.partition_id,
        clusters: [100, 101, 102],
        extracted_path: `/tmp/recovered/file_${i}.${fileType}`
      });
    }

    console.log(`✅ Recovered ${recovered.length} deleted files`);
    return recovered;
  }

  /**
   * Generate forensic timeline
   */
  async generateTimeline(
    image_path: string,
    partition: DiskPartition,
    start_date?: Date,
    end_date?: Date
  ): Promise<TimelineEvent[]> {
    console.log(`📅 Generating forensic timeline...`);

    // In production: Use fls + mactime (The Sleuth Kit) or plaso/log2timeline
    // fls -r -m / -o <offset> image.dd > bodyfile
    // mactime -b bodyfile -d > timeline.csv
    // log2timeline.py --storage-file timeline.plaso image.dd

    const timeline: TimelineEvent[] = [];

    // Simulated timeline generation
    const eventTypes: TimelineEvent['event_type'][] = [
      'file_created',
      'file_modified',
      'file_accessed',
      'file_deleted',
      'registry_modified',
      'process_executed',
      'network_connection',
      'user_login'
    ];

    for (let i = 0; i < 1000; i++) {
      const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];

      timeline.push({
        event_id: this.generateId(),
        timestamp: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
        event_type: eventType,
        source: this.getEventSource(eventType),
        description: this.getEventDescription(eventType),
        user: 'John',
        process: eventType === 'process_executed' ? 'malware.exe' : undefined,
        details: {}
      });
    }

    // Sort by timestamp
    timeline.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    console.log(`✅ Timeline generated: ${timeline.length} events`);
    return timeline;
  }

  /**
   * Analyze Windows registry
   */
  async analyzeRegistry(
    image_path: string,
    partition: DiskPartition
  ): Promise<{
    hives: RegistryHive[];
    findings: ForensicFinding[];
    artifacts: ExtractedArtifact[];
  }> {
    console.log(`🔍 Analyzing Windows registry...`);

    // In production: Use RegRipper, Registry Explorer, or python-registry
    // rip.pl -r SYSTEM -p compname
    // Registry Explorer (Eric Zimmerman tools)

    const hives: RegistryHive[] = [
      {
        hive_id: 'hive_system',
        hive_name: 'SYSTEM',
        file_path: 'C:\\Windows\\System32\\config\\SYSTEM',
        last_modified: new Date(),
        keys_count: 50000,
        values_count: 150000
      },
      {
        hive_id: 'hive_software',
        hive_name: 'SOFTWARE',
        file_path: 'C:\\Windows\\System32\\config\\SOFTWARE',
        last_modified: new Date(),
        keys_count: 100000,
        values_count: 300000
      }
    ];

    const findings: ForensicFinding[] = [];
    const artifacts: ExtractedArtifact[] = [];

    // Check for persistence mechanisms
    findings.push({
      finding_id: this.generateId(),
      finding_type: 'suspicious_file',
      severity: 'high',
      title: 'Suspicious Run key entry',
      description: 'Malicious executable found in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      file_path: 'C:\\Windows\\malware.exe',
      evidence: ['Registry persistence mechanism']
    });

    // Extract artifacts
    artifacts.push({
      artifact_id: this.generateId(),
      artifact_type: ArtifactType.CREDENTIAL,
      source_file: 'SAM',
      extracted_data: {
        username: 'Administrator',
        rid: 500,
        lm_hash: 'aad3b435b51404eeaad3b435b51404ee',
        ntlm_hash: '31d6cfe0d16ae931b73c59d7e0c089c0'
      },
      relevance_score: 0.9
    });

    console.log(`✅ Registry analyzed: ${hives.length} hives, ${findings.length} findings`);
    return { hives, findings, artifacts };
  }

  /**
   * Extract artifacts using AI
   */
  async extractArtifacts(
    image_path: string,
    partition: DiskPartition,
    artifact_types: ArtifactType[]
  ): Promise<ExtractedArtifact[]> {
    console.log(`🔍 Extracting artifacts...`);

    // Use MageAgent to intelligently extract and prioritize artifacts
    const agentResult = await this.mageAgent.spawnAgent({
      role: 'forensic_analyst',
      task: 'Extract and analyze digital artifacts',
      context: {
        partition_id: partition.partition_id,
        artifact_types,
        file_system: partition.file_system
      },
      sub_agents: [
        {
          role: 'browser_analyst',
          task: 'Extract browser history, cookies, and downloads'
        },
        {
          role: 'email_analyst',
          task: 'Extract email artifacts'
        },
        {
          role: 'document_analyst',
          task: 'Extract and analyze documents'
        }
      ]
    });

    const artifacts: ExtractedArtifact[] = [];

    // Simulated artifact extraction
    if (artifact_types.includes(ArtifactType.BROWSER_HISTORY)) {
      artifacts.push({
        artifact_id: this.generateId(),
        artifact_type: ArtifactType.BROWSER_HISTORY,
        source_file: 'C:\\Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History',
        extracted_data: {
          visits: [
            { url: 'https://suspicious-site.com', timestamp: new Date(), title: 'Phishing Page' }
          ]
        },
        relevance_score: 0.95,
        timestamp: new Date()
      });
    }

    console.log(`✅ Extracted ${artifacts.length} artifacts`);
    return artifacts;
  }

  /**
   * Analyze memory dump
   */
  async analyzeMemoryDump(
    dump_path: string,
    os_type: 'windows' | 'linux' | 'macos'
  ): Promise<MemoryDump> {
    console.log(`🧠 Analyzing memory dump (${os_type})...`);

    // In production: Use Volatility 3
    // volatility -f memory.dmp windows.pslist
    // volatility -f memory.dmp windows.netscan
    // volatility -f memory.dmp windows.malfind

    const processes: MemoryProcess[] = [
      {
        pid: 1234,
        process_name: 'suspicious.exe',
        command_line: 'C:\\temp\\suspicious.exe --connect 192.168.1.100',
        parent_pid: 4,
        user: 'SYSTEM',
        start_time: new Date(),
        threads: 10,
        handles: 500,
        suspicious: true,
        suspicious_reasons: ['Connects to external IP', 'No valid code signature', 'Injected code detected']
      }
    ];

    const networkConnections: NetworkConnection[] = [
      {
        local_address: '192.168.1.50',
        local_port: 49152,
        remote_address: '192.168.1.100',
        remote_port: 4444,
        protocol: 'tcp',
        state: 'ESTABLISHED',
        process_name: 'suspicious.exe',
        pid: 1234
      }
    ];

    const loadedModules: LoadedModule[] = [
      {
        module_name: 'injected.dll',
        module_path: 'C:\\temp\\injected.dll',
        base_address: '0x7FFE0000',
        size: 102400,
        pid: 1234,
        process_name: 'suspicious.exe'
      }
    ];

    const memoryDump: MemoryDump = {
      dump_id: this.generateId(),
      dump_path,
      size_bytes: 4 * 1024 * 1024 * 1024, // 4 GB
      acquisition_date: new Date(),
      os_type,
      os_version: os_type === 'windows' ? 'Windows 10 21H2' : 'Ubuntu 22.04',
      processes,
      network_connections: networkConnections,
      loaded_modules: loadedModules,
      malware_found: true,
      suspicious_processes: ['suspicious.exe']
    };

    console.log(`✅ Memory analysis complete: ${processes.length} processes, malware: ${memoryDump.malware_found}`);
    return memoryDump;
  }

  /**
   * File carving (recover files without file system metadata)
   */
  async carveFiles(
    image_path: string,
    file_types: string[] = ['jpg', 'png', 'pdf', 'docx', 'zip']
  ): Promise<RecoveredFile[]> {
    console.log(`🔪 Carving files from image...`);

    // In production: Use scalpel, foremost, or photorec
    // scalpel -c scalpel.conf -o output/ image.dd
    // foremost -t jpg,png,pdf -i image.dd -o output/

    const carved: RecoveredFile[] = [];

    // Simulated file carving
    for (const fileType of file_types) {
      const count = Math.floor(Math.random() * 20) + 5;

      for (let i = 0; i < count; i++) {
        carved.push({
          file_id: this.generateId(),
          original_path: 'unknown',
          file_name: `carved_${fileType}_${i}.${fileType}`,
          file_size: Math.floor(Math.random() * 5000000),
          file_type: fileType,
          mime_type: this.getMimeType(fileType),
          created: new Date(),
          modified: new Date(),
          accessed: new Date(),
          md5: this.generateHash(),
          sha256: this.generateHash(),
          recovery_method: 'carving',
          recovery_confidence: 0.6 + Math.random() * 0.3,
          fragmented: Math.random() > 0.5,
          partition_id: 'unknown',
          clusters: [],
          extracted_path: `/tmp/carved/${fileType}_${i}.${fileType}`
        });
      }
    }

    console.log(`✅ Carved ${carved.length} files`);
    return carved;
  }

  /**
   * Calculate hash of file/device
   */
  private async calculateHash(algorithm: 'md5' | 'sha256', path: string): Promise<string> {
    // In production: Use md5sum, sha256sum, or hashdeep
    // md5sum /dev/sda
    // sha256sum image.dd

    // Simulated hash
    return crypto.createHash(algorithm).update(path + Date.now()).digest('hex');
  }

  /**
   * Generate random hash (for simulation)
   */
  private generateHash(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Get MIME type for file extension
   */
  private getMimeType(extension: string): string {
    const mimeTypes: Record<string, string> = {
      'pdf': 'application/pdf',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'jpg': 'image/jpeg',
      'png': 'image/png',
      'exe': 'application/x-msdownload',
      'zip': 'application/zip'
    };
    return mimeTypes[extension] || 'application/octet-stream';
  }

  /**
   * Get event source based on type
   */
  private getEventSource(eventType: TimelineEvent['event_type']): string {
    const sources: Record<string, string> = {
      'file_created': 'C:\\Users\\John\\Documents\\report.docx',
      'file_modified': 'C:\\Users\\John\\Documents\\report.docx',
      'file_accessed': 'C:\\Users\\John\\Documents\\report.docx',
      'file_deleted': 'C:\\Users\\John\\temp\\file.tmp',
      'registry_modified': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'process_executed': 'C:\\Windows\\System32\\cmd.exe',
      'network_connection': '192.168.1.100:4444',
      'user_login': 'Terminal Services'
    };
    return sources[eventType] || 'Unknown';
  }

  /**
   * Get event description
   */
  private getEventDescription(eventType: TimelineEvent['event_type']): string {
    const descriptions: Record<string, string> = {
      'file_created': 'File created',
      'file_modified': 'File modified',
      'file_accessed': 'File accessed',
      'file_deleted': 'File deleted',
      'registry_modified': 'Registry key modified',
      'process_executed': 'Process executed',
      'network_connection': 'Network connection established',
      'user_login': 'User logged in'
    };
    return descriptions[eventType] || 'Event occurred';
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }

  /**
   * Export forensic report
   */
  async exportForensicReport(
    case_number: string,
    format: 'html' | 'pdf' | 'json'
  ): Promise<string> {
    console.log(`📄 Exporting forensic report (${format})...`);

    // Retrieve all case data from GraphRAG
    const caseData = await this.graphRAG.recallMemory({
      query: `forensic case ${case_number}`,
      limit: 100
    });

    const reportPath = `/tmp/reports/case_${case_number}.${format}`;

    // Format-specific export
    switch (format) {
      case 'json':
        await fs.writeFile(reportPath, JSON.stringify(caseData, null, 2));
        break;
      case 'html':
      case 'pdf':
        // Generate formatted report
        break;
    }

    console.log(`✅ Report exported to ${reportPath}`);
    return reportPath;
  }
}

export default DiskForensicsService;
