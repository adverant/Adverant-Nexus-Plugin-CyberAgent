/**
 * APT (Advanced Persistent Threat) Framework Types
 *
 * Type definitions for automated penetration testing, APT creation,
 * and AI-powered attack path discovery
 */

/**
 * Payload types for APT construction
 */
export enum PayloadType {
  WORM = 'worm',                    // Self-replicating malware
  VIRUS = 'virus',                  // File-infecting malware
  TROJAN = 'trojan',                // Disguised malware
  RANSOMWARE = 'ransomware',        // Encryption-based extortion
  ROOTKIT = 'rootkit',              // Kernel-level persistence
  BACKDOOR = 'backdoor',            // Remote access implant
  BEACON = 'beacon',                // C2 agent
  DROPPER = 'dropper',              // Stage 1 payload delivery
  LOADER = 'loader',                // Load additional payloads
  KEYLOGGER = 'keylogger',          // Keystroke capture
  INFOSTEALER = 'infostealer'       // Credential/data theft
}

/**
 * Target platform
 */
export enum TargetPlatform {
  WINDOWS = 'windows',
  LINUX = 'linux',
  MACOS = 'macos',
  ANDROID = 'android',
  IOS = 'ios'
}

/**
 * Payload format
 */
export enum PayloadFormat {
  EXE = 'exe',                      // Windows executable
  DLL = 'dll',                      // Dynamic library
  ELF = 'elf',                      // Linux executable
  MACH_O = 'mach_o',                // macOS executable
  POWERSHELL = 'powershell',        // PowerShell script
  PYTHON = 'python',                // Python script
  BASH = 'bash',                    // Bash script
  SHELLCODE = 'shellcode',          // Raw shellcode
  OFFICE_MACRO = 'office_macro',    // Office document macro
  HTA = 'hta',                      // HTML Application
  VBS = 'vbs',                      // VBScript
  JAR = 'jar'                       // Java Archive
}

/**
 * Evasion techniques
 */
export enum EvasionTechnique {
  CODE_OBFUSCATION = 'code_obfuscation',
  POLYMORPHIC = 'polymorphic',
  METAMORPHIC = 'metamorphic',
  PACKING = 'packing',
  ENCRYPTION = 'encryption',
  ANTI_DEBUG = 'anti_debug',
  ANTI_VM = 'anti_vm',
  ANTI_SANDBOX = 'anti_sandbox',
  AMSI_BYPASS = 'amsi_bypass',
  EDR_EVASION = 'edr_evasion',
  DIRECT_SYSCALLS = 'direct_syscalls',
  UNHOOKING = 'unhooking',
  PROCESS_INJECTION = 'process_injection',
  PROCESS_HOLLOWING = 'process_hollowing',
  REFLECTIVE_DLL = 'reflective_dll'
}

/**
 * C2 channel types
 */
export enum C2ChannelType {
  HTTP = 'http',
  HTTPS = 'https',
  WEBSOCKET = 'websocket',
  DNS = 'dns',
  ICMP = 'icmp',
  SMB = 'smb',
  CLOUD_STORAGE = 'cloud_storage',    // Dropbox, OneDrive, etc.
  SOCIAL_MEDIA = 'social_media',      // Twitter, Discord, etc.
  EMAIL = 'email',
  CUSTOM = 'custom'
}

/**
 * Lateral movement techniques
 */
export enum LateralMovementTechnique {
  PASS_THE_HASH = 'pass_the_hash',
  PASS_THE_TICKET = 'pass_the_ticket',
  OVERPASS_THE_HASH = 'overpass_the_hash',
  WMI = 'wmi',
  DCOM = 'dcom',
  PSEXEC = 'psexec',
  SSH = 'ssh',
  RDP = 'rdp',
  WINRM = 'winrm',
  SMB_EXEC = 'smb_exec',
  SERVICE_EXPLOITATION = 'service_exploitation',
  SCHEDULED_TASK = 'scheduled_task'
}

/**
 * Persistence mechanisms
 */
export enum PersistenceMechanism {
  REGISTRY_RUN = 'registry_run',
  REGISTRY_RUNONCE = 'registry_runonce',
  SERVICE_CREATION = 'service_creation',
  SCHEDULED_TASK_CREATION = 'scheduled_task',
  DLL_HIJACKING = 'dll_hijacking',
  BOOT_SCRIPT = 'boot_script',
  LOGON_SCRIPT = 'logon_script',
  STARTUP_FOLDER = 'startup_folder',
  WMI_EVENT = 'wmi_event',
  CRON_JOB = 'cron_job',
  BASHRC = 'bashrc',
  SYSTEMD_SERVICE = 'systemd_service'
}

/**
 * Privilege escalation techniques
 */
export enum PrivilegeEscalationTechnique {
  TOKEN_IMPERSONATION = 'token_impersonation',
  UAC_BYPASS = 'uac_bypass',
  SERVICE_MISCONFIGURATION = 'service_misconfiguration',
  KERNEL_EXPLOIT = 'kernel_exploit',
  SUID_BINARY = 'suid_binary',
  SUDO_MISCONFIGURATION = 'sudo_misconfiguration',
  CAPABILITY_EXPLOITATION = 'capability_exploitation',
  CRON_JOB_HIJACKING = 'cron_job_hijacking',
  DLL_HIJACKING_PRIVESC = 'dll_hijacking_privesc',
  POTATO_FAMILY = 'potato_family'      // RottenPotato, JuicyPotato, etc.
}

/**
 * APT Campaign configuration
 */
export interface APTCampaign {
  campaign_id: string;
  name: string;
  description: string;
  organization_id: string;
  created_by: string;

  // Targeting
  target_network: string;              // CIDR or network range
  target_hosts: string[];               // Specific target hosts
  entry_point: string;                  // Initial compromise point
  objectives: string[];                 // Campaign objectives

  // Payload configuration
  payload_type: PayloadType;
  payload_format: PayloadFormat;
  target_platform: TargetPlatform;

  // C2 configuration
  c2_channel: C2ChannelType;
  c2_server: string;
  check_in_interval: number;            // Seconds
  jitter: number;                       // Randomization percentage (0-100)

  // Evasion
  evasion_techniques: EvasionTechnique[];
  obfuscation_level: 'low' | 'medium' | 'high' | 'maximum';

  // Behavior
  stealth_level: 'low' | 'medium' | 'high' | 'maximum';
  speed_priority: 'stealth' | 'balanced' | 'speed';
  working_hours_only: boolean;
  geofencing?: {
    allowed_countries?: string[];
    allowed_regions?: string[];
  };

  // Safety
  kill_date: Date;                      // Auto-terminate after this date
  auto_cleanup: boolean;
  max_spread_count?: number;            // Limit worm propagation

  // Attack chain
  lateral_movement_techniques: LateralMovementTechnique[];
  persistence_mechanisms: PersistenceMechanism[];
  privilege_escalation_techniques: PrivilegeEscalationTechnique[];

  // MageAgent AI configuration
  ai_powered_planning: boolean;
  ai_adaptation: boolean;
  attack_path_optimization: 'stealth' | 'speed' | 'impact' | 'balanced';

  status: 'draft' | 'ready' | 'active' | 'paused' | 'completed' | 'terminated';
  created_at: Date;
  updated_at: Date;
}

/**
 * Beacon/Implant configuration
 */
export interface BeaconConfig {
  beacon_id: string;
  campaign_id: string;

  // Host information
  host_id: string;
  hostname: string;
  ip_address: string;
  platform: TargetPlatform;
  username: string;
  is_admin: boolean;

  // Beacon behavior
  check_in_interval: number;
  jitter: number;
  sleep_timer: number;                  // Sleep between activities

  // C2 configuration
  c2_channel: C2ChannelType;
  c2_endpoints: string[];               // Fallback endpoints
  c2_profile?: string;                  // Malleable C2 profile

  // Capabilities
  capabilities: string[];               // Available commands

  // Status
  status: 'active' | 'sleeping' | 'disconnected' | 'terminated';
  last_seen: Date;
  first_seen: Date;

  // Metrics
  commands_executed: number;
  data_uploaded_bytes: number;
  data_downloaded_bytes: number;
}

/**
 * Attack path node
 */
export interface AttackPathNode {
  node_id: string;
  hostname: string;
  ip_address: string;
  platform: TargetPlatform;

  // Discovered information
  services: {
    port: number;
    protocol: string;
    service_name: string;
    version?: string;
    vulnerabilities: string[];          // CVE IDs
  }[];

  // Credentials discovered
  credentials: {
    username: string;
    password?: string;
    hash?: string;
    hash_type?: string;
    domain?: string;
  }[];

  // Access level
  access_level: 'none' | 'user' | 'admin' | 'system';
  beacon_deployed: boolean;

  // Relationships
  connected_to: string[];               // Node IDs
  trust_relationships: {
    target_node: string;
    relationship_type: string;
    bidirectional: boolean;
  }[];
}

/**
 * Attack path (graph)
 */
export interface AttackPath {
  path_id: string;
  campaign_id: string;

  // Path metadata
  start_node: string;
  target_node: string;
  path_length: number;

  // Path nodes (ordered)
  nodes: AttackPathNode[];

  // Path edges (exploitation techniques)
  edges: {
    from_node: string;
    to_node: string;
    technique: LateralMovementTechnique | PrivilegeEscalationTechnique;
    exploit_used?: string;
    reliability_score: number;          // 0-1
    stealth_score: number;              // 0-1 (higher = stealthier)
    estimated_time: number;             // Seconds
  }[];

  // Scoring
  overall_reliability: number;          // 0-1
  overall_stealth: number;              // 0-1
  detection_probability: number;        // 0-1
  estimated_completion_time: number;    // Seconds

  // AI analysis
  ai_recommended: boolean;
  ai_confidence: number;                // 0-1
  ai_reasoning?: string;

  status: 'planned' | 'in_progress' | 'completed' | 'failed';
  created_at: Date;
  updated_at: Date;
}

/**
 * MageAgent attack path planning request
 */
export interface AttackPathPlanningRequest {
  campaign_id: string;
  start_node: AttackPathNode;
  target_node: AttackPathNode;
  known_network: AttackPathNode[];

  // Objectives
  objectives: ('stealth' | 'speed' | 'impact' | 'reliability')[];
  constraints: string[];                // e.g., 'no-destructive', 'business-hours-only'

  // Preferences
  preferred_techniques?: LateralMovementTechnique[];
  avoid_techniques?: LateralMovementTechnique[];
  max_path_length?: number;
  detection_budget?: number;            // Max acceptable detection probability
}

/**
 * MageAgent attack path planning response
 */
export interface AttackPathPlanningResponse {
  request_id: string;
  campaign_id: string;

  // Recommended paths (ranked)
  paths: AttackPath[];

  // AI analysis
  ai_analysis: {
    total_paths_evaluated: number;
    evaluation_time: number;            // Seconds
    confidence: number;                 // 0-1
    reasoning: string;
    risk_assessment: {
      detection_risk: 'low' | 'medium' | 'high';
      impact_risk: 'low' | 'medium' | 'high';
      success_probability: number;      // 0-1
    };
  };

  // Alternative strategies
  alternative_strategies?: {
    strategy_name: string;
    description: string;
    estimated_success_rate: number;
    estimated_stealth: number;
  }[];
}

/**
 * Payload generation request
 */
export interface PayloadGenerationRequest {
  campaign_id: string;

  // Payload configuration
  payload_type: PayloadType;
  payload_format: PayloadFormat;
  target_platform: TargetPlatform;

  // C2 configuration
  c2_channel: C2ChannelType;
  c2_server: string;
  c2_port: number;

  // Evasion
  evasion_techniques: EvasionTechnique[];
  obfuscation_level: 'low' | 'medium' | 'high' | 'maximum';
  anti_analysis: boolean;

  // Behavior
  persistence: boolean;
  persistence_mechanism?: PersistenceMechanism;
  privilege_escalation: boolean;
  lateral_movement: boolean;

  // Safety
  kill_date: Date;
  auto_cleanup: boolean;

  // Customization
  custom_code?: string;                 // Additional functionality
  icon?: string;                        // Icon file path (for exe/dll)
  file_description?: string;
  product_name?: string;
}

/**
 * Generated payload
 */
export interface GeneratedPayload {
  payload_id: string;
  campaign_id: string;

  // Payload details
  payload_type: PayloadType;
  payload_format: PayloadFormat;
  target_platform: TargetPlatform;

  // File information
  file_name: string;
  file_size: number;
  file_hash_md5: string;
  file_hash_sha256: string;

  // Signatures
  signatures: {
    av_detection_rate: number;          // 0-100 (% of AVs that detect)
    behavior_detection_risk: 'low' | 'medium' | 'high';
    signature_matches: string[];        // Matched YARA rules, etc.
  };

  // Payload content (encrypted)
  payload_content: string;              // Base64 encoded
  encryption_key: string;

  // Deployment
  deployment_methods: string[];
  recommended_delivery: string;

  generated_at: Date;
  expires_at: Date;
}

/**
 * Lateral movement execution request
 */
export interface LateralMovementRequest {
  campaign_id: string;
  source_beacon_id: string;
  target_node: AttackPathNode;

  technique: LateralMovementTechnique;
  credentials?: {
    username: string;
    password?: string;
    hash?: string;
    domain?: string;
  };

  // Options
  deploy_beacon: boolean;
  establish_persistence: boolean;
  escalate_privileges: boolean;

  // Safety
  dry_run: boolean;
  rollback_on_failure: boolean;
}

/**
 * Command to beacon
 */
export interface BeaconCommand {
  command_id: string;
  beacon_id: string;
  campaign_id: string;

  command_type: string;                 // 'shell', 'upload', 'download', 'pivot', etc.
  command_data: any;

  // Execution
  priority: number;                     // 1-10
  timeout: number;                      // Seconds

  status: 'queued' | 'sent' | 'executing' | 'completed' | 'failed' | 'timeout';
  created_at: Date;
  sent_at?: Date;
  completed_at?: Date;

  // Response
  response_data?: any;
  error_message?: string;
}

/**
 * Campaign execution statistics
 */
export interface CampaignStatistics {
  campaign_id: string;

  // Deployment
  beacons_deployed: number;
  hosts_compromised: number;
  total_hosts_discovered: number;
  network_coverage_percent: number;

  // Credentials
  credentials_harvested: number;
  unique_users: number;
  admin_credentials: number;

  // Activity
  commands_executed: number;
  files_exfiltrated: number;
  total_data_exfiltrated_bytes: number;

  // Attack path
  attack_paths_discovered: number;
  attack_paths_executed: number;
  attack_paths_successful: number;

  // Security
  detection_events: number;
  edr_alerts_triggered: number;
  siem_alerts_triggered: number;

  // Timeline
  campaign_start: Date;
  campaign_end?: Date;
  total_duration?: number;              // Seconds

  // Success metrics
  objectives_achieved: string[];
  objectives_failed: string[];
  overall_success_rate: number;         // 0-100
}
