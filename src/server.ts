#!/usr/bin/env node

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { SecureCommandExecutor } from "./commands/executor.js";
import { SecurityAuditor, SecurityEventType } from "./security/audit.js";
import { sanitizeFilePath } from "./security/sanitizer.js";
import { COMMAND_WHITELIST } from "./commands/whitelist.js";
import fs from 'fs/promises';

/**
 * Secure MCP Terminal Server
 * 
 * Provides safe terminal command execution capabilities for Claude Desktop
 * with comprehensive security controls following MCP security requirements.
 */
class SecureMcpTerminalServer {
  private server: McpServer;
  private executor: SecureCommandExecutor;
  private auditor: SecurityAuditor;

  constructor() {
    // Initialize security components
    this.executor = SecureCommandExecutor.getInstance();
    this.auditor = SecurityAuditor.getInstance();

    // Create MCP server with security-focused configuration
    this.server = new McpServer({
      name: "secure-terminal-server",
      version: "1.0.0",
      description: "Secure terminal command execution server for Claude Desktop with comprehensive security controls"
    });

    this.setupTools();
    this.setupResources();
    this.setupErrorHandling();
  }

  /**
   * Set up MCP tools with security validation
   */
  private setupTools(): void {
    // List directory contents safely
    this.server.tool(
      "list_directory",
      "List directory contents with security validation",
      {
        path: z.string().optional().describe("Directory path to list (defaults to current directory)"),
        includeHidden: z.boolean().optional().describe("Include hidden files and directories"),
        longFormat: z.boolean().optional().describe("Use detailed long format listing")
      },
      async ({ path: dirPath, includeHidden, longFormat }, { _meta }) => {
        const clientId = this.getClientId(_meta);
        
        try {
          const args: string[] = [];
          if (longFormat) args.push('-l');
          if (includeHidden) args.push('-a');
          if (dirPath) {
            const sanitizedPath = sanitizeFilePath(dirPath);
            args.push(sanitizedPath);
          }

          const result = await this.executor.executeCommand(
            'list_directory',
            'ls',
            args,
            { clientId, workingDirectory: dirPath || undefined }
          );

          return {
            content: [{
              type: "text" as const,
              text: result.success ? result.output : `Error: ${result.error}`
            }],
            isError: !result.success
          };
        } catch (error) {
          return this.createErrorResponse(error);
        }
      }
    );

    // Get current working directory
    this.server.tool(
      "get_current_directory",
      "Get the current working directory",
      {},
      async (_, { _meta }) => {
        const clientId = this.getClientId(_meta);
        
        try {
          const result = await this.executor.executeCommand(
            'get_current_directory',
            'pwd',
            [],
            { clientId }
          );

          return {
            content: [{
              type: "text" as const,
              text: result.success ? result.output.trim() : `Error: ${result.error}`
            }],
            isError: !result.success
          };
        } catch (error) {
          return this.createErrorResponse(error);
        }
      }
    );

    // Execute safe commands from whitelist
    this.server.tool(
      "execute_safe_command",
      "Execute commands from the security whitelist",
      {
        command: z.string().describe("Command to execute (must be in whitelist)"),
        args: z.array(z.string()).optional().describe("Command arguments"),
        workingDirectory: z.string().optional().describe("Working directory for command execution")
      },
      async ({ command, args = [], workingDirectory }, { _meta }) => {
        const clientId = this.getClientId(_meta);
        
        try {
          const result = await this.executor.executeCommand(
            'execute_safe_command',
            command,
            args,
            { clientId, workingDirectory: workingDirectory || undefined }
          );

          return {
            content: [{
              type: "text" as const,
              text: result.success ? result.output : `Error: ${result.error}`
            }],
            isError: !result.success,
            metadata: {
              executionTime: result.executionTime,
              outputSize: result.outputSize,
              truncated: result.truncated
            }
          };
        } catch (error) {
          return this.createErrorResponse(error);
        }
      }
    );

    // Read file contents safely
    this.server.tool(
      "read_file_safe",
      "Safely read file contents with size limits",
      {
        filePath: z.string().describe("Path to file to read"),
        maxLines: z.number().optional().describe("Maximum number of lines to read (default: 100)")
      },
      async ({ filePath, maxLines = 100 }, { _meta }) => {
        const clientId = this.getClientId(_meta);
        
        try {
          const args = ['-n', maxLines.toString(), filePath];
          const result = await this.executor.executeCommand(
            'read_file_safe',
            'head',
            args,
            { clientId }
          );

          return {
            content: [{
              type: "text" as const,
              text: result.success ? result.output : `Error: ${result.error}`
            }],
            isError: !result.success
          };
        } catch (error) {
          return this.createErrorResponse(error);
        }
      }
    );

    // Git repository status
    this.server.tool(
      "git_status",
      "Get Git repository status",
      {
        workingDirectory: z.string().optional().describe("Git repository directory"),
        short: z.boolean().optional().describe("Use short format output")
      },
      async ({ workingDirectory, short }, { _meta }) => {
        const clientId = this.getClientId(_meta);
        
        try {
          const args = ['status'];
          if (short) args.push('--short');

          const result = await this.executor.executeCommand(
            'git_status',
            'git',
            args,
            { clientId, workingDirectory: workingDirectory || undefined }
          );

          return {
            content: [{
              type: "text" as const,
              text: result.success ? result.output : `Error: ${result.error}`
            }],
            isError: !result.success
          };
        } catch (error) {
          return this.createErrorResponse(error);
        }
      }
    );

    // Count lines, words, characters in files
    this.server.tool(
      "count_file_stats",
      "Count lines, words, or characters in files",
      {
        filePath: z.string().describe("Path to file to analyze"),
        countType: z.enum(['lines', 'words', 'characters']).optional().describe("Type of count to perform")
      },
      async ({ filePath, countType }, { _meta }) => {
        const clientId = this.getClientId(_meta);
        
        try {
          const args: string[] = [];
          if (countType === 'lines') args.push('-l');
          else if (countType === 'words') args.push('-w');
          else if (countType === 'characters') args.push('-c');
          
          args.push(filePath);

          const result = await this.executor.executeCommand(
            'count_file_stats',
            'wc',
            args,
            { clientId }
          );

          return {
            content: [{
              type: "text" as const,
              text: result.success ? result.output : `Error: ${result.error}`
            }],
            isError: !result.success
          };
        } catch (error) {
          return this.createErrorResponse(error);
        }
      }
    );

    // Check system information
    this.server.tool(
      "system_info",
      "Get basic system information",
      {
        infoType: z.enum(['user', 'os', 'system']).optional().describe("Type of system information")
      },
      async ({ infoType }, { _meta }) => {
        const clientId = this.getClientId(_meta);
        
        try {
          let command: string;
          let args: string[] = [];

          switch (infoType) {
            case 'user':
              command = 'whoami';
              break;
            case 'os':
              command = 'uname';
              args = ['-s', '-r'];
              break;
            case 'system':
              command = 'uname';
              args = ['-a'];
              break;
            default:
              command = 'whoami';
          }

          const result = await this.executor.executeCommand(
            'system_info',
            command,
            args,
            { clientId }
          );

          return {
            content: [{
              type: "text" as const,
              text: result.success ? result.output : `Error: ${result.error}`
            }],
            isError: !result.success
          };
        } catch (error) {
          return this.createErrorResponse(error);
        }
      }
    );
  }

  /**
   * Set up MCP resources
   */
  private setupResources(): void {
    // Available commands resource
    this.server.resource(
      "available_commands",
      "commands://whitelist",
      async () => {
        const commands = Object.entries(COMMAND_WHITELIST).map(([key, def]) => {
          return `${key}: ${def.description} (Risk: ${def.riskLevel})`;
        }).join('\n');

        return {
          contents: [{
            uri: "commands://whitelist",
            text: `Available Commands:\n\n${commands}\n\nAll commands are subject to rate limiting and security validation.`
          }]
        };
      }
    );

    // Security status resource
    this.server.resource(
      "security_status",
      new ResourceTemplate("security://status/{clientId}", { list: undefined }),
      async (uri, { clientId }) => {
        try {
          const stats = await this.executor.getExecutionStats(clientId);
          const statusText = `Security Status for Client: ${clientId}

Rate Limit Status:
- Global: ${stats.rateLimitStatus.global?.remaining || 'N/A'} remaining
- Failed Attempts: ${stats.rateLimitStatus.failedAttempts?.remaining || 'N/A'} remaining
- Suspicious Activity: ${stats.rateLimitStatus.suspicious?.remaining || 'N/A'} remaining

Client Blocked: ${stats.isBlocked ? 'YES' : 'NO'}

Security Features Active:
✓ Command whitelist validation
✓ Input/output sanitization
✓ Rate limiting
✓ Audit logging
✓ Path traversal protection
✓ Credential leak prevention`;

          return {
            contents: [{
              uri: uri.href,
              text: statusText
            }]
          };
        } catch (error) {
          return {
            contents: [{
              uri: uri.href,
              text: `Error retrieving security status: ${error}`
            }]
          };
        }
      }
    );

    // Server capabilities resource
    this.server.resource(
      "server_capabilities",
      "server://capabilities",
      async () => {
        const capabilities = `MCP Secure Terminal Server Capabilities

Security Features:
- Whitelisted command execution only
- Input sanitization and validation
- Output sanitization (credential filtering)
- Rate limiting (risk-based)
- Comprehensive audit logging
- Path traversal prevention
- Working directory restrictions
- Command timeout enforcement
- Output size limiting

Available Tools:
- list_directory: Safe directory listing
- get_current_directory: Get working directory
- execute_safe_command: Execute whitelisted commands
- read_file_safe: Safe file reading (limited)
- git_status: Git repository status
- count_file_stats: File statistics
- system_info: Basic system information

Available Resources:
- available_commands: Command whitelist
- security_status: Security and rate limit status
- server_capabilities: This information

All operations are logged and subject to security validation.`;

        return {
          contents: [{
            uri: "server://capabilities",
            text: capabilities
          }]
        };
      }
    );
  }

  /**
   * Set up error handling
   */
  private setupErrorHandling(): void {
    process.on('uncaughtException', (error) => {
      this.auditor.logError('system', 'uncaught_exception', error);
      console.error('Uncaught Exception:', error);
      process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
      this.auditor.logError('system', 'unhandled_rejection', reason);
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });

    process.on('SIGINT', () => {
      this.auditor.logServerEvent(SecurityEventType.SERVER_STOPPED, 'SIGINT received');
      console.log('\nShutting down server gracefully...');
      process.exit(0);
    });

    process.on('SIGTERM', () => {
      this.auditor.logServerEvent(SecurityEventType.SERVER_STOPPED, 'SIGTERM received');
      console.log('Shutting down server gracefully...');
      process.exit(0);
    });
  }

  /**
   * Extract client ID from metadata
   */
  private getClientId(meta: any): string {
    // In a real implementation, this would extract actual client identification
    // For now, use a default identifier
    return meta?.clientId || 'claude-desktop';
  }

  /**
   * Create standardized error response
   */
  private createErrorResponse(error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return {
      content: [{
        type: "text" as const,
        text: `Error: ${errorMessage}`
      }],
      isError: true
    };
  }

  /**
   * Start the MCP server
   */
  async start(): Promise<void> {
    try {
      // Create logs directory if it doesn't exist
      await fs.mkdir('logs', { recursive: true });

      // Log server startup
      this.auditor.logServerEvent(SecurityEventType.SERVER_STARTED, 'MCP Terminal Server starting');

      // Create stdio transport for Claude Desktop integration
      const transport = new StdioServerTransport();
      
      // Connect server to transport
      await this.server.connect(transport);
      
      console.log('MCP Secure Terminal Server started successfully');
      console.log('Waiting for connections from Claude Desktop...');

    } catch (error) {
      this.auditor.logError('system', 'server_startup', error);
      console.error('Failed to start MCP server:', error);
      process.exit(1);
    }
  }
}

/**
 * Main entry point
 */
async function main() {
  try {
    const server = new SecureMcpTerminalServer();
    await server.start();
  } catch (error) {
    console.error('Fatal error starting server:', error);
    process.exit(1);
  }
}

// Start the server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { SecureMcpTerminalServer };
