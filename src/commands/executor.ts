import { spawn } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { 
  isCommandAllowed, 
  areArgsAllowed, 
  getCommandDefinition,
  isWorkingDirectorySafe 
} from './whitelist.js';
import { 
  sanitizeInput, 
  sanitizeCommandArgs, 
  sanitizeOutput, 
  sanitizeFilePath,
  validateWorkingDirectory,
  createSafeErrorMessage,
  stripAnsiCodes,
  limitOutputLines
} from '../security/sanitizer.js';
import { CommandRateLimiter } from '../security/rateLimit.js';
import { SecurityAuditor, SecurityEventType, RiskLevel } from '../security/audit.js';

/**
 * Command execution result
 */
export interface CommandResult {
  success: boolean;
  output: string;
  error?: string;
  exitCode?: number;
  executionTime: number;
  outputSize: number;
  truncated: boolean;
}

/**
 * Command execution options
 */
export interface ExecutionOptions {
  workingDirectory?: string;
  timeout?: number;
  maxOutputSize?: number;
  clientId?: string;
}

/**
 * Safe command executor with comprehensive security controls
 */
export class SecureCommandExecutor {
  private static instance: SecureCommandExecutor;
  private rateLimiter: CommandRateLimiter;
  private auditor: SecurityAuditor;
  private readonly DEFAULT_TIMEOUT = 30000; // 30 seconds
  private readonly MAX_OUTPUT_SIZE = 1048576; // 1MB
  private readonly MAX_LINES = 1000;

  private constructor() {
    this.rateLimiter = CommandRateLimiter.getInstance();
    this.auditor = SecurityAuditor.getInstance();
  }

  public static getInstance(): SecureCommandExecutor {
    if (!SecureCommandExecutor.instance) {
      SecureCommandExecutor.instance = new SecureCommandExecutor();
    }
    return SecureCommandExecutor.instance;
  }

  /**
   * Execute a command with full security validation
   */
  async executeCommand(
    toolName: string,
    command: string,
    args: string[] = [],
    options: ExecutionOptions = {}
  ): Promise<CommandResult> {
    const startTime = Date.now();
    const clientId = options.clientId || 'default';
    
    try {
      // Step 1: Input validation and sanitization
      await this.validateAndSanitizeInput(toolName, command, args, options, clientId);

      // Step 2: Rate limiting check
      await this.checkRateLimit(toolName, command, clientId);

      // Step 3: Working directory validation
      const workingDir = await this.validateWorkingDirectory(options.workingDirectory, clientId);

      // Step 4: Execute command safely
      const result = await this.executeSafeCommand(
        toolName,
        command,
        args,
        workingDir,
        options,
        clientId
      );

      // Step 5: Consume rate limit on success
      await this.rateLimiter.consumeRateLimit(toolName, command, clientId);

      // Step 6: Log successful execution
      this.auditor.logCommandExecution(
        clientId,
        toolName,
        command,
        args,
        workingDir,
        result.executionTime,
        result.outputSize
      );

      return result;

    } catch (error) {
      const executionTime = Date.now() - startTime;
      
      // Log error and handle rate limiting for failed attempts
      await this.handleExecutionError(error, toolName, command, args, clientId, executionTime);
      
      // Return safe error result
      return {
        success: false,
        output: '',
        error: createSafeErrorMessage(error),
        executionTime,
        outputSize: 0,
        truncated: false
      };
    }
  }

  /**
   * Validate and sanitize all inputs
   */
  private async validateAndSanitizeInput(
    toolName: string,
    command: string,
    args: string[],
    options: ExecutionOptions,
    clientId: string
  ): Promise<void> {
    // Sanitize command
    const sanitizedCommand = sanitizeInput(command);
    if (sanitizedCommand !== command) {
      this.auditor.logValidationFailure(clientId, toolName, 'command_sanitization', command);
      throw new Error('Command contains invalid characters');
    }

    // Check if command is allowed
    if (!isCommandAllowed(sanitizedCommand)) {
      this.auditor.logBlockedCommand(clientId, toolName, command, args, 'Command not in whitelist');
      throw new Error('Command not allowed');
    }

    // Sanitize arguments
    let sanitizedArgs: string[];
    try {
      sanitizedArgs = sanitizeCommandArgs(args);
    } catch (error) {
      this.auditor.logValidationFailure(clientId, toolName, 'argument_sanitization', args.join(' '));
      throw error;
    }

    // Validate arguments against whitelist
    if (!areArgsAllowed(sanitizedCommand, sanitizedArgs)) {
      this.auditor.logBlockedCommand(clientId, toolName, command, args, 'Arguments not allowed');
      throw new Error('Command arguments not allowed');
    }

    // Check for suspicious patterns in arguments
    const suspiciousArgs = args.filter(arg => this.containsSuspiciousPatterns(arg));
    if (suspiciousArgs.length > 0) {
      this.auditor.logSuspiciousActivity(
        clientId,
        'Suspicious command arguments',
        `Arguments: ${suspiciousArgs.join(', ')}`
      );
      throw new Error('Suspicious command arguments detected');
    }
  }

  /**
   * Check rate limiting
   */
  private async checkRateLimit(toolName: string, command: string, clientId: string): Promise<void> {
    const rateLimitResult = await this.rateLimiter.checkRateLimit(toolName, command, clientId);
    
    if (!rateLimitResult.allowed) {
      this.auditor.logRateLimitExceeded(clientId, toolName, rateLimitResult.error || 'Unknown limit');
      throw new Error(`Rate limit exceeded: ${rateLimitResult.error}`);
    }
  }

  /**
   * Validate working directory
   */
  private async validateWorkingDirectory(
    workingDirectory: string | undefined,
    clientId: string
  ): Promise<string> {
    const workingDir = workingDirectory || process.cwd();
    
    try {
      const sanitizedDir = sanitizeFilePath(workingDir);
      
      if (!isWorkingDirectorySafe(sanitizedDir)) {
        this.auditor.logPathTraversalAttempt(clientId, 'working_directory', workingDir);
        throw new Error('Working directory not allowed');
      }

      if (!validateWorkingDirectory(sanitizedDir)) {
        this.auditor.logValidationFailure(clientId, 'working_directory', 'directory_validation', workingDir);
        throw new Error('Invalid working directory');
      }

      return sanitizedDir;
    } catch (error) {
      this.auditor.logValidationFailure(clientId, 'working_directory', 'directory_sanitization', workingDir);
      throw error;
    }
  }

  /**
   * Execute command with safety controls
   */
  private async executeSafeCommand(
    toolName: string,
    command: string,
    args: string[],
    workingDir: string,
    options: ExecutionOptions,
    clientId: string
  ): Promise<CommandResult> {
    const startTime = Date.now();
    const timeout = options.timeout || this.DEFAULT_TIMEOUT;
    const maxOutputSize = options.maxOutputSize || this.MAX_OUTPUT_SIZE;

    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let outputSize = 0;
      let truncated = false;

      // Create child process with security restrictions
      const child = spawn(command, args, {
        cwd: workingDir,
        stdio: ['ignore', 'pipe', 'pipe'], // No stdin, capture stdout/stderr
        env: this.createSafeEnvironment(),
        timeout,
        killSignal: 'SIGTERM'
      });

      // Set up timeout
      const timeoutId = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('Command execution timed out'));
      }, timeout);

      // Handle stdout
      child.stdout?.on('data', (data: Buffer) => {
        const chunk = data.toString();
        outputSize += chunk.length;
        
        if (outputSize > maxOutputSize) {
          if (!truncated) {
            stdout += '[Output truncated - size limit exceeded]\n';
            truncated = true;
          }
          child.kill('SIGTERM');
          return;
        }
        
        stdout += chunk;
      });

      // Handle stderr
      child.stderr?.on('data', (data: Buffer) => {
        const chunk = data.toString();
        outputSize += chunk.length;
        
        if (outputSize > maxOutputSize) {
          if (!truncated) {
            stderr += '[Error output truncated - size limit exceeded]\n';
            truncated = true;
          }
          child.kill('SIGTERM');
          return;
        }
        
        stderr += chunk;
      });

      // Handle process completion
      child.on('close', (code, signal) => {
        clearTimeout(timeoutId);
        const executionTime = Date.now() - startTime;

        if (signal === 'SIGTERM') {
          reject(new Error('Command was terminated'));
          return;
        }

        // Sanitize outputs
        const sanitizedStdout = this.sanitizeAndLimitOutput(stdout);
        const sanitizedStderr = this.sanitizeAndLimitOutput(stderr);
        
        // Combine outputs
        let output = sanitizedStdout;
        if (sanitizedStderr) {
          output += sanitizedStderr ? `\n--- STDERR ---\n${sanitizedStderr}` : '';
        }

        resolve({
          success: code === 0,
          output,
          error: code !== 0 ? sanitizedStderr || `Command exited with code ${code}` : undefined,
          exitCode: code || 0,
          executionTime,
          outputSize,
          truncated
        });
      });

      // Handle process errors
      child.on('error', (error) => {
        clearTimeout(timeoutId);
        reject(error);
      });
    });
  }

  /**
   * Create safe environment for command execution
   */
  private createSafeEnvironment(): Record<string, string> {
    // Start with minimal environment
    const safeEnv: Record<string, string> = {
      PATH: '/usr/local/bin:/usr/bin:/bin',
      HOME: process.env.HOME || '/tmp',
      USER: process.env.USER || 'unknown',
      SHELL: '/bin/sh',
      TERM: 'xterm'
    };

    // Add safe environment variables if they exist
    const safeVars = ['LANG', 'LC_ALL', 'TZ'];
    safeVars.forEach(varName => {
      if (process.env[varName]) {
        safeEnv[varName] = process.env[varName]!;
      }
    });

    return safeEnv;
  }

  /**
   * Sanitize and limit command output
   */
  private sanitizeAndLimitOutput(output: string): string {
    if (!output) return '';
    
    // Strip ANSI codes
    let sanitized = stripAnsiCodes(output);
    
    // Limit number of lines
    sanitized = limitOutputLines(sanitized, this.MAX_LINES);
    
    // Sanitize for credentials and sensitive content
    sanitized = sanitizeOutput(sanitized);
    
    return sanitized;
  }

  /**
   * Check for suspicious patterns in input
   */
  private containsSuspiciousPatterns(input: string): boolean {
    const suspiciousPatterns = [
      /[;&|`$(){}[\]]/,  // Shell metacharacters
      /\.\./,            // Path traversal
      /\/etc\//,         // System directories
      /password|passwd|secret|key|token/i, // Credential-related terms
      /eval|exec|system|shell_exec/i,      // Code execution
      /union.*select|drop.*table/i,        // SQL injection
      /\<script\>/i,     // Script injection
    ];

    return suspiciousPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Handle execution errors
   */
  private async handleExecutionError(
    error: unknown,
    toolName: string,
    command: string,
    args: string[],
    clientId: string,
    executionTime: number
  ): Promise<void> {
    // Log the error
    this.auditor.logError(clientId, toolName, error);

    // Record failed attempt for rate limiting
    try {
      await this.rateLimiter.recordFailedAttempt(clientId);
    } catch (rateLimitError) {
      // Client is now blocked due to too many failed attempts
      this.auditor.logSuspiciousActivity(
        clientId,
        'Too many failed attempts',
        'Client blocked due to excessive failures'
      );
    }

    // Check if this looks like suspicious activity
    if (error instanceof Error) {
      if (error.message.includes('not allowed') || 
          error.message.includes('Suspicious') ||
          error.message.includes('injection')) {
        try {
          await this.rateLimiter.recordSuspiciousActivity(clientId, error.message);
        } catch (suspiciousLimitError) {
          // Client is now blocked for suspicious activity
          this.auditor.logSuspiciousActivity(
            clientId,
            'Suspicious activity threshold exceeded',
            'Client blocked for security reasons'
          );
        }
      }
    }
  }

  /**
   * Get execution statistics
   */
  async getExecutionStats(clientId: string = 'default'): Promise<{
    rateLimitStatus: any;
    isBlocked: boolean;
  }> {
    const rateLimitStatus = await this.rateLimiter.getRateLimitStatus(clientId);
    const isBlocked = await this.rateLimiter.isBlocked(clientId);

    return {
      rateLimitStatus,
      isBlocked
    };
  }

  /**
   * Validate command without executing (for testing)
   */
  async validateCommand(
    toolName: string,
    command: string,
    args: string[] = [],
    options: ExecutionOptions = {}
  ): Promise<{ valid: boolean; error?: string }> {
    const clientId = options.clientId || 'test';

    try {
      await this.validateAndSanitizeInput(toolName, command, args, options, clientId);
      await this.checkRateLimit(toolName, command, clientId);
      await this.validateWorkingDirectory(options.workingDirectory, clientId);
      
      return { valid: true };
    } catch (error) {
      return { 
        valid: false, 
        error: createSafeErrorMessage(error) 
      };
    }
  }
}

/**
 * Default export for easy import
 */
export default SecureCommandExecutor;
