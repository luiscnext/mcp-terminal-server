import winston from 'winston';
import { createSafeErrorMessage } from './sanitizer.js';

/**
 * Security event types for audit logging
 */
export enum SecurityEventType {
  COMMAND_EXECUTED = 'COMMAND_EXECUTED',
  COMMAND_BLOCKED = 'COMMAND_BLOCKED',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  VALIDATION_FAILED = 'VALIDATION_FAILED',
  CREDENTIAL_DETECTED = 'CREDENTIAL_DETECTED',
  PATH_TRAVERSAL_ATTEMPT = 'PATH_TRAVERSAL_ATTEMPT',
  INJECTION_ATTEMPT = 'INJECTION_ATTEMPT',
  SERVER_STARTED = 'SERVER_STARTED',
  SERVER_STOPPED = 'SERVER_STOPPED',
  CLIENT_CONNECTED = 'CLIENT_CONNECTED',
  CLIENT_DISCONNECTED = 'CLIENT_DISCONNECTED',
  ERROR_OCCURRED = 'ERROR_OCCURRED'
}

/**
 * Risk levels for security events
 */
export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

/**
 * Audit log entry structure
 */
export interface AuditLogEntry {
  timestamp: string;
  eventType: SecurityEventType;
  riskLevel: RiskLevel;
  clientId: string;
  toolName?: string;
  command?: string;
  args?: string[];
  workingDirectory?: string;
  success: boolean;
  errorMessage?: string;
  executionTime?: number;
  outputSize?: number;
  metadata?: Record<string, unknown>;
}

/**
 * Security audit logger
 */
export class SecurityAuditor {
  private static instance: SecurityAuditor;
  private logger: winston.Logger;
  private securityLogger: winston.Logger;

  private constructor() {
    this.initializeLoggers();
  }

  public static getInstance(): SecurityAuditor {
    if (!SecurityAuditor.instance) {
      SecurityAuditor.instance = new SecurityAuditor();
    }
    return SecurityAuditor.instance;
  }

  private initializeLoggers(): void {
    // Main application logger
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'mcp-terminal-server' },
      transports: [
        new winston.transports.File({ 
          filename: 'logs/error.log', 
          level: 'error',
          maxsize: 10485760, // 10MB
          maxFiles: 5
        }),
        new winston.transports.File({ 
          filename: 'logs/combined.log',
          maxsize: 10485760, // 10MB
          maxFiles: 10
        }),
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });

    // Dedicated security audit logger
    this.securityLogger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      defaultMeta: { 
        service: 'mcp-terminal-server',
        component: 'security-audit'
      },
      transports: [
        new winston.transports.File({ 
          filename: 'logs/security-audit.log',
          maxsize: 52428800, // 50MB
          maxFiles: 20 // Keep more security logs
        }),
        // Also log high-risk events to a separate file
        new winston.transports.File({
          filename: 'logs/security-alerts.log',
          level: 'warn',
          maxsize: 10485760, // 10MB
          maxFiles: 10
        })
      ]
    });
  }

  /**
   * Log a security event
   */
  logSecurityEvent(entry: Omit<AuditLogEntry, 'timestamp'>): void {
    const auditEntry: AuditLogEntry = {
      ...entry,
      timestamp: new Date().toISOString()
    };

    // Sanitize sensitive data before logging
    const sanitizedEntry = this.sanitizeAuditEntry(auditEntry);

    // Determine log level based on risk
    const logLevel = this.getLogLevel(entry.riskLevel);
    
    // Log to security audit log
    this.securityLogger.log(logLevel, 'Security event', sanitizedEntry);

    // Log high-risk events to main logger as well
    if (entry.riskLevel === RiskLevel.HIGH || entry.riskLevel === RiskLevel.CRITICAL) {
      this.logger.warn('High-risk security event', sanitizedEntry);
    }
  }

  /**
   * Log successful command execution
   */
  logCommandExecution(
    clientId: string,
    toolName: string,
    command: string,
    args: string[],
    workingDirectory: string,
    executionTime: number,
    outputSize: number,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.COMMAND_EXECUTED,
      riskLevel: RiskLevel.LOW,
      clientId,
      toolName,
      command,
      args,
      workingDirectory,
      success: true,
      executionTime,
      outputSize,
      metadata
    });
  }

  /**
   * Log blocked command attempt
   */
  logBlockedCommand(
    clientId: string,
    toolName: string,
    command: string,
    args: string[],
    reason: string,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.COMMAND_BLOCKED,
      riskLevel: RiskLevel.MEDIUM,
      clientId,
      toolName,
      command,
      args,
      success: false,
      errorMessage: reason,
      metadata
    });
  }

  /**
   * Log rate limit exceeded
   */
  logRateLimitExceeded(
    clientId: string,
    toolName: string,
    limitType: string,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.RATE_LIMIT_EXCEEDED,
      riskLevel: RiskLevel.MEDIUM,
      clientId,
      toolName,
      success: false,
      errorMessage: `Rate limit exceeded: ${limitType}`,
      metadata
    });
  }

  /**
   * Log suspicious activity
   */
  logSuspiciousActivity(
    clientId: string,
    activity: string,
    details: string,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.SUSPICIOUS_ACTIVITY,
      riskLevel: RiskLevel.HIGH,
      clientId,
      success: false,
      errorMessage: `${activity}: ${details}`,
      metadata
    });
  }

  /**
   * Log validation failure
   */
  logValidationFailure(
    clientId: string,
    toolName: string,
    validationType: string,
    input: string,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.VALIDATION_FAILED,
      riskLevel: RiskLevel.MEDIUM,
      clientId,
      toolName,
      success: false,
      errorMessage: `Validation failed: ${validationType}`,
      metadata: {
        ...metadata,
        inputLength: input.length,
        // Don't log the actual input for security
        inputPreview: input.substring(0, 50) + (input.length > 50 ? '...' : '')
      }
    });
  }

  /**
   * Log credential detection
   */
  logCredentialDetection(
    clientId: string,
    location: string,
    credentialType: string,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.CREDENTIAL_DETECTED,
      riskLevel: RiskLevel.CRITICAL,
      clientId,
      success: false,
      errorMessage: `Potential credential detected in ${location}: ${credentialType}`,
      metadata
    });
  }

  /**
   * Log path traversal attempt
   */
  logPathTraversalAttempt(
    clientId: string,
    toolName: string,
    attemptedPath: string,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.PATH_TRAVERSAL_ATTEMPT,
      riskLevel: RiskLevel.HIGH,
      clientId,
      toolName,
      success: false,
      errorMessage: `Path traversal attempt: ${attemptedPath}`,
      metadata
    });
  }

  /**
   * Log injection attempt
   */
  logInjectionAttempt(
    clientId: string,
    toolName: string,
    injectionType: string,
    payload: string,
    metadata?: Record<string, unknown>
  ): void {
    this.logSecurityEvent({
      eventType: SecurityEventType.INJECTION_ATTEMPT,
      riskLevel: RiskLevel.CRITICAL,
      clientId,
      toolName,
      success: false,
      errorMessage: `${injectionType} injection attempt`,
      metadata: {
        ...metadata,
        payloadLength: payload.length,
        // Don't log the actual payload for security
        payloadPreview: payload.substring(0, 30) + (payload.length > 30 ? '...' : '')
      }
    });
  }

  /**
   * Log server lifecycle events
   */
  logServerEvent(eventType: SecurityEventType, details?: string): void {
    this.logSecurityEvent({
      eventType,
      riskLevel: RiskLevel.LOW,
      clientId: 'system',
      success: true,
      errorMessage: details
    });
  }

  /**
   * Log error with safe message
   */
  logError(
    clientId: string,
    toolName: string,
    error: unknown,
    metadata?: Record<string, unknown>
  ): void {
    const safeErrorMessage = createSafeErrorMessage(error);
    
    this.logSecurityEvent({
      eventType: SecurityEventType.ERROR_OCCURRED,
      riskLevel: RiskLevel.MEDIUM,
      clientId,
      toolName,
      success: false,
      errorMessage: safeErrorMessage,
      metadata
    });

    // Also log to main logger for debugging
    this.logger.error('Command execution error', {
      clientId,
      toolName,
      error: safeErrorMessage,
      metadata
    });
  }

  /**
   * Get log level from risk level
   */
  private getLogLevel(riskLevel: RiskLevel): string {
    switch (riskLevel) {
      case RiskLevel.LOW:
        return 'info';
      case RiskLevel.MEDIUM:
        return 'warn';
      case RiskLevel.HIGH:
      case RiskLevel.CRITICAL:
        return 'error';
      default:
        return 'info';
    }
  }

  /**
   * Sanitize audit entry to remove sensitive information
   */
  private sanitizeAuditEntry(entry: AuditLogEntry): AuditLogEntry {
    const sanitized = { ...entry };

    // Sanitize command arguments
    if (sanitized.args) {
      sanitized.args = sanitized.args.map(arg => {
        // If argument looks like a password or key, redact it
        if (/password|secret|key|token/i.test(arg) && arg.includes('=')) {
          const [key, ] = arg.split('=', 2);
          return `${key}=[REDACTED]`;
        }
        return arg;
      });
    }

    // Sanitize working directory if it contains sensitive paths
    if (sanitized.workingDirectory) {
      sanitized.workingDirectory = sanitized.workingDirectory.replace(
        /\/home\/[^\/]+/g, 
        '/home/[USER]'
      );
      sanitized.workingDirectory = sanitized.workingDirectory.replace(
        /\/Users\/[^\/]+/g, 
        '/Users/[USER]'
      );
    }

    // Sanitize metadata
    if (sanitized.metadata) {
      const cleanMetadata = { ...sanitized.metadata };
      Object.keys(cleanMetadata).forEach(key => {
        if (typeof cleanMetadata[key] === 'string') {
          const value = cleanMetadata[key] as string;
          if (value.length > 1000) {
            cleanMetadata[key] = value.substring(0, 1000) + '[TRUNCATED]';
          }
        }
      });
      sanitized.metadata = cleanMetadata;
    }

    return sanitized;
  }

  /**
   * Get audit statistics
   */
  async getAuditStatistics(hours: number = 24): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsByRisk: Record<string, number>;
    suspiciousActivities: number;
    blockedCommands: number;
  }> {
    // This would typically query the log files or a database
    // For now, return a placeholder structure
    return {
      totalEvents: 0,
      eventsByType: {},
      eventsByRisk: {},
      suspiciousActivities: 0,
      blockedCommands: 0
    };
  }

  /**
   * Export logs for external analysis
   */
  async exportLogs(startDate: Date, endDate: Date): Promise<AuditLogEntry[]> {
    // This would typically read from log files or database
    // For now, return empty array
    return [];
  }
}

/**
 * Default export for easy import
 */
export default SecurityAuditor;
