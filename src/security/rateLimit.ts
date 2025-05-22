import { RateLimiterMemory } from 'rate-limiter-flexible';
import { getCommandDefinition } from '../commands/whitelist.js';

/**
 * Rate limiter instances for different command categories
 */
export class CommandRateLimiter {
  private static instance: CommandRateLimiter;
  private limiters: Map<string, RateLimiterMemory>;
  private globalLimiter: RateLimiterMemory;

  private constructor() {
    this.limiters = new Map();
    
    // Global rate limiter - maximum commands per minute across all tools
    this.globalLimiter = new RateLimiterMemory({
      points: 100, // Maximum 100 commands per minute globally
      duration: 60, // Per 60 seconds
      blockDuration: 60, // Block for 60 seconds if limit exceeded
    });
    
    this.initializeCommandLimiters();
  }

  public static getInstance(): CommandRateLimiter {
    if (!CommandRateLimiter.instance) {
      CommandRateLimiter.instance = new CommandRateLimiter();
    }
    return CommandRateLimiter.instance;
  }

  private initializeCommandLimiters(): void {
    // Risk-based rate limiting
    const riskLimiters = {
      low: new RateLimiterMemory({
        points: 50, // 50 executions per minute for low-risk commands
        duration: 60,
        blockDuration: 30,
      }),
      medium: new RateLimiterMemory({
        points: 20, // 20 executions per minute for medium-risk commands
        duration: 60,
        blockDuration: 60,
      }),
      high: new RateLimiterMemory({
        points: 5, // 5 executions per minute for high-risk commands
        duration: 60,
        blockDuration: 120,
      }),
    };

    this.limiters.set('risk_low', riskLimiters.low);
    this.limiters.set('risk_medium', riskLimiters.medium);
    this.limiters.set('risk_high', riskLimiters.high);

    // Tool-specific rate limiters for additional granular control
    const toolLimiters = {
      // Directory operations
      list_directory: new RateLimiterMemory({
        points: 30,
        duration: 60,
        blockDuration: 30,
      }),
      
      // File operations
      read_file: new RateLimiterMemory({
        points: 20,
        duration: 60,
        blockDuration: 60,
      }),
      
      // Command execution
      execute_command: new RateLimiterMemory({
        points: 15,
        duration: 60,
        blockDuration: 60,
      }),
      
      // Git operations
      git_status: new RateLimiterMemory({
        points: 10,
        duration: 60,
        blockDuration: 60,
      }),
      
      // System information
      system_info: new RateLimiterMemory({
        points: 5,
        duration: 60,
        blockDuration: 60,
      }),
    };

    Object.entries(toolLimiters).forEach(([tool, limiter]) => {
      this.limiters.set(`tool_${tool}`, limiter);
    });

    // Failed attempt limiter - progressive blocking for failed attempts
    this.limiters.set('failed_attempts', new RateLimiterMemory({
      points: 10, // Allow 10 failed attempts
      duration: 300, // Per 5 minutes
      blockDuration: 600, // Block for 10 minutes
    }));

    // Suspicious activity limiter - for potential security threats
    this.limiters.set('suspicious_activity', new RateLimiterMemory({
      points: 3, // Only 3 suspicious attempts
      duration: 3600, // Per hour
      blockDuration: 3600, // Block for 1 hour
    }));
  }

  /**
   * Check if a command execution is allowed based on rate limits
   */
  async checkRateLimit(
    toolName: string, 
    command: string, 
    clientId: string = 'default'
  ): Promise<{ allowed: boolean; resetTime?: Date; remainingPoints?: number; error?: string }> {
    try {
      // Check global rate limit first
      const globalResult = await this.globalLimiter.get(clientId);
      if (globalResult && globalResult.remainingPoints !== undefined && globalResult.remainingPoints <= 0) {
        return {
          allowed: false,
          resetTime: new Date(Date.now() + (globalResult.msBeforeNext || 0)),
          remainingPoints: 0,
          error: 'Global rate limit exceeded'
        };
      }

      // Check tool-specific rate limit
      const toolLimiter = this.limiters.get(`tool_${toolName}`);
      if (toolLimiter) {
        const toolResult = await toolLimiter.get(clientId);
        if (toolResult && toolResult.remainingPoints !== undefined && toolResult.remainingPoints <= 0) {
          return {
            allowed: false,
            resetTime: new Date(Date.now() + (toolResult.msBeforeNext || 0)),
            remainingPoints: 0,
            error: `Tool rate limit exceeded for ${toolName}`
          };
        }
      }

      // Check risk-based rate limit
      const cmdDef = getCommandDefinition(command);
      if (cmdDef) {
        const riskLimiter = this.limiters.get(`risk_${cmdDef.riskLevel}`);
        if (riskLimiter) {
          const riskResult = await riskLimiter.get(clientId);
          if (riskResult && riskResult.remainingPoints !== undefined && riskResult.remainingPoints <= 0) {
            return {
              allowed: false,
              resetTime: new Date(Date.now() + (riskResult.msBeforeNext || 0)),
              remainingPoints: 0,
              error: `Risk-based rate limit exceeded for ${cmdDef.riskLevel} risk commands`
            };
          }
        }
      }

      return { allowed: true };
    } catch (error) {
      // If rate limiting fails, err on the side of caution
      return {
        allowed: false,
        error: 'Rate limiting check failed'
      };
    }
  }

  /**
   * Consume rate limit points for successful execution
   */
  async consumeRateLimit(
    toolName: string,
    command: string,
    clientId: string = 'default'
  ): Promise<void> {
    try {
      // Consume global rate limit
      await this.globalLimiter.consume(clientId);

      // Consume tool-specific rate limit
      const toolLimiter = this.limiters.get(`tool_${toolName}`);
      if (toolLimiter) {
        await toolLimiter.consume(clientId);
      }

      // Consume risk-based rate limit
      const cmdDef = getCommandDefinition(command);
      if (cmdDef) {
        const riskLimiter = this.limiters.get(`risk_${cmdDef.riskLevel}`);
        if (riskLimiter) {
          await riskLimiter.consume(clientId);
        }
      }
    } catch (error) {
      // Rate limit exceeded - this should have been caught in checkRateLimit
      throw new Error('Rate limit exceeded during consumption');
    }
  }

  /**
   * Record a failed attempt
   */
  async recordFailedAttempt(clientId: string = 'default'): Promise<void> {
    try {
      const failedLimiter = this.limiters.get('failed_attempts');
      if (failedLimiter) {
        await failedLimiter.consume(clientId);
      }
    } catch (error) {
      // Too many failed attempts - client is now blocked
      throw new Error('Too many failed attempts - client blocked');
    }
  }

  /**
   * Record suspicious activity
   */
  async recordSuspiciousActivity(
    clientId: string = 'default',
    reason: string
  ): Promise<void> {
    try {
      const suspiciousLimiter = this.limiters.get('suspicious_activity');
      if (suspiciousLimiter) {
        await suspiciousLimiter.consume(clientId);
      }
    } catch (error) {
      // Too much suspicious activity - client is now blocked for longer
      throw new Error(`Suspicious activity detected: ${reason} - client blocked`);
    }
  }

  /**
   * Check if client is currently blocked
   */
  async isBlocked(clientId: string = 'default'): Promise<boolean> {
    try {
      const checks = [
        this.globalLimiter.get(clientId),
        this.limiters.get('failed_attempts')?.get(clientId),
        this.limiters.get('suspicious_activity')?.get(clientId)
      ];

      const results = await Promise.all(checks.filter(Boolean));
      return results.some(result => 
        result && result.remainingPoints !== undefined && result.remainingPoints <= 0
      );
    } catch (error) {
      // If we can't check, assume blocked for safety
      return true;
    }
  }

  /**
   * Get rate limit status for a client
   */
  async getRateLimitStatus(clientId: string = 'default'): Promise<{
    global: { remaining: number; resetTime: Date } | null;
    failedAttempts: { remaining: number; resetTime: Date } | null;
    suspicious: { remaining: number; resetTime: Date } | null;
  }> {
    try {
      const globalResult = await this.globalLimiter.get(clientId);
      const failedResult = await this.limiters.get('failed_attempts')?.get(clientId);
      const suspiciousResult = await this.limiters.get('suspicious_activity')?.get(clientId);

      return {
        global: globalResult ? {
          remaining: globalResult.remainingPoints || 0,
          resetTime: new Date(Date.now() + (globalResult.msBeforeNext || 0))
        } : null,
        failedAttempts: failedResult ? {
          remaining: failedResult.remainingPoints || 0,
          resetTime: new Date(Date.now() + (failedResult.msBeforeNext || 0))
        } : null,
        suspicious: suspiciousResult ? {
          remaining: suspiciousResult.remainingPoints || 0,
          resetTime: new Date(Date.now() + (suspiciousResult.msBeforeNext || 0))
        } : null
      };
    } catch (error) {
      throw new Error('Failed to get rate limit status');
    }
  }

  /**
   * Reset rate limits for a client (admin function)
   */
  async resetRateLimits(clientId: string): Promise<void> {
    try {
      await this.globalLimiter.delete(clientId);
      
      for (const limiter of this.limiters.values()) {
        await limiter.delete(clientId);
      }
    } catch (error) {
      throw new Error('Failed to reset rate limits');
    }
  }

  /**
   * Get all active limiters for monitoring
   */
  getActiveLimiters(): string[] {
    return ['global', ...Array.from(this.limiters.keys())];
  }
}

/**
 * Default export for easy import
 */
export default CommandRateLimiter;
