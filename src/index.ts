/**
 * MCP Secure Terminal Server
 * 
 * Main module export for programmatic usage
 */

export { SecureMcpTerminalServer } from './server.js';
export { SecureCommandExecutor } from './commands/executor.js';
export { SecurityAuditor } from './security/audit.js';
export { CommandRateLimiter } from './security/rateLimit.js';
export { 
  COMMAND_WHITELIST, 
  FORBIDDEN_COMMANDS,
  isCommandAllowed,
  areArgsAllowed,
  getCommandDefinition 
} from './commands/whitelist.js';
export {
  sanitizeInput,
  sanitizeOutput,
  sanitizeFilePath,
  containsCredentials,
  createSafeErrorMessage
} from './security/sanitizer.js';

// Type exports
export type { CommandDefinition } from './commands/whitelist.js';
export type { CommandResult, ExecutionOptions } from './commands/executor.js';
export type { AuditLogEntry, SecurityEventType, RiskLevel } from './security/audit.js';
