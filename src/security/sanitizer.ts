import validator from 'validator';

/**
 * Patterns for detecting sensitive information in command outputs
 */
const CREDENTIAL_PATTERNS = [
  // API Keys and tokens
  /[Aa]pi[_-]?[Kk]ey[s]?[\s]*[:=][\s]*['"]?([A-Za-z0-9_-]{20,})['"]?/g,
  /[Tt]oken[\s]*[:=][\s]*['"]?([A-Za-z0-9_.-]{20,})['"]?/g,
  /[Aa]ccess[_-]?[Tt]oken[\s]*[:=][\s]*['"]?([A-Za-z0-9_.-]{20,})['"]?/g,
  
  // Private keys
  /-----BEGIN[A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]+PRIVATE KEY-----/g,
  /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
  
  // Database connection strings
  /(?:mongodb|mysql|postgresql|redis):\/\/[^\s]+/g,
  /[Dd]atabase[_-]?[Uu]rl[\s]*[:=][\s]*['"]?([^'"\s]+)['"]?/g,
  
  // Email and password combinations
  /[Pp]assword[\s]*[:=][\s]*['"]?([^'"\s]{6,})['"]?/g,
  /[Ee]mail[\s]*[:=][\s]*['"]?([^'"\s]+@[^'"\s]+)['"]?/g,
  
  // AWS credentials
  /AKIA[0-9A-Z]{16}/g,
  /[Aa]ws[_-]?[Aa]ccess[_-]?[Kk]ey[_-]?[Ii]d[\s]*[:=][\s]*['"]?([A-Z0-9]{20})['"]?/g,
  /[Aa]ws[_-]?[Ss]ecret[_-]?[Aa]ccess[_-]?[Kk]ey[\s]*[:=][\s]*['"]?([A-Za-z0-9/+=]{40})['"]?/g,
  
  // GitHub tokens
  /ghp_[A-Za-z0-9]{36}/g,
  /gho_[A-Za-z0-9]{36}/g,
  /ghu_[A-Za-z0-9]{36}/g,
  /ghs_[A-Za-z0-9]{36}/g,
  
  // SSH keys
  /ssh-rsa\s+[A-Za-z0-9+/=]+/g,
  /ssh-ed25519\s+[A-Za-z0-9+/=]+/g,
  
  // Environment variables that often contain secrets
  /[A-Z_]+SECRET[A-Z_]*[\s]*[:=][\s]*['"]?([^'"\s]+)['"]?/g,
  /[A-Z_]+KEY[A-Z_]*[\s]*[:=][\s]*['"]?([^'"\s]+)['"]?/g,
  /[A-Z_]+TOKEN[A-Z_]*[\s]*[:=][\s]*['"]?([^'"\s]+)['"]?/g,
];

/**
 * Patterns for detecting potentially harmful content
 */
const HARMFUL_PATTERNS = [
  // Script injection attempts
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /onload[\s]*=/gi,
  /onerror[\s]*=/gi,
  /onclick[\s]*=/gi,
  
  // Path traversal attempts
  /\.\.\/|\.\.\\/g,
  /\/etc\/passwd/gi,
  /\/etc\/shadow/gi,
  
  // Command injection attempts
  /[;&|`$(){}[\]]/g,
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  
  // SQL injection patterns
  /union[\s]+select/gi,
  /drop[\s]+table/gi,
  /delete[\s]+from/gi,
  
  // LDAP injection
  /\(\|\(/g,
  /\)\|\)/g,
];

/**
 * File paths that should be redacted from outputs
 */
const SENSITIVE_PATHS = [
  /\/home\/[^\/]+\/\.(ssh|aws|docker|kube)/g,
  /\/Users\/[^\/]+\/\.(ssh|aws|docker|kube)/g,
  /C:\\Users\\[^\\]+\\\.ssh/g,
  /\/etc\/(passwd|shadow|sudoers)/g,
  /\/var\/log\/[^\/]*\.log/g,
];

/**
 * Sanitize input to prevent injection attacks
 */
export function sanitizeInput(input: string): string {
  if (!input || typeof input !== 'string') {
    return '';
  }
  
  // Basic input validation
  if (input.length > 10000) {
    throw new Error('Input too long');
  }
  
  // Escape special characters
  let sanitized = validator.escape(input);
  
  // Remove null bytes and control characters
  sanitized = sanitized.replace(/\x00/g, '');
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  
  // Check for harmful patterns
  if (HARMFUL_PATTERNS.some(pattern => pattern.test(sanitized))) {
    throw new Error('Input contains potentially harmful content');
  }
  
  return sanitized;
}

/**
 * Sanitize command arguments
 */
export function sanitizeCommandArgs(args: string[]): string[] {
  return args.map(arg => {
    const sanitized = sanitizeInput(arg);
    
    // Additional validation for command arguments
    if (sanitized.includes('..')) {
      throw new Error('Path traversal attempt detected');
    }
    
    if (sanitized.length > 1000) {
      throw new Error('Command argument too long');
    }
    
    return sanitized;
  });
}

/**
 * Sanitize command output to remove sensitive information
 */
export function sanitizeOutput(output: string, maxLength: number = 50000): string {
  if (!output || typeof output !== 'string') {
    return '';
  }
  
  // Truncate if too long
  if (output.length > maxLength) {
    output = output.substring(0, maxLength) + '\n[Output truncated for security]';
  }
  
  let sanitized = output;
  
  // Remove credentials and sensitive information
  CREDENTIAL_PATTERNS.forEach(pattern => {
    sanitized = sanitized.replace(pattern, (match, group1) => {
      if (group1 && group1.length > 4) {
        // Keep first 2 and last 2 characters, mask the rest
        return match.replace(group1, group1.substring(0, 2) + '*'.repeat(Math.max(4, group1.length - 4)) + group1.substring(group1.length - 2));
      }
      return '[REDACTED]';
    });
  });
  
  // Remove sensitive file paths
  SENSITIVE_PATHS.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '[SENSITIVE_PATH_REDACTED]');
  });
  
  // Remove potentially harmful content
  HARMFUL_PATTERNS.forEach(pattern => {
    sanitized = sanitized.replace(pattern, '[POTENTIALLY_HARMFUL_CONTENT_REMOVED]');
  });
  
  // Clean up any remaining control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  
  return sanitized;
}

/**
 * Validate and sanitize file path
 */
export function sanitizeFilePath(filePath: string): string {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('Invalid file path');
  }
  
  // Basic validation
  if (filePath.length > 4096) {
    throw new Error('File path too long');
  }
  
  // Normalize path separators
  const normalized = filePath.replace(/\\/g, '/');
  
  // Check for path traversal
  if (normalized.includes('../') || normalized.includes('./')) {
    throw new Error('Path traversal not allowed');
  }
  
  // Check for absolute paths to sensitive directories
  const sensitiveDirectories = [
    '/etc/', '/proc/', '/sys/', '/dev/', '/boot/', '/root/',
    '/var/log/', '/var/run/', '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/'
  ];
  
  if (sensitiveDirectories.some(dir => normalized.startsWith(dir))) {
    throw new Error('Access to sensitive directory not allowed');
  }
  
  // Remove any remaining dangerous characters
  const sanitized = normalized.replace(/[;&|`$(){}[\]<>]/g, '');
  
  return sanitized;
}

/**
 * Check if output contains potential credentials
 */
export function containsCredentials(text: string): boolean {
  return CREDENTIAL_PATTERNS.some(pattern => pattern.test(text));
}

/**
 * Create a safe error message that doesn't leak information
 */
export function createSafeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // Only return generic error messages to prevent information leakage
    if (error.message.includes('ENOENT')) {
      return 'File or directory not found';
    }
    if (error.message.includes('EACCES')) {
      return 'Permission denied';
    }
    if (error.message.includes('ETIMEDOUT')) {
      return 'Operation timed out';
    }
    if (error.message.includes('command not found')) {
      return 'Command not found';
    }
    
    // For validation errors, return the message as it's safe
    if (error.message.includes('not allowed') || 
        error.message.includes('Invalid') ||
        error.message.includes('too long') ||
        error.message.includes('harmful content')) {
      return error.message;
    }
  }
  
  // Generic error message for anything else
  return 'Command execution failed';
}

/**
 * Validate working directory path
 */
export function validateWorkingDirectory(dirPath: string): boolean {
  try {
    const sanitized = sanitizeFilePath(dirPath);
    
    // Must be a relative path or absolute path under allowed directories
    const allowedPrefixes = [
      '/home/', '/Users/', '/workspace/', '/app/', '/opt/',
      './src/', './docs/', './tests/', './examples/'
    ];
    
    // Allow current directory and subdirectories
    if (sanitized === '.' || sanitized.startsWith('./')) {
      return true;
    }
    
    // Check against allowed prefixes
    return allowedPrefixes.some(prefix => sanitized.startsWith(prefix));
  } catch {
    return false;
  }
}

/**
 * Strip ANSI color codes from output
 */
export function stripAnsiCodes(text: string): string {
  // ANSI escape code pattern
  const ansiPattern = /\x1b\[[0-9;]*m/g;
  return text.replace(ansiPattern, '');
}

/**
 * Limit output lines for safety
 */
export function limitOutputLines(output: string, maxLines: number = 1000): string {
  const lines = output.split('\n');
  if (lines.length > maxLines) {
    return lines.slice(0, maxLines).join('\n') + `\n[Output limited to ${maxLines} lines for security]`;
  }
  return output;
}
