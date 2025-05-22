import { describe, it, expect, beforeEach } from '@jest/globals';
import { 
  isCommandAllowed, 
  areArgsAllowed, 
  containsDangerousPatterns,
  isWorkingDirectorySafe 
} from '../src/commands/whitelist.js';
import { 
  sanitizeInput, 
  sanitizeOutput, 
  sanitizeFilePath,
  containsCredentials,
  createSafeErrorMessage 
} from '../src/security/sanitizer.js';
import { SecureCommandExecutor } from '../src/commands/executor.js';

describe('Command Whitelist Security', () => {
  it('should allow whitelisted commands', () => {
    expect(isCommandAllowed('ls')).toBe(true);
    expect(isCommandAllowed('pwd')).toBe(true);
    expect(isCommandAllowed('git')).toBe(true);
  });

  it('should block forbidden commands', () => {
    expect(isCommandAllowed('rm')).toBe(false);
    expect(isCommandAllowed('sudo')).toBe(false);
    expect(isCommandAllowed('bash')).toBe(false);
    expect(isCommandAllowed('python')).toBe(false);
  });

  it('should validate command arguments', () => {
    expect(areArgsAllowed('ls', ['-l', '-a'])).toBe(true);
    expect(areArgsAllowed('ls', ['../../../etc/passwd'])).toBe(false);
    expect(areArgsAllowed('cat', ['file.txt'])).toBe(true);
    expect(areArgsAllowed('cat', ['/etc/shadow'])).toBe(false);
  });

  it('should detect dangerous patterns', () => {
    expect(containsDangerousPatterns('normal_text')).toBe(false);
    expect(containsDangerousPatterns('command; rm -rf /')).toBe(true);
    expect(containsDangerousPatterns('$(evil_command)')).toBe(true);
    expect(containsDangerousPatterns('../../../etc/passwd')).toBe(true);
  });

  it('should validate working directories', () => {
    expect(isWorkingDirectorySafe('/home/user/project')).toBe(true);
    expect(isWorkingDirectorySafe('/etc')).toBe(false);
    expect(isWorkingDirectorySafe('/proc')).toBe(false);
    expect(isWorkingDirectorySafe('/root')).toBe(false);
  });
});

describe('Input Sanitization', () => {
  it('should sanitize basic input', () => {
    expect(sanitizeInput('normal_text')).toBe('normal_text');
    expect(() => sanitizeInput('<script>alert("xss")</script>')).toThrow();
    expect(() => sanitizeInput('command; rm -rf /')).toThrow();
  });

  it('should handle file paths safely', () => {
    expect(sanitizeFilePath('file.txt')).toBe('file.txt');
    expect(sanitizeFilePath('folder/file.txt')).toBe('folder/file.txt');
    expect(() => sanitizeFilePath('../../../etc/passwd')).toThrow();
    expect(() => sanitizeFilePath('/etc/shadow')).toThrow();
  });

  it('should detect credentials in text', () => {
    expect(containsCredentials('normal text')).toBe(false);
    expect(containsCredentials('api_key=abc123xyz')).toBe(true);
    expect(containsCredentials('password: secret123')).toBe(true);
    expect(containsCredentials('AKIA1234567890123456')).toBe(true); // AWS key
  });

  it('should sanitize output safely', () => {
    const normalOutput = 'file1.txt\nfile2.txt\n';
    expect(sanitizeOutput(normalOutput)).toBe(normalOutput);
    
    const outputWithCreds = 'api_key=secret123\nother_file.txt';
    const sanitized = sanitizeOutput(outputWithCreds);
    expect(sanitized).not.toContain('secret123');
    expect(sanitized).toContain('ap**ret123'); // Partially redacted
  });

  it('should create safe error messages', () => {
    const error = new Error('ENOENT: no such file or directory');
    expect(createSafeErrorMessage(error)).toBe('File or directory not found');
    
    const permissionError = new Error('EACCES: permission denied');
    expect(createSafeErrorMessage(permissionError)).toBe('Permission denied');
    
    const genericError = new Error('Some internal system error with sensitive data');
    expect(createSafeErrorMessage(genericError)).toBe('Command execution failed');
  });
});

describe('Command Executor Security', () => {
  let executor: SecureCommandExecutor;

  beforeEach(() => {
    executor = SecureCommandExecutor.getInstance();
  });

  it('should validate commands before execution', async () => {
    // Valid command should pass validation
    const validResult = await executor.validateCommand('list_directory', 'ls', ['-l']);
    expect(validResult.valid).toBe(true);

    // Invalid command should fail validation
    const invalidResult = await executor.validateCommand('malicious', 'rm', ['-rf', '/']);
    expect(invalidResult.valid).toBe(false);
    expect(invalidResult.error).toBeDefined();
  });

  it('should handle rate limiting', async () => {
    const stats = await executor.getExecutionStats('test-client');
    expect(stats).toHaveProperty('rateLimitStatus');
    expect(stats).toHaveProperty('isBlocked');
  });
});

describe('Security Edge Cases', () => {
  it('should handle null and undefined inputs', () => {
    expect(() => sanitizeInput(null as any)).toThrow();
    expect(() => sanitizeInput(undefined as any)).toThrow();
    expect(sanitizeOutput('')).toBe('');
    expect(sanitizeOutput(null as any)).toBe('');
  });

  it('should handle very long inputs', () => {
    const longInput = 'a'.repeat(20000);
    expect(() => sanitizeInput(longInput)).toThrow('Input too long');
  });

  it('should handle special characters safely', () => {
    const specialChars = '!@#$%^&*()[]{}|\\:";\'<>?,./';
    // Should not throw for basic special characters
    expect(() => sanitizeInput('file!@#.txt')).not.toThrow();
    // But should throw for dangerous shell characters
    expect(() => sanitizeInput('file; rm -rf /')).toThrow();
  });

  it('should prevent command injection through arguments', () => {
    expect(areArgsAllowed('ls', ['file.txt; rm -rf /'])).toBe(false);
    expect(areArgsAllowed('cat', ['$(whoami)'])).toBe(false);
    expect(areArgsAllowed('head', ['`id`'])).toBe(false);
  });

  it('should sanitize environment-based attacks', () => {
    const envAttack = 'export EVIL=payload; cat /etc/passwd';
    expect(containsDangerousPatterns(envAttack)).toBe(true);
    expect(() => sanitizeInput(envAttack)).toThrow();
  });
});
