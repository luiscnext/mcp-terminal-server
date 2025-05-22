export interface CommandDefinition {
  command: string;
  description: string;
  allowedArgs: string[];
  riskLevel: 'low' | 'medium' | 'high';
  requiresArgs?: boolean;
  maxExecutionsPerMinute: number;
}

/**
 * Whitelist of allowed commands with strict validation rules
 * Following the principle of least privilege
 */
export const COMMAND_WHITELIST: Record<string, CommandDefinition> = {
  // Directory operations (low risk)
  'ls': {
    command: 'ls',
    description: 'List directory contents',
    allowedArgs: ['-l', '-la', '-a', '-h', '--help'],
    riskLevel: 'low',
    maxExecutionsPerMinute: 30
  },
  'pwd': {
    command: 'pwd',
    description: 'Print working directory',
    allowedArgs: [],
    riskLevel: 'low',
    maxExecutionsPerMinute: 30
  },
  'tree': {
    command: 'tree',
    description: 'Display directory tree structure',
    allowedArgs: ['-L', '-a', '-d', '--help'],
    riskLevel: 'low',
    maxExecutionsPerMinute: 10
  },

  // File operations (low to medium risk)
  'cat': {
    command: 'cat',
    description: 'Display file contents',
    allowedArgs: [],
    riskLevel: 'medium',
    requiresArgs: true,
    maxExecutionsPerMinute: 20
  },
  'head': {
    command: 'head',
    description: 'Display first lines of file',
    allowedArgs: ['-n'],
    riskLevel: 'medium',
    requiresArgs: true,
    maxExecutionsPerMinute: 20
  },
  'tail': {
    command: 'tail',
    description: 'Display last lines of file',
    allowedArgs: ['-n'],
    riskLevel: 'medium',
    requiresArgs: true,
    maxExecutionsPerMinute: 20
  },
  'wc': {
    command: 'wc',
    description: 'Count lines, words, characters',
    allowedArgs: ['-l', '-w', '-c'],
    riskLevel: 'low',
    requiresArgs: true,
    maxExecutionsPerMinute: 20
  },

  // Git operations (medium risk)
  'git status': {
    command: 'git',
    description: 'Show git repository status',
    allowedArgs: ['status', '--short', '--porcelain'],
    riskLevel: 'medium',
    maxExecutionsPerMinute: 15
  },
  'git log': {
    command: 'git',
    description: 'Show git commit history',
    allowedArgs: ['log', '--oneline', '-n', '--graph', '--pretty=oneline'],
    riskLevel: 'medium',
    maxExecutionsPerMinute: 10
  },
  'git branch': {
    command: 'git',
    description: 'List git branches',
    allowedArgs: ['branch', '-a', '-r'],
    riskLevel: 'medium',
    maxExecutionsPerMinute: 15
  },
  'git diff': {
    command: 'git',
    description: 'Show git differences',
    allowedArgs: ['diff', '--name-only', '--stat'],
    riskLevel: 'medium',
    maxExecutionsPerMinute: 10
  },

  // Node.js/npm operations (medium to high risk)
  'npm list': {
    command: 'npm',
    description: 'List installed packages',
    allowedArgs: ['list', '--depth=0', '--production'],
    riskLevel: 'medium',
    maxExecutionsPerMinute: 5
  },
  'npm outdated': {
    command: 'npm',
    description: 'Check for outdated packages',
    allowedArgs: ['outdated'],
    riskLevel: 'medium',
    maxExecutionsPerMinute: 3
  },
  'npm audit': {
    command: 'npm',
    description: 'Check for security vulnerabilities',
    allowedArgs: ['audit', '--audit-level=moderate'],
    riskLevel: 'high',
    maxExecutionsPerMinute: 2
  },

  // System information (low risk)
  'which': {
    command: 'which',
    description: 'Locate command',
    allowedArgs: [],
    riskLevel: 'low',
    requiresArgs: true,
    maxExecutionsPerMinute: 10
  },
  'uname': {
    command: 'uname',
    description: 'System information',
    allowedArgs: ['-a', '-s', '-r'],
    riskLevel: 'low',
    maxExecutionsPerMinute: 5
  },
  'whoami': {
    command: 'whoami',
    description: 'Current user',
    allowedArgs: [],
    riskLevel: 'low',
    maxExecutionsPerMinute: 5
  }
};

/**
 * Commands that are explicitly forbidden
 */
export const FORBIDDEN_COMMANDS = [
  'rm', 'rmdir', 'del', 'delete',
  'mv', 'move', 'cp', 'copy',
  'chmod', 'chown', 'chgrp',
  'sudo', 'su', 'doas',
  'passwd', 'useradd', 'userdel',
  'mount', 'umount',
  'kill', 'killall', 'pkill',
  'systemctl', 'service',
  'crontab', 'at',
  'ssh', 'scp', 'rsync',
  'curl', 'wget', 'nc', 'netcat',
  'python', 'python3', 'node', 'ruby', 'perl',
  'sh', 'bash', 'zsh', 'fish', 'csh',
  'eval', 'exec', 'source',
  'dd', 'fdisk', 'mkfs',
  'iptables', 'firewall-cmd',
  'docker', 'podman', 'kubectl'
];

/**
 * Dangerous patterns that should never be allowed
 */
export const DANGEROUS_PATTERNS = [
  /[;&|`$(){}[\]]/,  // Shell metacharacters
  /\.\./,            // Path traversal
  /\/etc\//,         // System directories
  /\/proc\//,        // Process directories
  /\/sys\//,         // System directories
  /\/dev\//,         // Device directories
  /\/tmp\//,         // Temporary directories (often writable)
  /\/var\/log\//,    // Log directories
  /~\/\./,           // Hidden files in home
  /password|passwd|shadow|sudoers/i,  // Password files
  /private.*key|\.pem|\.key/i,        // Private keys
  /\.env|config.*secret/i,            // Environment/config files
  /\beval\b/i,       // Eval statements
  /\bexec\b/i,       // Exec statements
  /\\x[0-9a-f]{2}/i, // Hex encoded characters
  /%[0-9a-f]{2}/i,   // URL encoded characters
  /\x00-\x1F/,       // Control characters
  /\x7F-\xFF/        // Extended ASCII
];

/**
 * Sensitive file patterns that should be blocked
 */
export const SENSITIVE_FILE_PATTERNS = [
  /.*\.key$/,
  /.*\.pem$/,
  /.*\.crt$/,
  /.*\.p12$/,
  /.*\.pfx$/,
  /id_rsa/,
  /id_dsa/,
  /id_ecdsa/,
  /id_ed25519/,
  /\.ssh\/config/,
  /\.aws\/credentials/,
  /\.docker\/config\.json/,
  /\.gitconfig/,
  /\.npmrc/,
  /\.pypirc/
];

/**
 * Validate if a command is in the whitelist
 */
export function isCommandAllowed(command: string): boolean {
  // Check against forbidden commands first
  if (FORBIDDEN_COMMANDS.includes(command.toLowerCase())) {
    return false;
  }
  
  // Check if command is in whitelist
  return Object.keys(COMMAND_WHITELIST).some(whitelistedCmd => {
    const cmdDef = COMMAND_WHITELIST[whitelistedCmd];
    return cmdDef?.command === command || whitelistedCmd === command;
  });
}

/**
 * Validate command arguments against whitelist
 */
export function areArgsAllowed(command: string, args: string[]): boolean {
  const cmdKey = Object.keys(COMMAND_WHITELIST).find(key => {
    const cmdDef = COMMAND_WHITELIST[key];
    return cmdDef?.command === command || key === command;
  });
  
  if (!cmdKey) return false;
  
  const cmdDef = COMMAND_WHITELIST[cmdKey];
  if (!cmdDef) return false;
  
  // Check if command requires arguments but none provided
  if (cmdDef.requiresArgs && args.length === 0) {
    return false;
  }
  
  // Validate each argument
  return args.every(arg => {
    // Check against dangerous patterns
    if (DANGEROUS_PATTERNS.some(pattern => pattern.test(arg))) {
      return false;
    }
    
    // Check against sensitive file patterns if it looks like a file path
    if (arg.includes('/') || arg.includes('.')) {
      if (SENSITIVE_FILE_PATTERNS.some(pattern => pattern.test(arg))) {
        return false;
      }
    }
    
    // Check if argument is in allowed list (if allowedArgs is not empty)
    if (cmdDef.allowedArgs.length > 0) {
      return cmdDef.allowedArgs.includes(arg) || 
             // Allow file paths and numbers for certain commands
             /^[a-zA-Z0-9._/-]+$/.test(arg) ||
             /^\d+$/.test(arg);
    }
    
    // Default validation for arguments
    return /^[a-zA-Z0-9._/-]+$/.test(arg) || /^\d+$/.test(arg);
  });
}

/**
 * Get command definition for rate limiting
 */
export function getCommandDefinition(command: string): CommandDefinition | null {
  const cmdKey = Object.keys(COMMAND_WHITELIST).find(key => {
    const cmdDef = COMMAND_WHITELIST[key];
    return cmdDef?.command === command || key === command;
  });
  
  return cmdKey ? COMMAND_WHITELIST[cmdKey] || null : null;
}

/**
 * Check if input contains dangerous patterns
 */
export function containsDangerousPatterns(input: string): boolean {
  return DANGEROUS_PATTERNS.some(pattern => pattern.test(input));
}

/**
 * Validate working directory is safe
 */
export function isWorkingDirectorySafe(dir: string): boolean {
  // Normalize path
  const normalizedDir = dir.replace(/\/+/g, '/');
  
  // Block system directories
  const dangerousDirs = [
    '/etc', '/proc', '/sys', '/dev', '/boot', '/root',
    '/var/log', '/var/run', '/usr/bin', '/usr/sbin',
    '/bin', '/sbin'
  ];
  
  return !dangerousDirs.some(dangerousDir => 
    normalizedDir.startsWith(dangerousDir + '/') || 
    normalizedDir === dangerousDir
  );
}
