# MCP Secure Terminal Server

A comprehensive, security-focused MCP (Model Context Protocol) TypeScript SDK server that provides safe terminal command execution capabilities for Claude Desktop. This server implements enterprise-grade security controls following all MCP security requirements.

## 🚀 Quick Start with npx

The easiest way to use this server is with npx - no installation required!

### Prerequisites
- Node.js 18+ 
- Claude Desktop

### Usage

Simply add the server to your Claude Desktop configuration using npx:

**Claude Desktop Configuration**: `~/.claude_desktop_config.json` (macOS) or `%APPDATA%/Claude/claude_desktop_config.json` (Windows)

```json
{
  "servers": {
    "secure-terminal": {
      "command": "npx",
      "args": ["@modelcontextprotocol/mcp-terminal-server"]
    }
  }
}
```

That's it! Claude Desktop will automatically download and run the server when needed.

### Alternative: Global Installation

If you prefer to install globally:

```bash
npm install -g @modelcontextprotocol/mcp-terminal-server
```

Then configure Claude Desktop:
```json
{
  "servers": {
    "secure-terminal": {
      "command": "mcp-terminal-server"
    }
  }
}
```

## 🛡️ Security Features

This server addresses all major security requirements and threat vectors identified in the MCP security documentation:

### ✅ Security Requirements Compliance
- **✓ Mandatory code signing** - Ready for production deployment
- **✓ Static tool definitions** - Tools cannot be changed at runtime  
- **✓ Security tested interfaces** - Comprehensive validation and sanitization
- **✓ Package identity** - Clear provenance and version control
- **✓ Privilege declarations** - Explicit capability requirements

### 🔒 Threat Vector Mitigation
- **✓ Cross-Prompt Injection (XPIA)** - Input sanitization and validation
- **✓ Authentication Gaps** - Rate limiting and client identification
- **✓ Credential Leakage** - Output sanitization and credential filtering
- **✓ Tool Poisoning** - Strict command whitelist enforcement
- **✓ Lack of Containment** - Process isolation and resource limits
- **✓ Command Injection** - Comprehensive input validation
- **✓ Limited Security Review** - Extensive security testing

### 🛠️ Security Controls
- **Command Whitelist**: Only pre-approved, safe commands allowed
- **Input Sanitization**: All inputs validated and sanitized
- **Output Filtering**: Credentials and sensitive data automatically redacted
- **Rate Limiting**: Risk-based rate limiting with progressive blocking
- **Audit Logging**: Comprehensive security event logging
- **Path Traversal Protection**: Directory access restrictions
- **Timeout Enforcement**: Commands automatically terminated
- **Process Isolation**: Secure environment for command execution

## 🛠️ Available Tools

### Core Tools

#### `list_directory`
Safely list directory contents with security validation.
```
Parameters:
- path (optional): Directory path to list
- includeHidden (optional): Include hidden files
- longFormat (optional): Use detailed listing
```

#### `get_current_directory`
Get the current working directory.

#### `execute_safe_command`
Execute commands from the security whitelist.
```
Parameters:
- command: Command to execute (must be whitelisted)
- args (optional): Command arguments
- workingDirectory (optional): Working directory
```

#### `read_file_safe`
Safely read file contents with size limits.
```
Parameters:
- filePath: Path to file
- maxLines (optional): Maximum lines to read (default: 100)
```

#### `git_status`
Get Git repository status.
```
Parameters:
- workingDirectory (optional): Git repository path
- short (optional): Use short format
```

#### `count_file_stats`
Count lines, words, or characters in files.
```
Parameters:
- filePath: Path to file
- countType (optional): 'lines', 'words', or 'characters'
```

#### `system_info`
Get basic system information.
```
Parameters:
- infoType (optional): 'user', 'os', or 'system'
```

## 📋 Available Resources

### `available_commands`
Lists all whitelisted commands with descriptions and risk levels.

### `security_status/{clientId}`
Shows security status including rate limits and blocking status.

### `server_capabilities`
Displays server capabilities and security features.

## 🔧 Command Whitelist

The server only allows execution of pre-approved commands:

### Low Risk Commands
- `ls` - Directory listing
- `pwd` - Current directory
- `tree` - Directory tree
- `wc` - Word/line/character count
- `which` - Command location
- `uname` - System information
- `whoami` - Current user

### Medium Risk Commands
- `cat`, `head`, `tail` - File reading (with restrictions)
- `git status`, `git log`, `git branch`, `git diff` - Git operations
- `npm list`, `npm outdated` - Package information

### High Risk Commands
- `npm audit` - Security vulnerability check (limited rate)

### Forbidden Commands
All dangerous commands are explicitly forbidden:
- File modification: `rm`, `mv`, `cp`, `chmod`
- System administration: `sudo`, `su`, `systemctl`
- Network operations: `curl`, `wget`, `ssh`
- Script execution: `python`, `node`, `bash`
- And many more...

## 🛡️ Rate Limiting

The server implements sophisticated rate limiting:

### Global Limits
- 100 commands per minute across all tools
- Progressive blocking for violations

### Risk-Based Limits
- **Low Risk**: 50 executions/minute
- **Medium Risk**: 20 executions/minute  
- **High Risk**: 5 executions/minute

### Failure Handling
- 10 failed attempts per 5 minutes
- 3 suspicious activities per hour
- Automatic blocking and logging

## 📊 Monitoring

### Log Files
When running, the server creates logs in the current directory:
- `logs/security-audit.log` - All security events
- `logs/security-alerts.log` - High-risk events only
- `logs/combined.log` - General application logs
- `logs/error.log` - Error events

### Monitoring Commands
```bash
# Watch security events
tail -f logs/security-audit.log

# Check for alerts
tail -f logs/security-alerts.log

# Monitor rate limiting
grep "RATE_LIMIT_EXCEEDED" logs/security-audit.log
```

## 📚 Usage Examples

Once configured with Claude Desktop, you can ask Claude to:

- **List directories**: "Show me the files in the current directory"
- **Check Git status**: "What's the status of this Git repository?"
- **Read files safely**: "Show me the first 50 lines of package.json"
- **Get system info**: "What user am I running as?"
- **Execute safe commands**: "Run 'npm list' to show installed packages"
- **Check security status**: "Show me the current security status"

## 🔨 Development

### Local Development

1. **Clone and setup**
   ```bash
   git clone https://github.com/luiscnext/mcp-terminal-server.git
   cd mcp-terminal-server
   npm install
   ```

2. **Build and test**
   ```bash
   npm run build
   npm test
   npm run test:security
   ```

3. **Run locally**
   ```bash
   npm run dev
   ```

### Scripts
- `npm run build` - Build TypeScript to JavaScript
- `npm run dev` - Development mode with auto-reload
- `npm test` - Run security tests
- `npm run lint` - Code linting
- `npm run format` - Code formatting

## 📦 Publishing

To publish this package to npm:

1. **Build and test**
   ```bash
   npm run build
   npm test
   ```

2. **Login to npm**
   ```bash
   npm login
   ```

3. **Publish**
   ```bash
   npm publish
   ```

The package is configured with proper `publishConfig` for npm registry.

## 🚨 Security Best Practices

### For Users
1. **Monitor logs** - Check security audit logs regularly
2. **Update frequently** - Keep the package updated
3. **Review commands** - Understand what commands are available
4. **Report issues** - Submit security concerns immediately

### For Developers
1. **Never bypass security checks** - All validation is mandatory
2. **Review command additions** - New commands require security analysis
3. **Monitor audit logs** - Watch for suspicious patterns
4. **Test thoroughly** - Run security tests before deployment

## 📄 License

MIT License - see [LICENSE](./LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/luiscnext/mcp-terminal-server/issues)
- **Security**: See [SECURITY.md](./SECURITY.md) for reporting security issues
- **Documentation**: Check the repository for detailed docs

## ⚡ Performance

- **Command Execution**: < 30 seconds timeout
- **Memory Usage**: < 100MB per session
- **Output Limits**: 1MB max per command
- **Concurrent Users**: Supports multiple Claude Desktop clients

---

**⚠️ Security Notice**: This server implements comprehensive security controls but should be used responsibly. Always review commands before execution and monitor audit logs for suspicious activity.

**🎯 Quick Start**: Just add `"npx @modelcontextprotocol/mcp-terminal-server"` to your Claude Desktop config and start using secure terminal commands immediately!
