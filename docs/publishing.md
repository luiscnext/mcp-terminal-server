# Publishing to NPM

This guide explains how to publish the MCP Secure Terminal Server to npm so users can install it with `npx @modelcontextprotocol/mcp-terminal-server`.

## Prerequisites

1. **NPM Account**: Create an account at [npmjs.com](https://npmjs.com)
2. **Organization Access**: Request access to the `@modelcontextprotocol` organization
3. **Two-Factor Authentication**: Enable 2FA on your npm account
4. **Local Setup**: Ensure you're logged in with `npm login`

## Publishing Steps

### 1. Prepare the Package

```bash
# Clone and setup
git clone https://github.com/luiscnext/mcp-terminal-server.git
cd mcp-terminal-server

# Install dependencies
npm install

# Run tests
npm test
npm run test:security

# Build the package
npm run build
```

### 2. Version Management

Update the version in `package.json`:

```bash
# For patch releases (bug fixes)
npm version patch

# For minor releases (new features)
npm version minor

# For major releases (breaking changes)
npm version major
```

This will automatically:
- Update `package.json` version
- Create a git tag
- Commit the changes

### 3. Pre-publish Verification

```bash
# Verify package contents
npm pack --dry-run

# Check what files will be included
npm publish --dry-run

# Verify all tests pass
npm run prepublishOnly
```

### 4. Publish to NPM

```bash
# Publish to npm registry
npm publish

# For beta/alpha versions
npm publish --tag beta
```

### 5. Verify Publication

```bash
# Test installation
npx @modelcontextprotocol/mcp-terminal-server --help

# Check on npm website
# Visit: https://www.npmjs.com/package/@modelcontextprotocol/mcp-terminal-server
```

## Package Configuration

The package is configured with:

- **Scoped package**: `@modelcontextprotocol/mcp-terminal-server`
- **Public access**: Available to all users
- **Binary executable**: `mcp-terminal-server` command
- **ESM modules**: Modern JavaScript modules
- **Type definitions**: Full TypeScript support

## NPX Usage

Once published, users can:

```bash
# Run directly with npx (no installation)
npx @modelcontextprotocol/mcp-terminal-server

# Install globally
npm install -g @modelcontextprotocol/mcp-terminal-server

# Use in Claude Desktop config
{
  "servers": {
    "secure-terminal": {
      "command": "npx",
      "args": ["@modelcontextprotocol/mcp-terminal-server"]
    }
  }
}
```

## Security Considerations

### Before Publishing

- [ ] All security tests pass
- [ ] No sensitive data in package
- [ ] Dependencies are up to date
- [ ] No known vulnerabilities (`npm audit`)
- [ ] Code is signed and verified

### Package Security

- **Scoped package**: Prevents name squatting
- **2FA required**: Secure publishing process
- **Audit logs**: Track all package changes
- **Vulnerability scanning**: Automatic security checks

## Automation

Consider setting up GitHub Actions for automated publishing:

```yaml
name: Publish to NPM
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 18
          registry-url: https://registry.npmjs.org/
      - run: npm ci
      - run: npm test
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

## Version Strategy

- **Patch (1.0.x)**: Bug fixes, security patches
- **Minor (1.x.0)**: New features, additional commands
- **Major (x.0.0)**: Breaking changes, API changes

## Support

After publishing:

1. **Monitor issues**: Watch GitHub issues for user problems
2. **Security alerts**: Subscribe to npm security advisories
3. **Usage analytics**: Monitor download statistics
4. **Community feedback**: Respond to user feedback

## Troubleshooting

### Common Issues

**Permission denied**: Ensure you have publish rights to the organization
```bash
npm access list packages @modelcontextprotocol
```

**Version conflicts**: Check existing versions
```bash
npm view @modelcontextprotocol/mcp-terminal-server versions --json
```

**Build failures**: Verify all dependencies
```bash
npm ci
npm run build
```

### Getting Help

- **NPM Support**: [support.npmjs.com](https://support.npmjs.com)
- **Organization Access**: Contact `@modelcontextprotocol` maintainers
- **GitHub Issues**: [Repository Issues](https://github.com/luiscnext/mcp-terminal-server/issues)

---

Once published, users will be able to use the server immediately with:

```bash
npx @modelcontextprotocol/mcp-terminal-server
```

No manual installation, cloning, or building required! 🚀
