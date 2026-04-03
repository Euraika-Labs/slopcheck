# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in ai-slopcheck, please report it responsibly:

1. **Do NOT open a public issue**
2. Email **security@euraika.net** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive a response within 48 hours
4. We will work with you to understand and address the issue

## Security Considerations

ai-slopcheck is designed to run on untrusted code (PR scanning). The security model:

- **No code execution** — rules use regex/AST matching only, never eval
- **No network calls** — fully offline, no telemetry
- **No secrets required** — the scan step needs only read access
- **Safe YAML parsing** — uses `yaml.safe_load` exclusively
- **Output escaping** — GitHub annotations and Markdown are properly escaped
- **Symlink protection** — file discovery rejects symlinks outside repo root

See [docs/security-model.md](docs/security-model.md) for the full threat model.
