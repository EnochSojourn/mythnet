# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MythNet, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@mythlogical.com** or use [GitHub's private vulnerability reporting](https://github.com/EnochSojourn/mythnet/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment if possible

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older | No |

## Security Design

MythNet is a network monitoring tool that by nature has broad network access. Key security considerations:

- **Authentication** — All API endpoints (except `/api/health` and `/status`) require password authentication
- **Auto-TLS** — Optional automatic TLS certificate generation
- **Rate limiting** — API rate limited to 300 requests/minute
- **Mesh encryption** — AES-256 encrypted gossip, mTLS for replication
- **Webhook signing** — HMAC-SHA256 signatures on outbound webhooks
- **Audit logging** — All administrative actions logged
- **Privilege separation** — Designed to run as a dedicated `mythnet` user via systemd

## Best Practices for Deployment

- Run behind a reverse proxy (nginx, Caddy) with TLS in production
- Use a dedicated system user (`mythnet`) with minimal privileges
- Set a strong password (or use the auto-generated one)
- Restrict mesh secret distribution to trusted nodes
- Keep API keys out of config files — use environment variables
- Review network policies regularly
