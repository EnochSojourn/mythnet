# Contributing to MythNet

Thanks for your interest in contributing.

## Getting Started

```bash
git clone https://github.com/EnochSojourn/mythnet.git
cd mythnet
make build
./mythnet
```

Requires Go 1.24+ and Node.js 18+.

## Development

The project is a single Go binary with an embedded SvelteKit frontend.

```
cmd/mythnet/     — Server entry point
cmd/mythctl/     — CLI client entry point
internal/        — All server packages
web/             — SvelteKit frontend (embedded at build time)
```

### Build & Test

```bash
make build                          # Build both binaries
go test ./internal/... -race        # Run tests
cd web && npm install && npm run dev # Frontend dev server
```

### Code Style

- Go: standard `gofmt` formatting
- Frontend: Svelte conventions, Tailwind CSS
- Commit messages: `type: description` (e.g., `fix: Exclude broadcast MAC from detection`)

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Ensure `go test ./internal/... -race` passes
5. Ensure `go build ./cmd/mythnet` succeeds
6. Submit a pull request

## Reporting Bugs

Use [GitHub Issues](https://github.com/EnochSojourn/mythnet/issues). Include:
- MythNet version (`mythnet --version` or check the web UI footer)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (redact any sensitive network information)

## Security Issues

See [SECURITY.md](SECURITY.md). Do not open public issues for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
