# Tor Go

A complete Tor client implementation written in pure Go.

## CI

All checks in `.github/workflows/test.yml` must pass before any changes are considered complete. This includes:

- `golangci-lint`: no lint errors
- `govulncheck`: no known vulnerabilities
- `gofmt`: all files formatted
- `gocyclo`: no function with cyclomatic complexity > 15
- `ineffassign`: no ineffectual assignments
- `misspell`: no misspellings
- `go test`: all tests pass
- Coverage: minimum 50% (excluding `cmd/`)
- LICENSE file exists
