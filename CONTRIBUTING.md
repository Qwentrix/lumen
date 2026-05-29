# Contributing to Micelium Lumen

Thank you for your interest in contributing to Lumen! Lumen is an
Apache 2.0 open-source project maintained by Qwentrix. We welcome
bug reports, feature requests, and pull requests.

## Contributor License Agreement (CLA)

Before your first pull request can be merged, you must sign the
Qwentrix Individual CLA (and, if contributing on behalf of a company,
the Corporate CLA). The CLA bot on this repository will prompt you
automatically when you open a PR.

CLA portal: **https://cla-assistant.io/Qwentrix/lumen**

If you have questions about the CLA, email legal@qwentrix.com.

## Development Prerequisites

- Go 1.22 or later (`go version`)
- `golangci-lint` >= 1.58 (`brew install golangci-lint` or
  https://golangci-lint.run/usage/install/)
- `gofmt` (bundled with Go)
- GNU `make` (optional; used for the `Makefile` convenience targets)

## Getting Started

```bash
# Clone the repository
git clone https://github.com/Qwentrix/lumen.git
cd lumen

# Pull the local lumen-scoring sibling (used via go.mod replace)
# If you don't have it, the replace directive in go.mod will need
# to be updated to point at the published module version instead.
git clone https://github.com/Qwentrix/lumen-scoring.git ../lumen-scoring

# Download Go module dependencies
go mod download

# Build the binary
go build -o lumen ./cmd/lumen/

# Run all unit tests
go test ./...

# Run the linter
golangci-lint run ./...
```

## Code Style

- All Go code **must** be formatted with `gofmt` (enforced by CI).
- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).
- Run `golangci-lint run ./...` locally before pushing; CI will reject
  lint failures.
- Keep probe modules **read-only by contract** — probes must never
  write to or modify user state. Any code that touches the filesystem
  must go through the `consent.ConsentSnapshot` gate.
- The `internal/hybrid/` upload path must never transmit file content
  or personal identifiers. Tests enforcing this are in
  `internal/hybrid/upload_test.go`.

## Testing Expectations

- All new probe modules must include a unit test using mock OS
  interfaces (build-tag-isolated where necessary).
- The `TestNoNetworkCalls` integration test (`internal/probes/...`)
  must remain green — it asserts that a default (non-hybrid) scan
  makes zero outbound TCP connections.
- HTML report tests must assert that the rendered HTML contains no
  `http(s)://` external resource references.
- Aim for >= 80% package-level coverage on new packages; the CI gate
  is currently set at 60% to allow for OS-dispatch stubs.

## Pull Request Process

1. Open an issue first for non-trivial changes so we can discuss the
   approach before you invest time coding.
2. Fork the repository and work on a feature branch
   (`feat/<short-description>` or `fix/<short-description>`).
3. Ensure `go test ./...` and `golangci-lint run ./...` pass locally.
4. Open a PR targeting `main`. Fill in the PR template.
5. The CLA bot will check your CLA status automatically.
6. At least one member of `@qwentrix/lumen-pod` must approve before
   merge.

## Reporting Security Issues

**Do not file security issues as GitHub issues.**
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating, you agree to uphold this standard.
