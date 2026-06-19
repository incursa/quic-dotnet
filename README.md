# Incursa.Quic

[![CI](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/incursa/quic-dotnet/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/incursa/quic-dotnet)](LICENSE)

`Incursa.Quic` is the managed QUIC library set in this repository. The NuGet release surface here is the core transport package plus sibling packages for DNS over QUIC, a diagnostics-to-qlog adapter, standalone QPACK, and HTTP/3. The separate qlog repository owns the `Incursa.Qlog.*` model and vocabulary packages; this repo’s qlog package is `Incursa.Quic.Diagnostics.Qlog`, a transport-specific adapter that maps Incursa.Quic diagnostics into that model layer.

Source documentation lives in [`docs/`](docs/) and is mirrored into the central
`incursa-docs` site through [`docs.site.json`](docs.site.json) and
[`.github/workflows/sync-docs.yml`](.github/workflows/sync-docs.yml). Edit the
source docs here; do not edit mirrored output in the central docs repository.

## Packages

- [`Incursa.Quic`](src/Incursa.Quic/README.md): core QUIC transport primitives, connection management, stream handling, and public client/listener entry points
- [`Incursa.Quic.Dns`](src/Incursa.Quic.Dns/README.md): DNS over QUIC built on the managed transport
- [`Incursa.Quic.Diagnostics.Qlog`](src/Incursa.Quic.Qlog/README.md): qlog capture adapter for transport diagnostics
- [`Incursa.Qpack`](src/Incursa.Qpack/README.md): standalone QPACK encoder and decoder package
- [`Incursa.Quic.Http3`](src/Incursa.Quic.Http3/README.md): HTTP/3 layer over `Incursa.Quic`

## Scope

- Managed QUIC transport, streams, connection options, errors, and listener/client entry points
- DNS over QUIC on top of the transport package
- qlog capture and diagnostics mapping support code that bridges to the separate qlog model repository
- Standalone QPACK for HTTP/3 header compression
- HTTP/3 request, control-stream, SETTINGS, GOAWAY, and request/response floor behavior
- repository requirements, architecture, work-item, and verification artifacts under `specs/`

## Install

```bash
dotnet add package Incursa.Quic
dotnet add package Incursa.Quic.Dns
dotnet add package Incursa.Quic.Diagnostics.Qlog
dotnet add package Incursa.Qpack
dotnet add package Incursa.Quic.Http3
```

## Build

```bash
dotnet restore Incursa.Quic.slnx
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release
git diff --check
```

For traceability and repository-owned validation, also use the docs and scripts
under [`docs/requirements-workflow.md`](docs/requirements-workflow.md),
[`docs/spec-trace-prep.md`](docs/spec-trace-prep.md), and
[`scripts/`](scripts/). ProtocolLab package and run helpers live under
[`eng/protocol-lab/`](eng/protocol-lab/).

## Release

- Tag a release commit as `vX.Y.Z` and push it.
- [`.github/workflows/publish-nuget-packages.yml`](.github/workflows/publish-nuget-packages.yml) runs on version tags, validates public API versioning, packs the public packages, and pushes them to nuget.org.
- The same workflow can also be run manually with an explicit `version` input when you need a non-tagged publish rehearsal.

Package versioning follows the public NuGet/API surface. Keep package metadata,
public API baselines, release scripts, and compatibility notes aligned with any
behavior or surface change.

## Start Here

- Core package guide: [`src/Incursa.Quic/README.md`](src/Incursa.Quic/README.md)
- DNS over QUIC package guide: [`src/Incursa.Quic.Dns/README.md`](src/Incursa.Quic.Dns/README.md)
- qlog diagnostics adapter guide: [`src/Incursa.Quic.Qlog/README.md`](src/Incursa.Quic.Qlog/README.md)
- QPACK package guide: [`src/Incursa.Qpack/README.md`](src/Incursa.Qpack/README.md)
- HTTP/3 package guide: [`src/Incursa.Quic.Http3/README.md`](src/Incursa.Quic.Http3/README.md)
- Requirements workflow: [`docs/requirements-workflow.md`](docs/requirements-workflow.md)

## Repository Layout

- `src/Incursa.Quic`: core QUIC transport package
- `src/Incursa.Quic.Dns`: DNS over QUIC package
- `src/Incursa.Quic.Qlog`: qlog adapter package for diagnostics capture (`Incursa.Quic.Diagnostics.Qlog`)
- `src/Incursa.Qpack`: standalone QPACK package
- `src/Incursa.Quic.Http3`: HTTP/3 package and readiness note
- `src/Incursa.Quic.InteropHarness`: support assembly for interop runner scenarios
- `tests/Incursa.Quic.Tests`: requirement-homed tests and release guardrails
- `benchmarks`: performance suites
- `specs/requirements/quic`: canonical QUIC requirement artifacts
- `specs/architecture/quic`: architecture artifacts
- `specs/work-items/quic`: implementation planning artifacts
- `specs/verification/quic`: verification artifacts

## Security And Credentials

- Use [`SECURITY.md`](SECURITY.md) for vulnerability reporting.
- Do not commit NuGet tokens, docs sync tokens, contributor-agreement tokens,
  local auth state, private transcripts, or private artifact paths.
- GitHub workflows read credentials from repository secrets; local validation
  does not prove those secrets or branch protections are configured.

## Readiness And Known Gaps

- [`docs/current-status.md`](docs/current-status.md) is the date-stamped status
  snapshot for local and hosted evidence.
- Implementation changes should remain traceable through `specs/` before
  behavior changes are reviewed.
- Broader production hosting, MASQUE, CONNECT-UDP, trailers, server push, and
  other future HTTP/3 work remain outside the stable documented surface until
  the owning requirements and verification artifacts close.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
