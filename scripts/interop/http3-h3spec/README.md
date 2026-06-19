# HTTP/3 h3spec Harness

This harness runs `h3spec` against the local Incursa HTTP/3 file server and converts stdout/stderr into JSON and Markdown triage artifacts.

The harness is advisory. It identifies RFC 9114 and RFC 9204 failures and records follow-up rows, but it does not promote HTTP/3 or QPACK support by itself.

## Scripts

- `Start-H3SpecServer.ps1`: builds and starts the local HTTP/3 sample server with a temporary fixture and certificate.
- `Run-H3Spec.ps1`: starts the server unless `-NoStartServer` is provided, invokes `h3spec`, captures stdout/stderr, and runs the parser.
- `Stop-H3SpecServer.ps1`: stops a server started by `Start-H3SpecServer.ps1`.
- `parse-h3spec-results.py`: converts h3spec output into JSON and Markdown triage artifacts.

## Plan-Only Smoke

```powershell
pwsh -NoProfile -File scripts\interop\http3-h3spec\Run-H3Spec.ps1 -PlanOnly
```

## Live Local Run

Install `h3spec`, provide a wrapper command, or let the repo acquire the upstream
Linux release under `.artifacts/tools` and run it through Docker without changing
global `PATH`.

```powershell
pwsh -NoProfile -File scripts\interop\http3-h3spec\Run-H3Spec.ps1 `
  -AcquireH3Spec `
  -NoValidateCertificate `
  -TimeoutMilliseconds 5000
```

To acquire only the local tool/wrapper:

```powershell
pwsh -NoProfile -File scripts\interop\http3-h3spec\Install-H3SpecTool.ps1
```

The Windows acquisition path downloads the upstream `h3spec-linux-x86_64` release
binary and generates a Docker-backed wrapper under `.artifacts/tools/h3spec-v0.1.13/`.
When `Run-H3Spec.ps1 -AcquireH3Spec` uses that wrapper with a loopback host, the
h3spec target host is rewritten to `host.docker.internal` while the local server
still binds on the requested port.

```powershell
pwsh -NoProfile -File scripts\interop\http3-h3spec\Run-H3Spec.ps1 `
  -NoValidateCertificate `
  -TimeoutMilliseconds 5000
```

For a Docker-wrapped h3spec binary on Linux:

```powershell
pwsh -NoProfile -File scripts\interop\http3-h3spec\Run-H3Spec.ps1 `
  -H3SpecExecutable docker `
  -H3SpecPrefixArguments @("run","--rm","--network","host","incursa-h3spec") `
  -NoValidateCertificate `
  -HostName 127.0.0.1 `
  -TimeoutMilliseconds 5000
```

`h3spec` command shape is:

```text
h3spec [options] <host> <port>
```

Supported h3spec options used by this harness include `--no-validate`, `--match`, `--skip`, `--qlog-dir`, `--key-log-file`, and `--timeout`.

## Artifacts

Default output root:

```text
.artifacts/http3-h3spec/<UTC-run-id>/
```

Each run writes:

- `logs/h3spec.stdout.log`
- `logs/h3spec.stderr.log`
- `h3spec-metadata.json`
- `h3spec-results.json`
- `h3spec-report.md`
- `server-context.json`
- `logs/server.stdout.log`
- `logs/server.stderr.log`

Filtered runs also record the requested `--match` and `--skip` values in
`h3spec-metadata.json`. If requested matches select no cases, the parser marks
the run as `no-selected-cases`; treat that as tooling evidence, not conformance
evidence.

## Failure Mapping

The parser maps h3spec case suffixes:

- `[HTTP/3 x.y]` to RFC 9114 section `x.y` and the `http3-adapter-boundary` gap.
- `[QPACK x.y]` to RFC 9204 section `x.y` and the `qpack-stream-state-boundary` gap.
- `[Transport x.y]` to RFC 9000 for context only.
- `[TLS x.y]` to RFC 9001 for context only.

Only RFC 9114 and RFC 9204 failures are converted into HTTP/3/QPACK follow-up rows.
