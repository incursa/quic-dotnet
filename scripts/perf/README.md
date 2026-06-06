# Performance Helpers

This folder contains local performance and ProtocolLab integration helpers for
`quic-dotnet` development.

## ProtocolLab Local QUIC Benchmark Loop

Use `Invoke-ProtocolLabLocalQuicBenchmark.ps1` when you want ProtocolLab to run
against the current local `quic-dotnet` checkout instead of the published
`Incursa.Quic` packages.

The helper:

- can run in fast source-reference mode against the current `quic-dotnet`
  working tree;
- can still run in compatibility local-package mode, where it packs local
  `Incursa.Qpack`, `Incursa.Quic`, and `Incursa.Quic.Http3`;
- runs the selected ProtocolLab suite with nested PowerShell script output
  streamed to the current console;
- optionally uploads the generated publication bundle to R2.

For tight performance iteration, use project references and focused filters:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -UseProjectReferences `
  -Suite quic-transport-v1-comparison `
  -Implementation incursa-raw-quic-adapter-v1 `
  -Scenario quic.transport.multiplex.100x64kb `
  -DurationSeconds 1 `
  -WarmupSeconds 1 `
  -Repetitions 1 `
  -Connections 1 `
  -StreamsPerConnection 1
```

After the first source-mode restore, add `-NoRestore` to avoid restore work in
the close loop:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -UseProjectReferences `
  -NoRestore `
  -Suite quic-transport-v1-comparison `
  -Implementation incursa-raw-quic-adapter-v1 `
  -Scenario quic.transport.multiplex.100x64kb `
  -DurationSeconds 1 `
  -WarmupSeconds 1 `
  -Repetitions 1 `
  -Connections 1 `
  -StreamsPerConnection 1
```

Use local packages only when you explicitly need package restore compatibility
coverage:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -UseLocalPackages `
  -Suite h3-local-v1-comparison `
  -WorkflowProfile Quick
```

Choose the suite explicitly:

```powershell
-Suite ci-public-report
-Suite h3-local-v1-comparison
-Suite quic-transport-v1-comparison
```

`Quick` is the fastest close-loop proof. `Regression` uses the local regression
load shape. `Comparison` keeps ProtocolLab's full comparison behavior and is
intentionally slower.

## xUnit Opt-In Bridge

Normal `dotnet test` skips ProtocolLab performance benchmarks. To run the
focused bridge test intentionally:

```powershell
$env:INCURSA_RUN_PROTOCOLLAB_PERF = "1"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj -c Release --filter "Category=Performance&BenchmarkHarness=ProtocolLab"
```

The test invokes `Invoke-ProtocolLabLocalQuicBenchmark.ps1` with
`-UseProjectReferences`, tiny load settings, and no R2 upload. It fails on a
nonzero helper exit and writes ProtocolLab artifact paths to the test output.

## Run And Upload

To run one suite and upload the resulting bundle to R2:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\perf\Invoke-ProtocolLabLocalQuicBenchmark.ps1 `
  -Suite h3-local-v1-comparison `
  -WorkflowProfile Quick `
  -UploadAfterRun
```

The upload uses ProtocolLab's R2-only uploader and does not pass a custom
prefix. Objects are written under:

```text
public/runs/{runId}/
```

The default bucket is:

```text
protocol-lab-reports
```

By default the helper verifies uploaded objects. Use `-NoUploadVerification`
only when you need a faster credentialed smoke.

The helper allows diagnostic/non-publishable local bundles by default because
`Quick` and local shared-host runs are not publishable benchmark evidence. Use
`-RequirePublishableUpload` only when you want the upload step to reject
diagnostic local bundles.

## R2 Credentials

Do not commit R2 credentials and do not rely on repo-local secret files. The
helper resolves credentials in this order:

1. Existing environment variables.
2. A file passed with `-R2CredentialsPath`.
3. A file path in `PROTOCOL_LAB_R2_CREDENTIALS_PATH`.
4. PowerShell SecretManagement secrets.

The environment variable contract is:

```text
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...        # optional, for temporary credentials
CLOUDFLARE_ACCOUNT_ID=...    # or R2_ENDPOINT=...
AWS_DEFAULT_REGION=auto
```

For a local file outside source control, set one durable user environment
variable and keep the file wherever your workstation secrets live:

```powershell
[Environment]::SetEnvironmentVariable(
  "PROTOCOL_LAB_R2_CREDENTIALS_PATH",
  "C:\Users\$env:USERNAME\.config\incursa\protocol-lab-r2.env",
  "User")
```

That file may contain either the S3-compatible names above or the R2-specific
aliases:

```text
CLOUDFLARE_ACCOUNT_ID=...
R2_ACCESS_KEY_ID=...
R2_SECRET_ACCESS_KEY=...
```

Secret values are mapped to the S3-compatible environment variables expected by
ProtocolLab's uploader and are not printed.

For a stronger local setup, use PowerShell SecretManagement with your preferred
vault and store these secret names:

```powershell
Set-Secret -Name ProtocolLab-R2-AccessKeyId -Secret "<access-key-id>"
Set-Secret -Name ProtocolLab-R2-SecretAccessKey -Secret "<secret-access-key>"
Set-Secret -Name ProtocolLab-CloudflareAccountId -Secret "<account-id>"
```

If your vault is not the default vault, pass `-R2SecretVault <vault-name>`.
Override the secret names with `-R2AccessKeyIdSecretName`,
`-R2SecretAccessKeySecretName`, `-CloudflareAccountIdSecretName`,
`-R2EndpointSecretName`, and `-R2SessionTokenSecretName`.

## Failure Semantics

ProtocolLab can still produce a publication bundle when some benchmark cells
fail. With `-UploadAfterRun`, the helper uploads that diagnostic bundle if it
exists, then exits nonzero after the upload so the failed benchmark result is
not hidden.

Use the generated run summary in ProtocolLab to inspect failures:

```text
C:\shared\src\incursa\protocol-lab\.artifacts\runs\{runId}\summary.md
```

Use the generated bundle for uploaded public-safe artifacts:

```text
C:\shared\src\incursa\protocol-lab\.artifacts\publication\{runId}
```
