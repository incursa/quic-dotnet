# Release Scripts

## Scripts

- [`Invoke-ReleaseVersioning.ps1`](Invoke-ReleaseVersioning.ps1) calculates or applies the next package version and can tag the release commit.
- [`validate-public-api-versioning.ps1`](validate-public-api-versioning.ps1) checks the version against the public API baseline rules.
- [`Test-IncursaQuicPackageConformance.ps1`](Test-IncursaQuicPackageConformance.ps1) proves a locally packed `Incursa.Quic` candidate is the exact binary consumed by the ProtocolLab internal Raw QUIC server and runs the five deterministic download/slow-reader correctness tests with no source-root fallback.

## Version source

- The repo version is stored in [`Directory.Build.props`](../../Directory.Build.props).
- The initial package version is `1.0.0`.

## Package-backed Raw QUIC release gate

`publish-nuget-packages.yml` runs the package-backed Raw QUIC conformance gate
after packing and before NuGet push. It requires the narrowly scoped
`PROTOCOL_LAB_INTERNAL_READ_TOKEN` repository secret to read the private
ProtocolLab fixture checkout. The gate is correctness-only: it does not run
BenchmarkDotNet, a ProtocolLab performance campaign, or any adaptive-policy
selection. It rejects `PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT`, verifies the
server's resolved package identity and binary hash, and retains a TRX plus JSON
summary as release evidence.
