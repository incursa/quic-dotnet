# Release Scripts

## Scripts

- [`Invoke-ReleaseVersioning.ps1`](Invoke-ReleaseVersioning.ps1) calculates or applies the next package version and can tag the release commit.
- [`validate-public-api-versioning.ps1`](validate-public-api-versioning.ps1) checks the version against the public API baseline rules.

## Version source

- The repo version is stored in [`Directory.Build.props`](../../Directory.Build.props).
- The initial scaffold version is `1.0.0`.
