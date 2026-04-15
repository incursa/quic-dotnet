# Packaging

This repository centralizes common package metadata in [`Directory.Build.props`](../Directory.Build.props) and dependency versions in [`Directory.Packages.props`](../Directory.Packages.props).

## Version Source

- Update [`Directory.Build.props`](../Directory.Build.props) to change the repository version.
- Keep shared package versions in [`Directory.Packages.props`](../Directory.Packages.props).

## Local Pack Commands

```bash
dotnet pack src/Incursa.Quic/Incursa.Quic.csproj -c Release
dotnet pack src/Incursa.Quic.Qlog/Incursa.Quic.Qlog.csproj -c Release
```

## Package Contents

- Package readmes come from the project-local `README.md` files.
- The package icon comes from [`assets/package-icon.png`](../assets/package-icon.png).
- Symbols are emitted as `snupkg` files through the shared build configuration.

## Release Checks

- [`scripts/release/Invoke-ReleaseVersioning.ps1`](../scripts/release/Invoke-ReleaseVersioning.ps1): calculate or apply the next version.
- [`scripts/release/validate-public-api-versioning.ps1`](../scripts/release/validate-public-api-versioning.ps1): validate shipped public API baselines against a release tag.
- [`.github/workflows/publish-nuget-packages.yml`](../.github/workflows/publish-nuget-packages.yml): publish the tagged `Incursa.Quic` package.
