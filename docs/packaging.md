# Packaging

The repository is already wired for NuGet packaging.

## Version source

- Update [`Directory.Build.props`](../Directory.Build.props) to change the package version.
- The current scaffold version is `1.0.0`.

## Pack command

```bash
dotnet pack src/Incursa.Quic/Incursa.Quic.csproj -c Release
```

## Package contents

- The package readme comes from [`src/Incursa.Quic/README.md`](../src/Incursa.Quic/README.md).
- The package icon is supplied from [`assets/package-icon.png`](../assets/package-icon.png).
- Symbols are emitted as `snupkg` files because symbol publishing is already enabled in the shared build props.

## Package versions

- Test dependency versions are centralized in [`Directory.Packages.props`](../Directory.Packages.props).
- Add future shared package versions there instead of repeating them in project files.

## Release automation

- [`scripts/release/Invoke-ReleaseVersioning.ps1`](../scripts/release/Invoke-ReleaseVersioning.ps1) calculates or applies the next version.
- [`scripts/release/validate-public-api-versioning.ps1`](../scripts/release/validate-public-api-versioning.ps1) checks the shipped API baseline against the release tag.
