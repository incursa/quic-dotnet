---
title: "Governance Decisions"
---

# Governance Decisions

This page records repository governance decisions for `quic-dotnet`.

## Notice File

`NOTICE.md` is present because this repository carries package/library release
surfaces where notice handling is useful. Keep it aligned with any third-party
notice or redistribution obligations.

## Release Policy

Release versioning follows SemVer and is based on the public package/API
surface:

- major for breaking public API, wire-behavior contract, or package changes
- minor for additive compatible capabilities
- patch for compatible fixes

Official releases are created by maintainer-controlled Git tags. The NuGet
publish workflow runs from version tags and validates public API versioning
before packaging and publishing.
