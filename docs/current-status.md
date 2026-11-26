---
title: "Readiness and Evidence"
---

# Readiness and evidence

This page explains how to determine repository readiness without copying a point-in-time branch, commit, test count, lab run, or deployment snapshot into durable documentation.

## Sources of truth

Use these sources in order:

1. Canonical requirements under [`specs/requirements/quic/`](../specs/requirements/quic/).
2. The maintained gap record in [`REQUIREMENT-GAPS.md`](../specs/requirements/quic/REQUIREMENT-GAPS.md).
3. Architecture and work-item artifacts under [`specs/architecture/quic/`](../specs/architecture/quic/) and [`specs/work-items/quic/`](../specs/work-items/quic/).
4. Verification artifacts under [`specs/verification/quic/`](../specs/verification/quic/).
5. Deterministic tests, benchmarks, schemas, fixtures, and repository validation scripts.
6. Release notes and workflow records for a particular published revision.

A requirement, work item, or verification record may preserve immutable evidence identifiers needed for traceability. That evidence proves only the revision and environment it names.

Point-in-time closure notes formerly collected on this page are preserved in the [historical status archive](repository-status-archive.md).

## Supported package boundary

The root [README](../README.md) and package READMEs describe the supported public surface for the managed QUIC transport, DNS over QUIC, qlog diagnostics adapter, QPACK, and HTTP/3 packages. Generated coverage reports and one-run interop results do not broaden that surface.

Broader production hosting, MASQUE, CONNECT-UDP, trailers, server push, HTTP Datagrams, and other protocol work are supported only when the owning requirement, public API, and verification artifacts explicitly say so.

## Readiness checks

For a candidate revision:

1. Review the owning requirements and unresolved gaps.
2. Validate the canonical SpecTrace artifacts.
3. Build and test the affected solution and focused requirement homes.
4. Run negative, fuzz, and benchmark evidence required by the repository guidance.
5. Record skipped, unavailable, or environment-dependent checks as unverified.
6. Put revision-specific commands and outcomes in the verification artifact or pull request.
7. Use a release record for publication and deployment claims.

A local green build does not prove external peer interoperability, lab comparability, package publication, secret configuration, or production deployment.

## Documentation rule

Do not add dated status summaries, “latest” test counts, active branch or worktree notes, temporary blockers, package inventory snapshots, or lab availability claims to this page. Update canonical requirements and verification artifacts instead; use issues and pull requests for active planning.
