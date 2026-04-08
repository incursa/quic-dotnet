# Phase 09 - Priority Finish Line

This is a hand-authored execution queue for the current finish-line backlog.
Run one prompt at a time, in order. Commit after every prompt. Do not start the next prompt until the current one has a green build and a green full test run.

Code roots used in prompts:
- ./src

Test roots used in prompts:
- ./tests

## Global Rules

- Stay trace-first. Read `docs/requirements-workflow.md`, `specs/requirements/quic/REQUIREMENT-GAPS.md`, the owning `SPEC-...json`, and the matching generated chunk artifacts before editing.
- Keep each prompt inside the selected chunk and the minimum shared helpers needed to support it.
- Add or update positive and negative tests for every requirement you implement.
- Add fuzz or property coverage for wire-facing parsers, serializers, and state machines.
- Add or update benchmarks when the chunk touches a hot path.
- Update the generated chunk summary, closeout, or review artifacts and the gap ledger when blockers move.
- Use the standard verification gate for every prompt:
  - `dotnet build Incursa.Quic.slnx -c Release`
  - `dotnet test Incursa.Quic.slnx -c Release`
  - If a benchmarked hot path changes, also run the relevant benchmark command from the chunk summary.
- Commit the changes for the prompt before moving to the next one.

## Prompt Order

- `9000-02-stream-state` - reconcile and finish the stream-state slice first.
- `9000-03-flow-control` - complete flow-control accounting next.
- `9000-19-retransmission-and-frame-reliability` - close the helper-backed retransmission and reliability slice.
- `9000-13-idle-and-close` - finish idle-timeout, close, and drain behavior.
- `9000-14-stateless-reset` - finish stateless-reset helper behavior and tracing.
- `9000-11-migration-core` - reconcile migration-core evidence and leave explicit blockers.
- `9002-06-appendix-b-constants-and-examples` - split or defer appendix-B work before automating it.
- `9001-02-security-and-registry` - finish the remaining RFC 9001 security and registry slice.

## 9000-02-stream-state

```text

```

## 9000-03-flow-control

```text

```

## 9000-19-retransmission-and-frame-reliability

```text

```

## 9000-13-idle-and-close

```text

```

## 9000-14-stateless-reset

```text

```

## 9000-11-migration-core

```text

```

## 9002-06-appendix-b-constants-and-examples

```text

```

## 9001-02-security-and-registry

```text

```
