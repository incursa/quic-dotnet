You are working in a repository that contains imported QUIC Spec Trace requirements.

Goal:
Verify any remaining gaps in the QUIC implementation

Tasks:
1. Review all requirements found in these spec files:
   - C:\src\incursa\quic-dotnet\specs\requirements\quic\SPEC-QUIC-RFC8999.json
   - C:\src\incursa\quic-dotnet\specs\requirements\quic\SPEC-QUIC-RFC9000.json
   - C:\src\incursa\quic-dotnet\specs\requirements\quic\SPEC-QUIC-RFC9001.json
   - C:\src\incursa\quic-dotnet\specs\requirements\quic\SPEC-QUIC-RFC9002.json
2. Run the workbench tool and identify which requirements do not have tests or other similar gaps
3. Check if any requirements are missing obvious types of tests that should be considered, e.g. positive, negative, fuzz, mutation, etc.
4. Inventory any requirements that need more work, better implementation, strict testing, and so on.

Write:
- ./specs/codex_work/quic.review.md



In a nutshell, we just need to go over absolutely everything that's been done. I'm primarily looking for, out of all the requirements that we have written, have we implemented everything and can we prove that everything has been implemented properly? Then as a second step, it's, okay, just because we say we have a test, is that test a good test? You know, are we able to determine if it's a good test by, does a particular test claim to fulfill way too many requirements at the same time? Do we have enough variety on the tests, positive and negative, the fuzz testing and stuff like that? We should try our best to hit all of those kinds of tests for all of these requirements if we can. Try not to reuse the same tests to fulfill multiple requirements. I'd much rather have a large test suite that's focused than not.
