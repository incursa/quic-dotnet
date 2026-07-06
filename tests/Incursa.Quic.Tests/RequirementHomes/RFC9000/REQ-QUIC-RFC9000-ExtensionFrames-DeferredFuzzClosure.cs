// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_ExtensionFrames_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1376")]
    [Requirement("REQ-QUIC-RFC9000-1377")]
    [Requirement("REQ-QUIC-RFC9000-1378")]
    [Requirement("REQ-QUIC-RFC9000-1383")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ExtensionFrameRequirementFuzz_PreservesNegotiationSignalingAndFlowControlBoundaries()
    {
        ExtensionFrameRequirementCase[] cases =
        [
            new(
                "REQ-QUIC-RFC9000-1376",
                "MUST",
                ["extension to QUIC", "new type of frame", "peer is able to understand the frame"],
                ["public API", "runtime policy", "transport-runtime behavior"]),
            new(
                "REQ-QUIC-RFC9000-1377",
                "MAY",
                ["transport parameter", "willingness to receive", "extension frame types"],
                ["public API", "runtime enforcement", "frame parser"]),
            new(
                "REQ-QUIC-RFC9000-1378",
                "MAY",
                ["One transport parameter", "one or more extension frame types"],
                ["one transport parameter MUST", "runtime enforcement"]),
            new(
                "REQ-QUIC-RFC9000-1383",
                "MUST NOT",
                ["Extension frames MUST NOT be included in flow control", "unless specified in the extension"],
                ["every extension frame", "all packet data", "runtime policy"]),
        ];

        foreach (ExtensionFrameRequirementCase requirementCase in cases)
        {
            string statement = QuicRfc9000RequirementSpecSupport.GetStatement(requirementCase.RequirementId);
            string upstreamRef = QuicRfc9000RequirementSpecSupport.GetUpstreamRef(requirementCase.RequirementId);

            Assert.Contains(requirementCase.Modal, statement, StringComparison.Ordinal);
            Assert.Contains("#section-19.21", upstreamRef, StringComparison.Ordinal);

            foreach (string requiredPhrase in requirementCase.RequiredPhrases)
            {
                Assert.Contains(requiredPhrase, statement, StringComparison.Ordinal);
            }

            foreach (string forbiddenPhrase in requirementCase.ForbiddenPhrases)
            {
                Assert.DoesNotContain(forbiddenPhrase, statement, StringComparison.Ordinal);
            }
        }
    }

    private sealed record ExtensionFrameRequirementCase(
        string RequirementId,
        string Modal,
        string[] RequiredPhrases,
        string[] ForbiddenPhrases);
}
