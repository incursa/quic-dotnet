// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0011")]
public sealed class REQ_QUIC_RFC9001_S4_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalArtifactsKeepCoalescingPreferenceInsidePacketProtectionScope()
    {
        QuicRfc9001TailProofTestSupport.AssertCanonicalArtifactsOwnRequirement("REQ-QUIC-RFC9001-S4-0011");
    }
}
