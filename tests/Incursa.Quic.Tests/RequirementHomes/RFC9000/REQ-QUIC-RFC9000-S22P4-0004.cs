// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P4-0004")]
public sealed class REQ_QUIC_RFC9000_S22P4_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P4-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistry_UsesShortMnemonicFrameTypeNames()
    {
        foreach ((_, string frameTypeName, _) in QuicFrameRegistryProofSupport.PermanentFrameTypes)
        {
            Assert.Equal(frameTypeName, frameTypeName.ToUpperInvariant());
            Assert.DoesNotContain(' ', frameTypeName);
            Assert.DoesNotContain('-', frameTypeName);
        }
    }
}
