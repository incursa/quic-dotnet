// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S22-4-P3-R01")]
public sealed class RFC9000_S22_4_P3_R01
{
    [Fact]
    [Requirement("RFC9000-S22-4-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistry_IncludesTheFrameTypeNameField()
    {
        foreach ((_, string frameTypeName, _) in QuicFrameRegistryProofSupport.PermanentFrameTypes)
        {
            Assert.NotEmpty(frameTypeName);
        }
    }
}
