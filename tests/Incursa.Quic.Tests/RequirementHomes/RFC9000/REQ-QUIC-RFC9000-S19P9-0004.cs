// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0004">MAX_DATA frames MUST contain the following field:</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P9-0004")]
public sealed class REQ_QUIC_RFC9000_S19P9_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxDataFrame_ParsesTheRequiredMaximumDataField()
    {
        QuicMaxDataFrame frame = new(42);
        byte[] encoded = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(encoded, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxDataFrame_RejectsFrameWithoutTheRequiredMaximumDataField()
    {
        byte[] missingMaximumDataField = [0x10];

        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(missingMaximumDataField, out _, out _));
    }
}
