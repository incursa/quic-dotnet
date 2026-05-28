// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0032">A stream ID MUST be a 62-bit integer in the range 0 to 2^62-1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0032")]
public sealed class REQ_QUIC_RFC9000_0032
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-0033")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamIdentifier_AcceptsTheMaximumRepresentableStreamId()
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(QuicVariableLengthInteger.MaxValue);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, streamId.Value);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BuildStreamIdentifier_RejectsValuesBeyondThe62BitRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicStreamTestData.BuildStreamIdentifier(QuicVariableLengthInteger.MaxValue + 1UL));
    }
}
