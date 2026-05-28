// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0033">Stream IDs MUST be encoded as variable-length integers.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0033")]
public sealed class REQ_QUIC_RFC9000_0033
{
    [Theory]
    [InlineData(new byte[] { 0x40 })]
    [InlineData(new byte[] { 0x80, 0x00, 0x00 })]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamIdentifier_RejectsTruncatedEncodings(byte[] encoded)
    {
        Assert.False(QuicStreamParser.TryParseStreamIdentifier(encoded, out _, out _));
    }
}
