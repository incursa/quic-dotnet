// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0033")]
public sealed class REQ_QUIC_RFC9000_S18P2_0033
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesSixteenBytePreferredAddressStatelessResetTokenField()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress());
        int tokenOffset = QuicPreferredAddressRequirementTestSupport.ConnectionIdOffset
            + QuicPreferredAddressRequirementTestSupport.PreferredConnectionId.Length;

        Assert.Equal(16, QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.StatelessResetToken, value.AsSpan(
            tokenOffset,
            QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength).ToArray());
        Assert.Equal(tokenOffset + QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength, value.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsTruncatedPreferredAddressStatelessResetTokenField()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress());

        Assert.False(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value[..^1],
            out _));
    }
}
