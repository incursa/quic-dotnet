// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0032")]
public sealed class REQ_QUIC_RFC9000_S18P2_0032
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesPreferredAddressConnectionIdLengthAsOneByte()
    {
        QuicTransportParameters parameters = QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters(
            preferredConnectionId: [0x20, 0x21, 0x22, 0x23]);

        byte[] encoded = QuicPreferredAddressRequirementTestSupport.FormatAsServer(parameters);

        const int tupleHeaderLength = 2;
        const int connectionIdLengthOffsetInsidePreferredAddress = 4 + 2 + 16 + 2;
        Assert.Equal(4, encoded[tupleHeaderLength + connectionIdLengthOffsetInsidePreferredAddress]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsPreferredAddressConnectionIdLengthAboveTwenty()
    {
        byte[] tooLongConnectionId = Enumerable.Range(0, 21).Select(value => (byte)value).ToArray();
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address,
            ipv4Port: 443,
            ipv6Address: QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            ipv6Port: 8443,
            connectionId: tooLongConnectionId,
            statelessResetToken: QuicPreferredAddressRequirementTestSupport.StatelessResetToken);
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0F,
                QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseTransportParameters_AcceptsMaximumPreferredAddressConnectionIdLength()
    {
        byte[] maximumConnectionId = Enumerable.Range(0, 20).Select(value => (byte)(0x40 + value)).ToArray();
        byte[] encoded = QuicPreferredAddressRequirementTestSupport.FormatAsServer(
            QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters(
                preferredConnectionId: maximumConnectionId));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(maximumConnectionId, parsed.PreferredAddress!.ConnectionId);
    }
}
