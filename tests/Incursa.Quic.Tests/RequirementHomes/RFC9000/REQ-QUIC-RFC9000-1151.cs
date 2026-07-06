// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1151")]
public sealed class REQ_QUIC_RFC9000_1151
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_PreservesStatelessResetTokenAssociatedWithPreferredConnectionId()
    {
        byte[] expectedConnectionId = [0x44, 0x45, 0x46, 0x47];
        byte[] expectedStatelessResetToken = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F];
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredConnectionId: expectedConnectionId,
                statelessResetToken: expectedStatelessResetToken));

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(expectedConnectionId, parsed.PreferredAddress!.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsPreferredAddressMissingCompleteStatelessResetToken()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredConnectionId: [0x44, 0x45, 0x46, 0x47],
                statelessResetToken: [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F]));

        Assert.False(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value[..^1],
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreferredAddressCarriesStatelessResetTokenForEachConnectionIdLength()
    {
        for (int connectionIdLength = 1; connectionIdLength <= 20; connectionIdLength++)
        {
            byte[] expectedConnectionId = Enumerable.Range(0, connectionIdLength)
                .Select(value => (byte)(0x40 + value))
                .ToArray();
            byte[] expectedStatelessResetToken = Enumerable.Range(0, 16)
                .Select(value => (byte)(0x80 + connectionIdLength + value))
                .ToArray();
            byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
                QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                    preferredConnectionId: expectedConnectionId,
                    statelessResetToken: expectedStatelessResetToken));

            Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
                value,
                out QuicTransportParameters parsed));
            Assert.NotNull(parsed.PreferredAddress);
            Assert.Equal(expectedConnectionId, parsed.PreferredAddress!.ConnectionId);
            Assert.Equal(expectedStatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
        }
    }
}
