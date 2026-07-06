// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P3-0002")]
public sealed class REQ_QUIC_RFC9000_S5P2P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerPreferredAddressValueRoundTripsThroughClientParsing()
    {
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress();
        byte[] preferredAddressValue = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            preferredAddressValue,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(preferredAddress.IPv4Address, parsed.PreferredAddress!.IPv4Address);
        Assert.Equal(preferredAddress.IPv4Port, parsed.PreferredAddress.IPv4Port);
        Assert.Equal(preferredAddress.IPv6Address, parsed.PreferredAddress.IPv6Address);
        Assert.Equal(preferredAddress.IPv6Port, parsed.PreferredAddress.IPv6Port);
        Assert.Equal(preferredAddress.ConnectionId, parsed.PreferredAddress.ConnectionId);
        Assert.Equal(preferredAddress.StatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerPreferredAddressValuesRoundTripThroughClientParsing()
    {
        PreferredAddressRoundTripCase[] scenarios =
        [
            new(
                IPv4Address: [192, 0, 2, 10],
                IPv4Port: 443,
                IPv6Address: [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                IPv6Port: 8443,
                ConnectionId: [0x20, 0x21, 0x22, 0x23],
                StatelessResetToken: [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F]),
            new(
                IPv4Address: [198, 51, 100, 77],
                IPv4Port: 1,
                IPv6Address: [0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6],
                IPv6Port: 65535,
                ConnectionId: [0x01],
                StatelessResetToken: [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F]),
            new(
                IPv4Address: [203, 0, 113, 250],
                IPv4Port: 49152,
                IPv6Address: [0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64],
                IPv6Port: 4433,
                ConnectionId: [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7],
                StatelessResetToken: [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F]),
        ];

        foreach (PreferredAddressRoundTripCase scenario in scenarios)
        {
            QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                scenario.ConnectionId,
                scenario.IPv4Address,
                scenario.IPv4Port,
                scenario.IPv6Address,
                scenario.IPv6Port,
                scenario.StatelessResetToken);

            byte[] preferredAddressValue = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

            Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
                preferredAddressValue,
                out QuicTransportParameters parsed));

            Assert.NotNull(parsed.PreferredAddress);
            Assert.Equal(scenario.IPv4Address, parsed.PreferredAddress!.IPv4Address);
            Assert.Equal(scenario.IPv4Port, parsed.PreferredAddress.IPv4Port);
            Assert.Equal(scenario.IPv6Address, parsed.PreferredAddress.IPv6Address);
            Assert.Equal(scenario.IPv6Port, parsed.PreferredAddress.IPv6Port);
            Assert.Equal(scenario.ConnectionId, parsed.PreferredAddress.ConnectionId);
            Assert.Equal(scenario.StatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
        }
    }

    private readonly record struct PreferredAddressRoundTripCase(
        byte[] IPv4Address,
        ushort IPv4Port,
        byte[] IPv6Address,
        ushort IPv6Port,
        byte[] ConnectionId,
        byte[] StatelessResetToken);
}
