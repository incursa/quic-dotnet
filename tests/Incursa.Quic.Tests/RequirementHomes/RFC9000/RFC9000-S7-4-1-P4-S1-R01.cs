// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-4-1-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0007")]
    public void ZeroRttRememberedParametersExcludeProhibitedHandshakeValues()
    {
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParametersWithEveryProhibitedValue();

        QuicTransportParameters remembered = Assert.IsType<QuicTransportParameters>(
            QuicZeroRttTransportParameterPolicy.CreateRememberedTransportParametersForClientZeroRtt(
                peerTransportParameters));

        Assert.Null(remembered.OriginalDestinationConnectionId);
        Assert.Null(remembered.StatelessResetToken);
        Assert.Null(remembered.MaxAckDelay);
        Assert.Null(remembered.PreferredAddress);
        Assert.Null(remembered.InitialSourceConnectionId);
        Assert.Null(remembered.RetrySourceConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AckDelayExponentIsClassifiedAsProhibitedEvenThoughTheRuntimeDoesNotModelIt()
    {
        Assert.True(QuicZeroRttTransportParameterPolicy.TryGetKnownDefinition(
            QuicZeroRttTransportParameterPolicy.AckDelayExponentId,
            out QuicZeroRttTransportParameterDefinition definition));

        Assert.Equal("ack_delay_exponent", definition.Name);
        Assert.Equal(QuicZeroRttTransportParameterMemoryRequirement.Prohibited, definition.MemoryRequirement);
    }

    private static QuicTransportParameters CreatePeerTransportParametersWithEveryProhibitedValue()
    {
        return new QuicTransportParameters
        {
            OriginalDestinationConnectionId = [0x01],
            StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray(),
            MaxAckDelay = 33,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 4433,
                IPv6Address = new byte[16],
                IPv6Port = 0,
                ConnectionId = [0xA0],
                StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x80 + value)).ToArray(),
            },
            InitialSourceConnectionId = [0x02],
            RetrySourceConnectionId = [0x03],
            InitialMaxData = 1,
        };
    }
}
