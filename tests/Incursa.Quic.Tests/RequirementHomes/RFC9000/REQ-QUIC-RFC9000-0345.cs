namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0345")]
public sealed class REQ_QUIC_RFC9000_0345
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientUsesServerHandshakeValuesInsteadOfRememberedProhibitedValues()
    {
        QuicTransportParameters remembered = CreateProhibitedValues(prefix: 0x10);
        QuicTransportParameters handshake = CreateProhibitedValues(prefix: 0x40);

        QuicTransportParameters resolved =
            QuicZeroRttTransportParameterPolicy.ResolveClientHandshakeValuesForProhibitedZeroRttParameters(
                remembered,
                handshake);

        Assert.Equal(handshake.OriginalDestinationConnectionId, resolved.OriginalDestinationConnectionId);
        Assert.Equal(handshake.StatelessResetToken, resolved.StatelessResetToken);
        Assert.Equal(handshake.MaxAckDelay, resolved.MaxAckDelay);
        Assert.Equal(handshake.PreferredAddress!.IPv4Address, resolved.PreferredAddress!.IPv4Address);
        Assert.Equal(handshake.PreferredAddress.ConnectionId, resolved.PreferredAddress.ConnectionId);
        Assert.Equal(handshake.PreferredAddress.StatelessResetToken, resolved.PreferredAddress.StatelessResetToken);
        Assert.Equal(handshake.InitialSourceConnectionId, resolved.InitialSourceConnectionId);
        Assert.Equal(handshake.RetrySourceConnectionId, resolved.RetrySourceConnectionId);

        Assert.NotEqual(remembered.MaxAckDelay, resolved.MaxAckDelay);
        Assert.NotEqual(remembered.InitialSourceConnectionId, resolved.InitialSourceConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientUsesDefaultValuesWhenServerOmitsNewHandshakeValues()
    {
        QuicTransportParameters remembered = CreateProhibitedValues(prefix: 0x10);

        QuicTransportParameters resolved =
            QuicZeroRttTransportParameterPolicy.ResolveClientHandshakeValuesForProhibitedZeroRttParameters(
                remembered,
                handshakeTransportParameters: new QuicTransportParameters());

        Assert.Null(resolved.OriginalDestinationConnectionId);
        Assert.Null(resolved.StatelessResetToken);
        Assert.Equal(QuicMaxAckDelayPolicy.DefaultMaxAckDelayMicros, resolved.MaxAckDelay);
        Assert.Null(resolved.PreferredAddress);
        Assert.Null(resolved.InitialSourceConnectionId);
        Assert.Null(resolved.RetrySourceConnectionId);
    }

    private static QuicTransportParameters CreateProhibitedValues(byte prefix)
    {
        return new QuicTransportParameters
        {
            OriginalDestinationConnectionId = [prefix],
            StatelessResetToken = CreateSequentialBytes(prefix, 16),
            MaxAckDelay = (ulong)(prefix + 1),
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, prefix],
                IPv4Port = (ushort)(4_000 + prefix),
                IPv6Address = CreateSequentialBytes((byte)(prefix + 1), 16),
                IPv6Port = (ushort)(5_000 + prefix),
                ConnectionId = [(byte)(prefix + 2)],
                StatelessResetToken = CreateSequentialBytes((byte)(prefix + 3), 16),
            },
            InitialSourceConnectionId = [(byte)(prefix + 4)],
            RetrySourceConnectionId = [(byte)(prefix + 5)],
        };
    }

    private static byte[] CreateSequentialBytes(byte prefix, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(prefix + index);
        }

        return bytes;
    }
}
