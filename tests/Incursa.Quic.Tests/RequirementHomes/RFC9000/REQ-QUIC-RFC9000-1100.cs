namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1100">The extension_data field of the quic_transport_parameters extension defined in [QUIC-TLS] MUST contain the QUIC transport parameters.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1100")]
public sealed class REQ_QUIC_RFC9000_1100
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_RoundTripsKnownFieldsAndPreferredAddress()
    {
        byte[] statelessResetToken = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];
        byte[] preferredAddressStatelessResetToken = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = [0x01, 0x02, 0x03],
            MaxIdleTimeout = 25,
            StatelessResetToken = statelessResetToken,
            MaxUdpPayloadSize = 1350,
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 8192,
            InitialMaxStreamDataBidiRemote = 12288,
            InitialMaxStreamDataUni = 16384,
            InitialMaxStreamsBidi = 6,
            InitialMaxStreamsUni = 7,
            MaxAckDelay = 33,
            DisableActiveMigration = true,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                IPv6Port = 8443,
                ConnectionId = [0xAA, 0xBB],
                StatelessResetToken = preferredAddressStatelessResetToken,
            },
            ActiveConnectionIdLimit = 8,
            InitialSourceConnectionId = [0x11, 0x22],
            RetrySourceConnectionId = [0x33, 0x44, 0x55],
        };

        Span<byte> destination = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.True(parameters.OriginalDestinationConnectionId!.AsSpan().SequenceEqual(parsed.OriginalDestinationConnectionId!));
        Assert.Equal(parameters.MaxIdleTimeout, parsed.MaxIdleTimeout);
        Assert.True(parameters.StatelessResetToken!.AsSpan().SequenceEqual(parsed.StatelessResetToken!));
        Assert.Equal(parameters.MaxUdpPayloadSize, parsed.MaxUdpPayloadSize);
        Assert.Equal(parameters.InitialMaxData, parsed.InitialMaxData);
        Assert.Equal(parameters.InitialMaxStreamDataBidiLocal, parsed.InitialMaxStreamDataBidiLocal);
        Assert.Equal(parameters.InitialMaxStreamDataBidiRemote, parsed.InitialMaxStreamDataBidiRemote);
        Assert.Equal(parameters.InitialMaxStreamDataUni, parsed.InitialMaxStreamDataUni);
        Assert.Equal(parameters.InitialMaxStreamsBidi, parsed.InitialMaxStreamsBidi);
        Assert.Equal(parameters.InitialMaxStreamsUni, parsed.InitialMaxStreamsUni);
        Assert.Equal(parameters.MaxAckDelay, parsed.MaxAckDelay);
        Assert.True(parsed.DisableActiveMigration);
        Assert.NotNull(parsed.PreferredAddress);
        Assert.True(parameters.PreferredAddress!.IPv4Address.AsSpan().SequenceEqual(parsed.PreferredAddress!.IPv4Address));
        Assert.Equal(parameters.PreferredAddress.IPv4Port, parsed.PreferredAddress.IPv4Port);
        Assert.True(parameters.PreferredAddress.IPv6Address.AsSpan().SequenceEqual(parsed.PreferredAddress.IPv6Address));
        Assert.Equal(parameters.PreferredAddress.IPv6Port, parsed.PreferredAddress.IPv6Port);
        Assert.True(parameters.PreferredAddress.ConnectionId.AsSpan().SequenceEqual(parsed.PreferredAddress.ConnectionId));
        Assert.True(parameters.PreferredAddress.StatelessResetToken.AsSpan().SequenceEqual(parsed.PreferredAddress.StatelessResetToken));
        Assert.Equal(parameters.ActiveConnectionIdLimit, parsed.ActiveConnectionIdLimit);
        Assert.True(parameters.InitialSourceConnectionId!.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId!));
        Assert.True(parameters.RetrySourceConnectionId!.AsSpan().SequenceEqual(parsed.RetrySourceConnectionId!));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsMalformedExtensionData()
    {
        byte[] malformedExtensionData = [0x01, 0x02, 0x1E];

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            malformedExtensionData,
            QuicTransportParameterRole.Client,
            out _));
    }
}
