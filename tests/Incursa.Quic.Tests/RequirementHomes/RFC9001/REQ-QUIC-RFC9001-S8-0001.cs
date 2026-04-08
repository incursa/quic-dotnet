namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S8-0001")]
public sealed class REQ_QUIC_RFC9001_S8_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicTransportParametersCanBeCarriedThroughTheCodecAndCommitted()
    {
        QuicTransportParameters sourceParameters = new()
        {
            MaxIdleTimeout = 25,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                IPv6Port = 8443,
                ConnectionId = [0x10, 0x11],
                StatelessResetToken = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F],
            },
        };

        Span<byte> encodedParameters = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            sourceParameters,
            QuicTransportParameterRole.Server,
            encodedParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedParameters));

        QuicTransportTlsBridgeState bridge = new();
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: parsedParameters)));

        sourceParameters.InitialSourceConnectionId![0] = 0xFF;
        parsedParameters.InitialSourceConnectionId![0] = 0xEE;
        parsedParameters.PreferredAddress!.ConnectionId[0] = 0xDD;

        Assert.NotSame(parsedParameters, bridge.LocalTransportParameters);
        Assert.Equal(25UL, bridge.LocalTransportParameters!.MaxIdleTimeout);
        Assert.True(bridge.LocalTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, bridge.LocalTransportParameters.InitialSourceConnectionId);
        Assert.Equal(new byte[] { 0x10, 0x11 }, bridge.LocalTransportParameters.PreferredAddress!.ConnectionId);
    }
}
