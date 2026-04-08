namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S8-0002")]
public sealed class REQ_QUIC_RFC9001_S8_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AuthenticatedTransportParametersAreCommittedAsSnapshots()
    {
        QuicTransportParameters sourceParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [203, 0, 113, 7],
                IPv4Port = 9443,
                IPv6Address = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
                IPv6Port = 9553,
                ConnectionId = [0x44, 0x55],
                StatelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F],
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
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
            TransportParameters: parsedParameters)));

        sourceParameters.InitialSourceConnectionId![0] = 0xFF;
        parsedParameters.InitialSourceConnectionId![0] = 0xEE;
        parsedParameters.PreferredAddress!.ConnectionId[0] = 0xDD;
        parsedParameters.PreferredAddress.StatelessResetToken[0] = 0xCC;

        Assert.True(bridge.PeerTransportParametersAuthenticated);
        Assert.NotSame(parsedParameters, bridge.PeerTransportParameters);
        Assert.Equal(30UL, bridge.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(bridge.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, bridge.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(new byte[] { 0x44, 0x55 }, bridge.PeerTransportParameters.PreferredAddress!.ConnectionId);
        Assert.Equal(new byte[] { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F }, bridge.PeerTransportParameters.PreferredAddress.StatelessResetToken);
    }
}
