namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0006")]
public sealed class REQ_QUIC_RFC9001_S5_0006
{
    private static readonly byte[] ClientInitialDcid = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];

    private static readonly byte[] ExpectedClientAeadKey =
    [
        0x1F, 0x36, 0x96, 0x13, 0xDD, 0x76, 0xD5, 0x46,
        0x77, 0x30, 0xEF, 0xCB, 0xE3, 0xB1, 0xA2, 0x2D,
    ];

    private static readonly byte[] ExpectedClientAeadIv =
    [
        0xFA, 0x04, 0x4B, 0x2F, 0x42, 0xA3, 0xFD, 0x3B,
        0x46, 0xFB, 0x25, 0x5C,
    ];

    private static readonly byte[] ExpectedClientHeaderProtectionKey =
    [
        0x9F, 0x50, 0x44, 0x9E, 0x04, 0xA0, 0xE8, 0x10,
        0x28, 0x3A, 0x1E, 0x99, 0x33, 0xAD, 0xED, 0xD2,
    ];

    private static readonly byte[] ExpectedServerInitialSecret =
    [
        0x3C, 0x19, 0x98, 0x28, 0xFD, 0x13, 0x9E, 0xFD,
        0x21, 0x6C, 0x15, 0x5A, 0xD8, 0x44, 0xCC, 0x81,
        0xFB, 0x82, 0xFA, 0x8D, 0x74, 0x46, 0xFA, 0x7D,
        0x78, 0xBE, 0x80, 0x3A, 0xCD, 0xDA, 0x95, 0x1B,
    ];

    private static readonly byte[] ExpectedServerAeadKey =
    [
        0xCF, 0x3A, 0x53, 0x31, 0x65, 0x3C, 0x36, 0x4C,
        0x88, 0xF0, 0xF3, 0x79, 0xB6, 0x06, 0x7E, 0x37,
    ];

    private static readonly byte[] ExpectedServerAeadIv =
    [
        0x0A, 0xC1, 0x49, 0x3C, 0xA1, 0x90, 0x58, 0x53,
        0xB0, 0xBB, 0xA0, 0x3E,
    ];

    private static readonly byte[] ExpectedServerHeaderProtectionKey =
    [
        0xC2, 0x06, 0xB8, 0xD9, 0xB9, 0xF0, 0xF3, 0x76,
        0x44, 0x43, 0x0B, 0x49, 0x0E, 0xEA, 0xA3, 0x14,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDeriveInitialKeyMaterial_UsesTheFirstClientInitialDcid()
    {
        Assert.True(QuicInitialPacketProtection.TryDeriveInitialKeyMaterial(
            ClientInitialDcid,
            out QuicInitialPacketProtectionMaterial clientMaterial,
            out QuicInitialPacketProtectionMaterial serverMaterial));

        Assert.Equal(QuicAeadAlgorithm.Aes128Gcm, clientMaterial.Algorithm);
        Assert.True(ExpectedClientAeadKey.AsSpan().SequenceEqual(clientMaterial.AeadKey));
        Assert.True(ExpectedClientAeadIv.AsSpan().SequenceEqual(clientMaterial.AeadIv));
        Assert.True(ExpectedClientHeaderProtectionKey.AsSpan().SequenceEqual(clientMaterial.HeaderProtectionKey));

        Assert.Equal(QuicAeadAlgorithm.Aes128Gcm, serverMaterial.Algorithm);
        Assert.True(ExpectedServerAeadKey.AsSpan().SequenceEqual(serverMaterial.AeadKey));
        Assert.True(ExpectedServerAeadIv.AsSpan().SequenceEqual(serverMaterial.AeadIv));
        Assert.True(ExpectedServerHeaderProtectionKey.AsSpan().SequenceEqual(serverMaterial.HeaderProtectionKey));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetryReceived_RekeysSubsequentInitialPacketsToTheRetrySelectedDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection originalServerProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            out QuicInitialPacketProtection retryServerProtection));

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        QuicConnectionSendDatagramEffect replayDatagram = Assert.Single(
            retryResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator packetCoordinator = new();
        Assert.False(packetCoordinator.TryOpenInitialPacket(
            replayDatagram.Datagram.Span,
            originalServerProtection,
            out _,
            out _,
            out _));
        Assert.True(packetCoordinator.TryOpenInitialPacket(
            replayDatagram.Datagram.Span,
            retryServerProtection,
            out byte[] openedReplayPacket,
            out _,
            out _));

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedReplayPacket,
            out _,
            out uint replayVersion,
            out ReadOnlySpan<byte> replayDestinationConnectionId,
            out _,
            out ReadOnlySpan<byte> replayVersionSpecificData));
        Assert.Equal(1u, replayVersion);
        Assert.Equal(QuicS17P2P5P2TestSupport.RetrySourceConnectionId, replayDestinationConnectionId.ToArray());
        Assert.True(QuicVariableLengthInteger.TryParse(
            replayVersionSpecificData,
            out ulong retryTokenLength,
            out int retryTokenLengthBytes));
        Assert.Equal((ulong)QuicS17P2P5P2TestSupport.RetryToken.Length, retryTokenLength);
        Assert.True(QuicS17P2P5P2TestSupport.RetryToken.AsSpan().SequenceEqual(
            replayVersionSpecificData.Slice(retryTokenLengthBytes, QuicS17P2P5P2TestSupport.RetryToken.Length)));
    }
}
