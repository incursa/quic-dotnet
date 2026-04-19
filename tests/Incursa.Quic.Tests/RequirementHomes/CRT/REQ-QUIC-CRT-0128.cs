namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0128")]
public sealed class REQ_QUIC_CRT_0128
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleDriverSurfacesOpaquePostHandshakeTicketBytesAfterFinishedThroughTheInternalTranscriptSeam()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] expectedTicketBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            expectedTicketBytes,
            [0x01, 0x02]);

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            offset: 0,
            ticketMessage,
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.OneRtt);

        Assert.Single(ticketUpdates);
        Assert.Equal(QuicTlsUpdateKind.PostHandshakeTicketAvailable, ticketUpdates[0].Kind);
        Assert.Equal(expectedTicketBytes, ticketUpdates[0].TicketBytes.ToArray());
        Assert.Equal(expectedTicketBytes, driver.State.PostHandshakeTicketBytes.ToArray());
        Assert.True(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(driver.State.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsPostHandshakeTicketsBeforeFinishedAndKeepsEarlyDataClosed()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateStartedClientDriver();
        byte[] ticketBytes = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0x01, 0x02, 0x03],
            [0x09]);

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            offset: 0,
            ticketBytes,
            out _));
        Assert.Empty(driver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.OneRtt));

        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PostHandshakeTicketBytes.IsEmpty);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.OneRttKeysAvailable);
        Assert.Null(driver.State.OneRttOpenPacketProtectionMaterial);
        Assert.Null(driver.State.OneRttProtectPacketProtectionMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsDuplicatePostHandshakeTicketsAndKeepsTheFirstOpaquePayload()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] firstTicketBytes = [0x10, 0x20, 0x30];
        byte[] duplicateTicketBytes = [0x40, 0x50, 0x60];
        byte[] firstTicketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            firstTicketBytes,
            [0x01]);
        byte[] duplicateTicketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            duplicateTicketBytes,
            [0x02]);

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            offset: 0,
            firstTicketMessage,
            out _));
        Assert.Single(driver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.OneRtt));

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            offset: (ulong)firstTicketMessage.Length,
            duplicateTicketMessage,
            out _));
        Assert.Empty(driver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.OneRtt));
        Assert.Equal(firstTicketBytes, driver.State.PostHandshakeTicketBytes.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDriverRejectsPostHandshakeTicketPublication()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        byte[] ticketBytes = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0x01, 0x02, 0x03],
            [0x04]);

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            offset: 0,
            ticketBytes,
            out _));
        Assert.Empty(driver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.OneRtt));
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PostHandshakeTicketBytes.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverSafelyIgnoresUnsupportedOneRttPostHandshakeCryptoMessages()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            offset: 0,
            QuicPostHandshakeTicketTestSupport.CreateUnknownPostHandshakeMessage(),
            out _));

        Assert.Empty(driver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.OneRtt));
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(driver.State.OneRttProtectPacketProtectionMaterial.HasValue);
    }
}
