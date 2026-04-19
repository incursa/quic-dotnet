using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0129")]
public sealed class REQ_QUIC_CRT_0129
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleDriverConsumesRealOneRttCryptoTicketIngressAndRetainsOpaqueTicketBytesAfterFinished()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] expectedTicketBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            expectedTicketBytes,
            [0x01, 0x02]);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

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
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0x01, 0x02, 0x03],
            [0x09]);

        Assert.Empty(driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.OneRtt, ticketMessage));
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

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            firstTicketMessage));
        Assert.Empty(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            duplicateTicketMessage));
        Assert.Equal(firstTicketBytes, driver.State.PostHandshakeTicketBytes.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDriverRejectsPostHandshakeTicketIngress()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0x01, 0x02, 0x03],
            [0x04]);

        Assert.Empty(driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.OneRtt, ticketMessage));
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PostHandshakeTicketBytes.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverSafelyIgnoresUnsupportedOneRttPostHandshakeCryptoMessages()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();

        IReadOnlyList<QuicTlsStateUpdate> unsupportedPostHandshakeUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            QuicPostHandshakeTicketTestSupport.CreateUnknownPostHandshakeMessage());

        Assert.Empty(unsupportedPostHandshakeUpdates);
        Assert.False(driver.State.HasPostHandshakeTicket);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(driver.State.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceDoesNotExposeTicketOwnershipResumptionOrEarlyDataPromises()
    {
        string[] forbiddenFragments = ["Ownership", "Resum", "Ticket", "EarlyData"];

        string[] publicMembers = typeof(QuicConnection).Assembly
            .GetExportedTypes()
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(member => $"{type.FullName}.{member.Name}"))
            .Concat(
                typeof(QuicConnection).Assembly.GetExportedTypes()
                    .Select(type => type.FullName ?? type.Name))
            .ToArray();

        Assert.DoesNotContain(publicMembers, member =>
            forbiddenFragments.Any(fragment => member.Contains(fragment, StringComparison.OrdinalIgnoreCase)));
    }
}
