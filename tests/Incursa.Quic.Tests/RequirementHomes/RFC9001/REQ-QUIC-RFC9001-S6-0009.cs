namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0009">Endpoints MUST NOT send a TLS KeyUpdate message.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6-0009")]
public sealed class REQ_QUIC_RFC9001_S6_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleDriverSurfacesTLSKeyUpdateAsAProhibitedMessageThroughThePostHandshakeSeam()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            QuicPostHandshakeTicketTestSupport.CreateProhibitedKeyUpdatePostHandshakeMessage());

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation, updates[0].Kind);
        Assert.True(driver.State.IsTerminal);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, driver.State.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", driver.State.FatalAlertDescription);
        Assert.False(driver.State.KeyUpdateInstalled);
        Assert.Equal(0U, driver.State.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverKeepsNewSessionTicketProcessingSeparateFromTLSKeyUpdateProhibition()
    {
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0xDE, 0xAD, 0xBE, 0xEF],
            [0x01, 0x02]);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.OneRtt, ticketMessage);

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.PostHandshakeTicketAvailable, updates[0].Kind);
        Assert.True(driver.State.HasPostHandshakeTicket);
        Assert.False(driver.State.IsTerminal);
        Assert.False(driver.State.KeyUpdateInstalled);
        Assert.Equal(0U, driver.State.CurrentOneRttKeyPhase);
    }
}
