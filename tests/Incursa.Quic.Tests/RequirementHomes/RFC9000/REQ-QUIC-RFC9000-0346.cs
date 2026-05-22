namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0346")]
public sealed class REQ_QUIC_RFC9000_0346
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0006")]
    public void DetachedTicketSnapshotRemembersProcessablePeerTransportParametersForZeroRtt()
    {
        QuicTransportParameters peerTransportParameters = new()
        {
            MaxIdleTimeout = 21,
            MaxUdpPayloadSize = 1_350,
            InitialMaxData = 64,
            InitialMaxStreamDataBidiLocal = 8,
            InitialMaxStreamDataBidiRemote = 9,
            InitialMaxStreamDataUni = 10,
            InitialMaxStreamsBidi = 2,
            InitialMaxStreamsUni = 3,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 4,
            MaxAckDelay = 33,
            InitialSourceConnectionId = [0xAA],
        };

        QuicDetachedResumptionTicketSnapshot snapshot = CreateSnapshot(peerTransportParameters);

        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, snapshot.TicketBytes.ToArray());
        QuicTransportParameters remembered = Assert.IsType<QuicTransportParameters>(snapshot.ZeroRttTransportParameters);
        Assert.Equal(peerTransportParameters.MaxIdleTimeout, remembered.MaxIdleTimeout);
        Assert.Equal(peerTransportParameters.MaxUdpPayloadSize, remembered.MaxUdpPayloadSize);
        Assert.Equal(peerTransportParameters.InitialMaxData, remembered.InitialMaxData);
        Assert.Equal(peerTransportParameters.InitialMaxStreamDataBidiLocal, remembered.InitialMaxStreamDataBidiLocal);
        Assert.Equal(peerTransportParameters.InitialMaxStreamDataBidiRemote, remembered.InitialMaxStreamDataBidiRemote);
        Assert.Equal(peerTransportParameters.InitialMaxStreamDataUni, remembered.InitialMaxStreamDataUni);
        Assert.Equal(peerTransportParameters.InitialMaxStreamsBidi, remembered.InitialMaxStreamsBidi);
        Assert.Equal(peerTransportParameters.InitialMaxStreamsUni, remembered.InitialMaxStreamsUni);
        Assert.Equal(peerTransportParameters.DisableActiveMigration, remembered.DisableActiveMigration);
        Assert.Equal(peerTransportParameters.ActiveConnectionIdLimit, remembered.ActiveConnectionIdLimit);
        Assert.Null(remembered.MaxAckDelay);
        Assert.Null(remembered.InitialSourceConnectionId);
        Assert.True(snapshot.HasEarlyDataPrerequisiteMaterial);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S5P3-0006")]
    public void DetachedTicketSnapshotWithoutProcessablePeerTransportParametersDoesNotEnableZeroRttReadiness()
    {
        QuicDetachedResumptionTicketSnapshot snapshot = CreateSnapshot(new QuicTransportParameters
        {
            MaxAckDelay = 33,
            InitialSourceConnectionId = [0xAA],
        });

        Assert.Null(snapshot.ZeroRttTransportParameters);
        Assert.False(snapshot.HasEarlyDataPrerequisiteMaterial);
    }

    private static QuicDetachedResumptionTicketSnapshot CreateSnapshot(QuicTransportParameters peerTransportParameters)
    {
        return new QuicDetachedResumptionTicketSnapshot(
            ticketBytes: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
            ticketNonce: new byte[] { 0x01 },
            ticketLifetimeSeconds: 7_200,
            ticketAgeAdd: 0x01020304,
            capturedAtTicks: 1234,
            resumptionMasterSecret: Enumerable.Range(0, 32).Select(value => (byte)(0x40 + value)).ToArray(),
            ticketMaxEarlyDataSize: 4_096,
            peerTransportParameters);
    }
}
