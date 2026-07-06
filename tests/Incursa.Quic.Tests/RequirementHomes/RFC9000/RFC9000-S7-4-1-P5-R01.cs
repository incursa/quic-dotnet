// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-4-1-P5-R01")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DetachedTicketSnapshotFuzz_RemembersOnlyProcessableZeroRttParameters()
    {
        for (ulong value = 1; value <= 4; value++)
        {
            QuicTransportParameters peerTransportParameters = new()
            {
                MaxIdleTimeout = 20 + value,
                MaxUdpPayloadSize = 1_200 + value,
                MaxDatagramFrameSize = 256 + value,
                InitialMaxData = 1_000 + value,
                InitialMaxStreamDataBidiLocal = 100 + value,
                InitialMaxStreamDataBidiRemote = 120 + value,
                InitialMaxStreamDataUni = 80 + value,
                InitialMaxStreamsBidi = value,
                InitialMaxStreamsUni = value + 1,
                DisableActiveMigration = value % 2 == 0,
                ActiveConnectionIdLimit = 2 + value,
                MaxAckDelay = 30 + value,
                InitialSourceConnectionId = [(byte)(0xA0 + value)],
            };

            QuicDetachedResumptionTicketSnapshot snapshot = CreateSnapshot(peerTransportParameters);
            QuicTransportParameters remembered = Assert.IsType<QuicTransportParameters>(snapshot.ZeroRttTransportParameters);

            Assert.Equal(peerTransportParameters.MaxIdleTimeout, remembered.MaxIdleTimeout);
            Assert.Equal(peerTransportParameters.MaxUdpPayloadSize, remembered.MaxUdpPayloadSize);
            Assert.Equal(peerTransportParameters.MaxDatagramFrameSize, remembered.MaxDatagramFrameSize);
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
