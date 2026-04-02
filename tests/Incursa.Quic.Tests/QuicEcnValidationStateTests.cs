namespace Incursa.Quic.Tests;

public sealed class QuicEcnValidationStateTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0004")]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsMatchingCountsForEachPacketNumberSpace()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect1);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Initial,
            new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Handshake,
            new QuicEcnCounts(0, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 1,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [Trait("Category", "Negative")]
    public void TryValidateAcknowledgedEcnCounts_DisablesEcnWhenCountsAreMissingOrExceedSentCounts()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect1);

        Assert.False(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.True(validationFailed);
        Assert.False(state.IsEcnEnabled);

        state.ReenableEcn();

        Assert.False(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.True(validationFailed);
        Assert.False(state.IsEcnEnabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0005")]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_AllowsReorderedAckFramesAndLaterRevalidation()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: false,
            out bool validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);

        Assert.False(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.True(validationFailed);
        Assert.False(state.IsEcnEnabled);

        state.ReenableEcn();

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }
}
