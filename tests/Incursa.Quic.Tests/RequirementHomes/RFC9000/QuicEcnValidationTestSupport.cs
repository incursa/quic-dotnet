namespace Incursa.Quic.Tests;

internal static class QuicEcnValidationTestSupport
{
    internal static QuicEcnValidationState CreateApplicationDataState(ulong sentEct0Count, ulong sentEct1Count)
    {
        QuicEcnValidationState state = new();
        for (ulong sent = 0; sent < sentEct0Count; sent++)
        {
            state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);
        }

        for (ulong sent = 0; sent < sentEct1Count; sent++)
        {
            state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect1);
        }

        return state;
    }

    internal static void AssertValidationFailure(
        QuicEcnValidationState state,
        QuicEcnCounts? reportedCounts,
        ulong newlyAcknowledgedEct0Packets,
        ulong newlyAcknowledgedEct1Packets,
        bool largestAcknowledgedPacketNumberIncreased = true)
    {
        Assert.False(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts,
            newlyAcknowledgedEct0Packets,
            newlyAcknowledgedEct1Packets,
            largestAcknowledgedPacketNumberIncreased,
            out bool validationFailed));
        Assert.True(validationFailed);
        Assert.False(state.IsEcnEnabled);
    }

    internal static void AssertValidationSuccess(
        QuicEcnValidationState state,
        QuicEcnCounts? reportedCounts,
        ulong newlyAcknowledgedEct0Packets,
        ulong newlyAcknowledgedEct1Packets,
        bool largestAcknowledgedPacketNumberIncreased = true)
    {
        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts,
            newlyAcknowledgedEct0Packets,
            newlyAcknowledgedEct1Packets,
            largestAcknowledgedPacketNumberIncreased,
            out bool validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }
}
