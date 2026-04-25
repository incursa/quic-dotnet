using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks representative ECN ACK-count validation branches with fresh helper state per operation.
/// </summary>
[MemoryDiagnoser]
public class QuicEcnValidationBenchmarks
{
    /// <summary>
    /// Measures the successful ECT(0) validation path.
    /// </summary>
    [Benchmark]
    public bool ValidateMatchingEct0Counts()
    {
        QuicEcnValidationState state = CreateState(sentEct0Count: 2, sentEct1Count: 0);
        return state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed)
            && !validationFailed
            && state.IsEcnEnabled;
    }

    /// <summary>
    /// Measures the successful ECT(1) validation path when one packet is reported as CE.
    /// </summary>
    [Benchmark]
    public bool ValidateEct1CountsWithCeSubstitution()
    {
        QuicEcnValidationState state = CreateState(sentEct0Count: 0, sentEct1Count: 2);
        return state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(0, 1, 1),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed)
            && !validationFailed
            && state.IsEcnEnabled;
    }

    /// <summary>
    /// Measures the missing-counts failure path for newly acknowledged ECT packets.
    /// </summary>
    [Benchmark]
    public bool RejectMissingCountsForNewlyAcknowledgedEct()
    {
        QuicEcnValidationState state = CreateState(sentEct0Count: 1, sentEct1Count: 1);
        return !state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed)
            && validationFailed
            && !state.IsEcnEnabled;
    }

    /// <summary>
    /// Measures the too-small ECT(1)+CE increase failure path.
    /// </summary>
    [Benchmark]
    public bool RejectTooSmallEct1AndCeIncrease()
    {
        QuicEcnValidationState state = CreateState(sentEct0Count: 0, sentEct1Count: 2);
        return !state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(0, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 2,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed)
            && validationFailed
            && !state.IsEcnEnabled;
    }

    /// <summary>
    /// Measures the reordered-ACK branch that bypasses validation when largest acknowledged does not advance.
    /// </summary>
    [Benchmark]
    public bool IgnoreReorderedAckWithoutLargestAcknowledgedIncrease()
    {
        QuicEcnValidationState state = CreateState(sentEct0Count: 1, sentEct1Count: 1);
        return state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1,
            largestAcknowledgedPacketNumberIncreased: false,
            out bool validationFailed)
            && !validationFailed
            && state.IsEcnEnabled;
    }

    private static QuicEcnValidationState CreateState(ulong sentEct0Count, ulong sentEct1Count)
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
}
