namespace Incursa.Quic;

/// <summary>
/// Tracks the ECN send and validation state for a path.
/// </summary>
public sealed class QuicEcnValidationState
{
    private readonly Dictionary<QuicPacketNumberSpace, SpaceState> spaces = [];

    /// <summary>
    /// Gets whether ECN remains enabled for the current path.
    /// </summary>
    public bool IsEcnEnabled { get; private set; } = true;

    /// <summary>
    /// Marks ECN as disabled until the caller explicitly re-enables it for a later validation attempt.
    /// </summary>
    public void DisableEcn()
    {
        IsEcnEnabled = false;
    }

    /// <summary>
    /// Re-enables ECN for a later validation attempt.
    /// </summary>
    public void ReenableEcn()
    {
        IsEcnEnabled = true;
    }

    /// <summary>
    /// Records that a packet was sent with the supplied ECN marking.
    /// </summary>
    public void RecordPacketSent(QuicPacketNumberSpace packetNumberSpace, QuicEcnMarking ecnMarking)
    {
        SpaceState state = GetOrCreateSpaceState(packetNumberSpace);
        switch (ecnMarking)
        {
            case QuicEcnMarking.Ect0:
                state.SentEct0Count = SaturatingAdd(state.SentEct0Count, 1);
                break;
            case QuicEcnMarking.Ect1:
                state.SentEct1Count = SaturatingAdd(state.SentEct1Count, 1);
                break;
        }
    }

    /// <summary>
    /// Validates an ACK frame's ECN counts against the packets sent in the same packet number space.
    /// </summary>
    /// <remarks>
    /// The caller is expected to provide the number of newly acknowledged packets that were originally sent
    /// with ECT(0) and ECT(1) markings, if any.
    /// </remarks>
    public bool TryValidateAcknowledgedEcnCounts(
        QuicPacketNumberSpace packetNumberSpace,
        QuicEcnCounts? reportedCounts,
        ulong newlyAcknowledgedEct0Packets,
        ulong newlyAcknowledgedEct1Packets,
        bool largestAcknowledgedPacketNumberIncreased,
        out bool validationFailed)
    {
        validationFailed = false;

        if (!largestAcknowledgedPacketNumberIncreased)
        {
            return true;
        }

        SpaceState state = GetOrCreateSpaceState(packetNumberSpace);

        if (reportedCounts is null)
        {
            if (newlyAcknowledgedEct0Packets != 0 || newlyAcknowledgedEct1Packets != 0)
            {
                return FailValidation(out validationFailed);
            }

            return true;
        }

        QuicEcnCounts counts = reportedCounts.Value;
        if (counts.Ect0Count < state.ReportedEct0Count
            || counts.Ect1Count < state.ReportedEct1Count
            || counts.EcnCeCount < state.ReportedEcnCeCount)
        {
            return FailValidation(out validationFailed);
        }

        if (counts.Ect0Count > state.SentEct0Count || counts.Ect1Count > state.SentEct1Count)
        {
            return FailValidation(out validationFailed);
        }

        ulong ect0Increase = counts.Ect0Count - state.ReportedEct0Count;
        ulong ect1Increase = counts.Ect1Count - state.ReportedEct1Count;
        ulong ecnCeIncrease = counts.EcnCeCount - state.ReportedEcnCeCount;

        if (ect0Increase + ecnCeIncrease < newlyAcknowledgedEct0Packets
            || ect1Increase + ecnCeIncrease < newlyAcknowledgedEct1Packets)
        {
            return FailValidation(out validationFailed);
        }

        state.ReportedEct0Count = counts.Ect0Count;
        state.ReportedEct1Count = counts.Ect1Count;
        state.ReportedEcnCeCount = counts.EcnCeCount;
        IsEcnEnabled = true;
        return true;
    }

    private bool FailValidation(out bool validationFailed)
    {
        validationFailed = true;
        IsEcnEnabled = false;
        return false;
    }

    private SpaceState GetOrCreateSpaceState(QuicPacketNumberSpace packetNumberSpace)
    {
        if (!spaces.TryGetValue(packetNumberSpace, out SpaceState? state))
        {
            state = new SpaceState();
            spaces.Add(packetNumberSpace, state);
        }

        return state;
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        if (ulong.MaxValue - left < right)
        {
            return ulong.MaxValue;
        }

        return left + right;
    }

    private sealed class SpaceState
    {
        public ulong SentEct0Count { get; set; }

        public ulong SentEct1Count { get; set; }

        public ulong ReportedEct0Count { get; set; }

        public ulong ReportedEct1Count { get; set; }

        public ulong ReportedEcnCeCount { get; set; }
    }
}
