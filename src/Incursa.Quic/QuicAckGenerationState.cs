using System.Diagnostics.CodeAnalysis;

namespace Incursa.Quic;

/// <summary>
/// Tracks processed packets and derives ACK frames plus ACK scheduling hints.
/// </summary>
internal sealed class QuicAckGenerationState
{
    /// <summary>
    /// RFC 9000 ACK frame type.
    /// </summary>
    private const byte AckFrameType = 0x02;

    /// <summary>
    /// RFC 9000 ACK_ECN frame type.
    /// </summary>
    private const byte AckEcnFrameType = 0x03;

    private readonly int maximumRetainedAckRanges;
    private readonly int minimumAckElicitingPacketsBeforeDelayedAck;
    private readonly Dictionary<QuicPacketNumberSpace, SpaceState> spaces = [];

    /// <summary>
    /// Initializes a new ACK-generation state tracker.
    /// </summary>
    /// <param name="maximumRetainedAckRanges">The maximum number of ACK ranges to retain and emit.</param>
    /// <param name="minimumAckElicitingPacketsBeforeDelayedAck">The number of ack-eliciting packets that should usually be observed before a delayed ACK is emitted.</param>
    internal QuicAckGenerationState(int maximumRetainedAckRanges = 32, int minimumAckElicitingPacketsBeforeDelayedAck = 2)
    {
        if (maximumRetainedAckRanges < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRetainedAckRanges));
        }

        if (minimumAckElicitingPacketsBeforeDelayedAck < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumAckElicitingPacketsBeforeDelayedAck));
        }

        this.maximumRetainedAckRanges = maximumRetainedAckRanges;
        this.minimumAckElicitingPacketsBeforeDelayedAck = minimumAckElicitingPacketsBeforeDelayedAck;
    }

    /// <summary>
    /// Gets the maximum number of ACK ranges to retain and emit.
    /// </summary>
    internal int MaximumRetainedAckRanges => maximumRetainedAckRanges;

    /// <summary>
    /// Gets the number of ack-eliciting packets that should usually be observed before a delayed ACK is emitted.
    /// </summary>
    internal int MinimumAckElicitingPacketsBeforeDelayedAck => minimumAckElicitingPacketsBeforeDelayedAck;

    /// <summary>
    /// Records a processed packet for later ACK generation.
    /// The optional buffering delay captures time spent waiting for decryption keys before processing.
    /// </summary>
    internal void RecordProcessedPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool ackEliciting,
        ulong receivedAtMicros,
        ulong bufferingDelayMicros = 0,
        bool congestionExperienced = false,
        QuicEcnCounts? ecnCounts = null)
    {
        SpaceState state = GetOrCreateSpaceState(packetNumberSpace);
        if (ackEliciting && TryGetAckElicitingStats(state, out ulong previousLargestAckElicitingPacketNumber, out _, out _))
        {
            if (packetNumber < previousLargestAckElicitingPacketNumber
                || (packetNumber > previousLargestAckElicitingPacketNumber
                    && packetNumber - previousLargestAckElicitingPacketNumber > 1))
            {
                state.ImmediateAckRequired = true;
            }
        }

        state.Receipts[packetNumber] = new PacketReceipt(
            receivedAtMicros,
            bufferingDelayMicros,
            ackEliciting,
            congestionExperienced,
            ecnCounts);

        if (ackEliciting && (packetNumberSpace == QuicPacketNumberSpace.Initial || packetNumberSpace == QuicPacketNumberSpace.Handshake))
        {
            state.ImmediateAckRequired = true;
        }

        if (congestionExperienced)
        {
            state.ImmediateAckRequired = true;
        }

        TrimOldestRangesIfNeeded(state);
    }

    /// <summary>
    /// Determines whether the tracked packets require an immediate ACK.
    /// </summary>
    internal bool ShouldSendAckImmediately(QuicPacketNumberSpace packetNumberSpace)
    {
        return TryGetSpaceState(packetNumberSpace, out SpaceState? state)
            && state.ImmediateAckRequired;
    }

    /// <summary>
    /// Determines whether an ACK frame should be piggybacked on an outgoing packet.
    /// </summary>
    internal bool ShouldIncludeAckFrameWithOutgoingPacket(QuicPacketNumberSpace packetNumberSpace, ulong nowMicros, ulong maxAckDelayMicros)
    {
        if (!TryGetSpaceState(packetNumberSpace, out SpaceState? state) || state.Receipts.Count == 0)
        {
            return false;
        }

        if (state.ImmediateAckRequired)
        {
            return true;
        }

        if (!TryGetAckElicitingStats(
                state,
                out ulong largestAckElicitingPacketNumber,
                out ulong largestAckElicitingReceivedAtMicros,
                out int ackElicitingPacketCount))
        {
            return false;
        }

        if (state.LastAckFrameTriggerPacketNumber.HasValue
            && largestAckElicitingPacketNumber <= state.LastAckFrameTriggerPacketNumber.Value)
        {
            return false;
        }

        if (state.LastAckFrameSentAtMicros.HasValue
            && GetElapsedMicros(nowMicros, state.LastAckFrameSentAtMicros.Value) < maxAckDelayMicros)
        {
            return false;
        }

        return ackElicitingPacketCount >= minimumAckElicitingPacketsBeforeDelayedAck
            || GetElapsedMicros(nowMicros, largestAckElicitingReceivedAtMicros) >= maxAckDelayMicros;
    }

    /// <summary>
    /// Determines whether the tracked packets justify an ACK-only packet.
    /// </summary>
    internal bool CanSendAckOnlyPacket(QuicPacketNumberSpace packetNumberSpace, ulong nowMicros, ulong maxAckDelayMicros)
    {
        if (!TryGetSpaceState(packetNumberSpace, out SpaceState? state) || state.Receipts.Count == 0)
        {
            return false;
        }

        if (state.ImmediateAckRequired)
        {
            return true;
        }

        if (!TryGetAckElicitingStats(state, out ulong largestAckElicitingPacketNumber, out _, out int ackElicitingPacketCount))
        {
            return false;
        }

        if (state.LastAckFrameTriggerPacketNumber.HasValue
            && largestAckElicitingPacketNumber <= state.LastAckFrameTriggerPacketNumber.Value)
        {
            return false;
        }

        return ackElicitingPacketCount > 0;
    }

    /// <summary>
    /// Builds an ACK frame for the specified packet number space.
    /// </summary>
    internal bool TryBuildAckFrame(QuicPacketNumberSpace packetNumberSpace, ulong nowMicros, out QuicAckFrame frame)
    {
        frame = new QuicAckFrame();

        if (!TryGetSpaceState(packetNumberSpace, out SpaceState? state) || state.Receipts.Count == 0)
        {
            return false;
        }

        List<PacketRange> ranges = BuildRanges(state.Receipts.Keys);
        if (ranges.Count == 0)
        {
            return false;
        }

        int firstRangeIndex = Math.Max(0, ranges.Count - maximumRetainedAckRanges);
        PacketRange newestRange = ranges[^1];
        List<QuicAckRange> additionalRanges = [];
        ulong previousSmallestAcknowledged = newestRange.Smallest;

        for (int rangeIndex = ranges.Count - 2; rangeIndex >= firstRangeIndex; rangeIndex--)
        {
            PacketRange range = ranges[rangeIndex];
            ulong gap = previousSmallestAcknowledged - range.Largest - 2;
            ulong ackRangeLength = range.Largest - range.Smallest;
            additionalRanges.Add(new QuicAckRange(gap, ackRangeLength, range.Smallest, range.Largest));
            previousSmallestAcknowledged = range.Smallest;
        }

        QuicEcnCounts? ecnCounts = null;
        foreach (KeyValuePair<ulong, PacketReceipt> entry in state.Receipts)
        {
            if (entry.Value.EcnCounts.HasValue)
            {
                ecnCounts = entry.Value.EcnCounts;
            }
        }

        frame = new QuicAckFrame
        {
            FrameType = ecnCounts.HasValue ? AckEcnFrameType : AckFrameType,
            LargestAcknowledged = newestRange.Largest,
            AckDelay = GetAckDelayMicros(nowMicros, state.Receipts[newestRange.Largest]),
            FirstAckRange = newestRange.Largest - newestRange.Smallest,
            AdditionalRanges = additionalRanges.ToArray(),
            EcnCounts = ecnCounts,
        };

        return true;
    }

    /// <summary>
    /// Records the time at which an ACK frame was sent.
    /// </summary>
    internal void MarkAckFrameSent(QuicPacketNumberSpace packetNumberSpace, ulong sentAtMicros, bool ackOnlyPacket)
    {
        SpaceState state = GetOrCreateSpaceState(packetNumberSpace);
        state.LastAckFrameSentAtMicros = sentAtMicros;
        state.ImmediateAckRequired = false;

        if (TryGetAckElicitingStats(state, out ulong largestAckElicitingPacketNumber, out _, out _))
        {
            state.LastAckFrameTriggerPacketNumber = largestAckElicitingPacketNumber;
        }
    }

    /// <summary>
    /// Records the ACK ranges carried in a sent ACK frame so they can be retired once the carrier packet is acknowledged.
    /// </summary>
    internal void MarkAckFrameSent(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        QuicAckFrame ackFrame,
        ulong sentAtMicros,
        bool ackOnlyPacket)
    {
        ArgumentNullException.ThrowIfNull(ackFrame);

        PacketRange[] ackedRanges = BuildAckFrameRanges(ackFrame);
        MarkAckFrameSent(packetNumberSpace, sentAtMicros, ackOnlyPacket);

        SpaceState state = GetOrCreateSpaceState(packetNumberSpace);
        state.SentAckFrames[packetNumber] = new SentAckFrameState(ackedRanges);
    }

    /// <summary>
    /// Retires the ACK ranges that were carried in a previously sent ACK frame when the carrier packet is acknowledged.
    /// </summary>
    internal bool TryRetireAcknowledgedAckRanges(QuicPacketNumberSpace packetNumberSpace, ulong acknowledgedPacketNumber)
    {
        if (!TryGetSpaceState(packetNumberSpace, out SpaceState? state)
            || !state.SentAckFrames.TryGetValue(acknowledgedPacketNumber, out SentAckFrameState sentAckFrame))
        {
            return false;
        }

        state.SentAckFrames.Remove(acknowledgedPacketNumber);
        foreach (PacketRange range in sentAckFrame.AckedRanges)
        {
            RemoveRange(state.Receipts, range);
        }

        if (state.Receipts.Count == 0)
        {
            state.ImmediateAckRequired = false;
        }

        return true;
    }

    /// <summary>
    /// Discards any retained ACK-generation state for the specified packet number space.
    /// </summary>
    internal bool TryDiscardPacketNumberSpace(QuicPacketNumberSpace packetNumberSpace)
    {
        return spaces.Remove(packetNumberSpace);
    }

    private static List<PacketRange> BuildRanges(IEnumerable<ulong> packetNumbers)
    {
        List<PacketRange> ranges = [];

        using IEnumerator<ulong> enumerator = packetNumbers.GetEnumerator();
        if (!enumerator.MoveNext())
        {
            return ranges;
        }

        ulong rangeStart = enumerator.Current;
        ulong rangeEnd = rangeStart;

        while (enumerator.MoveNext())
        {
            ulong packetNumber = enumerator.Current;
            if (rangeEnd != ulong.MaxValue && packetNumber == rangeEnd + 1)
            {
                rangeEnd = packetNumber;
                continue;
            }

            ranges.Add(new PacketRange(rangeStart, rangeEnd));
            rangeStart = packetNumber;
            rangeEnd = packetNumber;
        }

        ranges.Add(new PacketRange(rangeStart, rangeEnd));
        return ranges;
    }

    private static PacketRange[] BuildAckFrameRanges(QuicAckFrame frame)
    {
        if (frame.FirstAckRange > frame.LargestAcknowledged)
        {
            throw new ArgumentException("The ACK frame is invalid.", nameof(frame));
        }

        List<PacketRange> ranges = [new PacketRange(frame.LargestAcknowledged - frame.FirstAckRange, frame.LargestAcknowledged)];
        foreach (QuicAckRange additionalRange in frame.AdditionalRanges ?? [])
        {
            ranges.Add(new PacketRange(additionalRange.SmallestAcknowledged, additionalRange.LargestAcknowledged));
        }

        return ranges.ToArray();
    }

    private void TrimOldestRangesIfNeeded(SpaceState state)
    {
        List<PacketRange> ranges = BuildRanges(state.Receipts.Keys);
        if (ranges.Count <= maximumRetainedAckRanges)
        {
            return;
        }

        int rangesToRemove = ranges.Count - maximumRetainedAckRanges;
        for (int rangeIndex = 0; rangeIndex < rangesToRemove; rangeIndex++)
        {
            RemoveRange(state.Receipts, ranges[rangeIndex]);
        }
    }

    private static void RemoveRange(SortedDictionary<ulong, PacketReceipt> receipts, PacketRange range)
    {
        for (ulong packetNumber = range.Smallest; ; packetNumber++)
        {
            receipts.Remove(packetNumber);
            if (packetNumber == range.Largest)
            {
                return;
            }
        }
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

    private bool TryGetSpaceState(QuicPacketNumberSpace packetNumberSpace, [NotNullWhen(true)] out SpaceState? state)
    {
        return spaces.TryGetValue(packetNumberSpace, out state);
    }

    private static bool TryGetAckElicitingStats(
        SpaceState state,
        out ulong largestAckElicitingPacketNumber,
        out ulong largestAckElicitingReceivedAtMicros,
        out int ackElicitingPacketCount)
    {
        largestAckElicitingPacketNumber = default;
        largestAckElicitingReceivedAtMicros = default;
        ackElicitingPacketCount = 0;

        bool found = false;
        foreach (KeyValuePair<ulong, PacketReceipt> entry in state.Receipts)
        {
            if (!entry.Value.AckEliciting)
            {
                continue;
            }

            ackElicitingPacketCount++;
            largestAckElicitingPacketNumber = entry.Key;
            largestAckElicitingReceivedAtMicros = entry.Value.ReceivedAtMicros;
            found = true;
        }

        return found;
    }

    private static ulong GetElapsedMicros(ulong laterMicros, ulong earlierMicros)
    {
        return laterMicros >= earlierMicros ? laterMicros - earlierMicros : 0;
    }

    private static ulong GetAckDelayMicros(ulong nowMicros, PacketReceipt receipt)
    {
        ulong elapsedMicros = GetElapsedMicros(nowMicros, receipt.ReceivedAtMicros);
        return receipt.BufferingDelayMicros == 0
            ? elapsedMicros
            : SaturatingAdd(elapsedMicros, receipt.BufferingDelayMicros);
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
    }

    private readonly record struct PacketRange(ulong Smallest, ulong Largest);

    private readonly record struct SentAckFrameState(PacketRange[] AckedRanges);

    private readonly record struct PacketReceipt(
        ulong ReceivedAtMicros,
        ulong BufferingDelayMicros,
        bool AckEliciting,
        bool CongestionExperienced,
        QuicEcnCounts? EcnCounts);

    private sealed class SpaceState
    {
        internal SortedDictionary<ulong, PacketReceipt> Receipts { get; } = new();
        internal Dictionary<ulong, SentAckFrameState> SentAckFrames { get; } = new();

        internal bool ImmediateAckRequired { get; set; }

        internal ulong? LastAckFrameSentAtMicros { get; set; }

        internal ulong? LastAckFrameTriggerPacketNumber { get; set; }
    }
}
