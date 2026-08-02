// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Incursa.Quic;

internal enum QuicImmediateAckTrigger
{
    None,
    AckElicitingPacketReordered,
    AckElicitingPacketGap,
    HandshakePacket,
    CongestionExperienced,
}

internal readonly record struct QuicPacketReceipt
{
    private const byte AckElicitingFlag = 1 << 0;

    private readonly byte flags;

    internal QuicPacketReceipt(
        ulong ReceivedAtMicros,
        ulong BufferingDelayMicros,
        bool AckEliciting)
    {
        this.ReceivedAtMicros = ReceivedAtMicros;
        this.BufferingDelayMicros = BufferingDelayMicros;
        flags = AckEliciting ? AckElicitingFlag : (byte)0;
    }

    public ulong ReceivedAtMicros { get; }

    public ulong BufferingDelayMicros { get; }

    public bool AckEliciting => (flags & AckElicitingFlag) != 0;

    public void Deconstruct(
        out ulong ReceivedAtMicros,
        out ulong BufferingDelayMicros,
        out bool AckEliciting)
    {
        ReceivedAtMicros = this.ReceivedAtMicros;
        BufferingDelayMicros = this.BufferingDelayMicros;
        AckEliciting = this.AckEliciting;
    }
}

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

    // CONTEXT: ACK generation keeps common cases on the stack
    // SEE: code:src/Incursa.Quic/QuicAckGenerationState.cs#TryBuildAckFrame
    // SEE: code:src/Incursa.Quic/QuicAckGenerationState.cs#TryRetireAcknowledgedAckRanges
    // The 32-entry stack thresholds keep the common ACK and ACK-retirement
    // paths allocation-free. Larger histories fall back to ArrayPool only when
    // the retained ACK set is genuinely bigger than the hot-path shape.
    private const int StackPacketRangeCapacity = 32;
    private const int StackAckFramePacketNumberCapacity = 32;
    private const int InitialPacketNumberSpaceCapacity = 32;

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
    internal QuicImmediateAckTrigger RecordProcessedPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool ackEliciting,
        ulong receivedAtMicros,
        ulong bufferingDelayMicros = 0,
        bool congestionExperienced = false,
        QuicEcnCounts? ecnCounts = null)
    {
        SpaceState state = GetOrCreateSpaceState(packetNumberSpace);
        QuicImmediateAckTrigger immediateAckTrigger = QuicImmediateAckTrigger.None;
        if (ackEliciting && state.LargestAckElicitingPacketNumber is ulong previousLargestAckElicitingPacketNumber)
        {
            bool packetIsReordered = packetNumber < previousLargestAckElicitingPacketNumber;
            bool packetHasAckElicitingNumberGap = packetNumber > previousLargestAckElicitingPacketNumber
                && packetNumber - previousLargestAckElicitingPacketNumber > 1;
            if (packetIsReordered || packetHasAckElicitingNumberGap)
            {
                state.ImmediateAckRequired = true;
                immediateAckTrigger = packetIsReordered
                    ? QuicImmediateAckTrigger.AckElicitingPacketReordered
                    : QuicImmediateAckTrigger.AckElicitingPacketGap;
            }
        }

        bool replacesLargestAckElicitingPacket = !ackEliciting
            && state.LargestAckElicitingPacketNumber == packetNumber
            && state.Receipts.TryGetValue(packetNumber, out QuicPacketReceipt previousReceipt)
            && previousReceipt.AckEliciting;
        state.Receipts.Set(packetNumber, new QuicPacketReceipt(
            receivedAtMicros,
            bufferingDelayMicros,
            ackEliciting));
        if (ackEliciting
            && (!state.LargestAckElicitingPacketNumber.HasValue
                || packetNumber > state.LargestAckElicitingPacketNumber.Value))
        {
            state.LargestAckElicitingPacketNumber = packetNumber;
        }
        else if (replacesLargestAckElicitingPacket)
        {
            RefreshLargestAckElicitingPacketNumber(state);
        }

        if (ecnCounts.HasValue)
        {
            state.EcnCounts = ecnCounts;
        }

        if (ackEliciting && (packetNumberSpace == QuicPacketNumberSpace.Initial || packetNumberSpace == QuicPacketNumberSpace.Handshake))
        {
            state.ImmediateAckRequired = true;
            immediateAckTrigger = QuicImmediateAckTrigger.HandshakePacket;
        }

        if (congestionExperienced)
        {
            state.ImmediateAckRequired = true;
            immediateAckTrigger = QuicImmediateAckTrigger.CongestionExperienced;
        }

        TrimOldestRangesIfNeeded(state);
        return immediateAckTrigger;
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

        if (!TryGetAckElicitingStatsAfterLastAckTrigger(
                state,
                out _,
                out ulong earliestUnacknowledgedAckElicitingReceivedAtMicros,
                out int ackElicitingPacketCount))
        {
            return false;
        }

        if (ackElicitingPacketCount >= minimumAckElicitingPacketsBeforeDelayedAck)
        {
            return true;
        }

        if (state.LastAckFrameSentAtMicros.HasValue
            && GetElapsedMicros(nowMicros, state.LastAckFrameSentAtMicros.Value) < maxAckDelayMicros)
        {
            return false;
        }

        return GetElapsedMicros(nowMicros, earliestUnacknowledgedAckElicitingReceivedAtMicros) >= maxAckDelayMicros;
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

        return TryGetAckElicitingStatsAfterLastAckTrigger(state, out _, out _, out int ackElicitingPacketCount)
            && ackElicitingPacketCount > 0;
    }

    private static bool TryGetAckElicitingStatsAfterLastAckTrigger(
        SpaceState state,
        out ulong largestAckElicitingPacketNumber,
        out ulong earliestAckElicitingReceivedAtMicros,
        out int ackElicitingPacketCount)
    {
        largestAckElicitingPacketNumber = default;
        earliestAckElicitingReceivedAtMicros = default;
        ackElicitingPacketCount = 0;

        bool found = false;
        int startIndex = state.LastAckFrameTriggerPacketNumber is ulong lastAckFrameTriggerPacketNumber
            ? state.Receipts.FindFirstIndexGreaterThan(lastAckFrameTriggerPacketNumber)
            : 0;
        for (int index = startIndex; index < state.Receipts.Count; index++)
        {
            ulong packetNumber = state.Receipts.GetPacketNumber(index);
            QuicPacketReceipt receipt = state.Receipts.GetReceipt(index);
            if (!receipt.AckEliciting)
            {
                continue;
            }

            if (!found)
            {
                earliestAckElicitingReceivedAtMicros = receipt.ReceivedAtMicros;
                found = true;
            }

            ackElicitingPacketCount++;
            largestAckElicitingPacketNumber = packetNumber;
        }

        return found;
    }

    /// <summary>
    /// Builds an ACK frame for the specified packet number space.
    /// </summary>
    internal bool TryBuildAckFrame(QuicPacketNumberSpace packetNumberSpace, ulong nowMicros, out QuicAckFrame frame)
    {
        frame = null!;

        if (!TryGetSpaceState(packetNumberSpace, out SpaceState? state) || state.Receipts.Count == 0)
        {
            return false;
        }

        PacketRange[]? rentedRanges = null;
        Span<PacketRange> ranges = stackalloc PacketRange[StackPacketRangeCapacity];
        if (maximumRetainedAckRanges > StackPacketRangeCapacity)
        {
            rentedRanges = ArrayPool<PacketRange>.Shared.Rent(maximumRetainedAckRanges);
            ranges = rentedRanges.AsSpan(0, maximumRetainedAckRanges);
        }

        try
        {
            int rangeCount = BuildRanges(state.Receipts, ranges);
            if (rangeCount == 0)
            {
                return false;
            }

            int firstRangeIndex = Math.Max(0, rangeCount - maximumRetainedAckRanges);
            PacketRange newestRange = ranges[rangeCount - 1];
            int additionalRangeCount = rangeCount - 1 - firstRangeIndex;
            QuicAckRange[] additionalRanges = additionalRangeCount == 0
                ? []
                : ArrayPool<QuicAckRange>.Shared.Rent(additionalRangeCount);
            QuicAckFrame? pendingFrame = null;
            bool additionalRangesTransferred = false;
            try
            {
                ulong previousSmallestAcknowledged = newestRange.Smallest;
                for (int rangeIndex = rangeCount - 2, additionalRangeIndex = 0;
                    rangeIndex >= firstRangeIndex;
                    rangeIndex--, additionalRangeIndex++)
                {
                    PacketRange range = ranges[rangeIndex];
                    ulong gap = previousSmallestAcknowledged - range.Largest - 2;
                    ulong ackRangeLength = range.Largest - range.Smallest;
                    additionalRanges[additionalRangeIndex] = new QuicAckRange(gap, ackRangeLength, range.Smallest, range.Largest);
                    previousSmallestAcknowledged = range.Smallest;
                }

                pendingFrame = QuicAckFrame.Rent();
                pendingFrame.FrameType = state.EcnCounts.HasValue ? AckEcnFrameType : AckFrameType;
                pendingFrame.LargestAcknowledged = newestRange.Largest;
                if (!state.Receipts.TryGetValue(newestRange.Largest, out QuicPacketReceipt newestReceipt))
                {
                    throw new InvalidOperationException("The newest ACK range has no matching packet receipt.");
                }

                pendingFrame.AckDelay = GetAckDelayMicros(nowMicros, newestReceipt);
                pendingFrame.FirstAckRange = newestRange.Largest - newestRange.Smallest;
                pendingFrame.EcnCounts = state.EcnCounts;
                if (additionalRangeCount > 0)
                {
                    pendingFrame.SetOwnedAdditionalRanges(additionalRanges, additionalRangeCount);
                    additionalRangesTransferred = true;
                }

                frame = pendingFrame;
                pendingFrame = null;
            }
            finally
            {
                pendingFrame?.Dispose();
                if (additionalRangeCount > 0 && !additionalRangesTransferred)
                {
                    ArrayPool<QuicAckRange>.Shared.Return(additionalRanges);
                }
            }
        }
        finally
        {
            if (rentedRanges is not null)
            {
                ArrayPool<PacketRange>.Shared.Return(rentedRanges);
            }
        }

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

        if (state.LargestAckElicitingPacketNumber is ulong largestAckElicitingPacketNumber)
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

        SentAckFrameState ackedRanges = BuildAckFrameRanges(ackFrame);
        MarkAckFrameSent(packetNumberSpace, sentAtMicros, ackOnlyPacket);

        SpaceState state = GetOrCreateSpaceState(packetNumberSpace);
        state.SentAckFrames[packetNumber] = ackedRanges;
    }

    /// <summary>
    /// Retires the ACK ranges that were carried in a previously sent ACK frame when the carrier packet is acknowledged.
    /// </summary>
    internal bool TryRetireAcknowledgedAckRanges(QuicPacketNumberSpace packetNumberSpace, ulong ackedPacketNumber)
    {
        if (!TryGetSpaceState(packetNumberSpace, out SpaceState? state)
            || !state.SentAckFrames.TryGetValue(ackedPacketNumber, out SentAckFrameState sentAckFrame))
        {
            return false;
        }

        RetireSentAckFrame(state, ackedPacketNumber, sentAckFrame);
        return true;
    }

    /// <summary>
    /// Retires ACK ranges carried by sent ACK frames whose carrier packet is acknowledged by an ACK frame.
    /// </summary>
    internal bool TryRetireAcknowledgedAckRanges(QuicPacketNumberSpace packetNumberSpace, QuicAckFrame ackFrame)
    {
        if (!TryGetSpaceState(packetNumberSpace, out SpaceState? state)
            || state.SentAckFrames.Count == 0
            || ackFrame.FirstAckRange > ackFrame.LargestAcknowledged)
        {
            return false;
        }

        if (state.SentAckFrames.Count <= StackAckFramePacketNumberCapacity)
        {
            Span<ulong> acknowledgedAckFramePacketNumbers = stackalloc ulong[StackAckFramePacketNumberCapacity];
            return TryRetireAcknowledgedAckRanges(state, ackFrame, acknowledgedAckFramePacketNumbers);
        }

        ulong[] rentedAcknowledgedPacketNumbers = ArrayPool<ulong>.Shared.Rent(state.SentAckFrames.Count);
        try
        {
            return TryRetireAcknowledgedAckRanges(
                state,
                ackFrame,
                rentedAcknowledgedPacketNumbers.AsSpan(0, state.SentAckFrames.Count));
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(rentedAcknowledgedPacketNumbers);
        }
    }

    private static bool TryRetireAcknowledgedAckRanges(SpaceState state, QuicAckFrame ackFrame, Span<ulong> acknowledgedAckFramePacketNumbers)
    {
        int acknowledgedAckFramePacketNumberCount = 0;
        foreach (KeyValuePair<ulong, SentAckFrameState> sentAckFrameEntry in state.SentAckFrames)
        {
            if (AckFrameAcknowledgesPacketNumber(ackFrame, sentAckFrameEntry.Key))
            {
                acknowledgedAckFramePacketNumbers[acknowledgedAckFramePacketNumberCount++] = sentAckFrameEntry.Key;
            }
        }

        if (acknowledgedAckFramePacketNumberCount == 0)
        {
            return false;
        }

        for (int index = 0; index < acknowledgedAckFramePacketNumberCount; index++)
        {
            ulong packetNumber = acknowledgedAckFramePacketNumbers[index];
            RetireSentAckFrame(state, packetNumber, state.SentAckFrames[packetNumber]);
        }

        return true;
    }

    /// <summary>
    /// Discards any retained ACK-generation state for the specified packet number space.
    /// </summary>
    internal bool TryDiscardPacketNumberSpace(QuicPacketNumberSpace packetNumberSpace)
    {
        if (!spaces.Remove(packetNumberSpace, out SpaceState? state))
        {
            return false;
        }

        state.Clear();
        return true;
    }

    private static bool AckFrameAcknowledgesPacketNumber(QuicAckFrame ackFrame, ulong packetNumber)
    {
        ulong firstRangeSmallestAcknowledged = ackFrame.LargestAcknowledged - ackFrame.FirstAckRange;
        if (packetNumber >= firstRangeSmallestAcknowledged && packetNumber <= ackFrame.LargestAcknowledged)
        {
            return true;
        }

        foreach (QuicAckRange range in ackFrame.AdditionalRangeSpan)
        {
            if (packetNumber >= range.SmallestAcknowledged && packetNumber <= range.LargestAcknowledged)
            {
                return true;
            }
        }

        return false;
    }

    private static void RetireSentAckFrame(SpaceState state, ulong packetNumber, SentAckFrameState sentAckFrame)
    {
        state.SentAckFrames.Remove(packetNumber);
        foreach (PacketRange range in sentAckFrame.AckedRanges.AsSpan(0, sentAckFrame.AckedRangeCount))
        {
            RemoveRange(state.Receipts, range);
        }

        RefreshLargestAckElicitingPacketNumber(state);

        ReturnAckFrameRanges(sentAckFrame.AckedRanges);

        if (state.Receipts.Count == 0)
        {
            state.ImmediateAckRequired = false;
        }
    }

    private static int BuildRanges(QuicPacketReceiptStore receipts, Span<PacketRange> ranges)
    {
        if (receipts.Count == 0)
        {
            return 0;
        }

        int rangeCount = 0;
        ulong rangeStart = receipts.GetPacketNumber(0);
        ulong rangeEnd = rangeStart;

        for (int index = 1; index < receipts.Count; index++)
        {
            ulong packetNumber = receipts.GetPacketNumber(index);
            if (rangeEnd != ulong.MaxValue && packetNumber == rangeEnd + 1)
            {
                rangeEnd = packetNumber;
                continue;
            }

            AddRange(ranges, ref rangeCount, new PacketRange(rangeStart, rangeEnd));
            rangeStart = packetNumber;
            rangeEnd = packetNumber;
        }

        AddRange(ranges, ref rangeCount, new PacketRange(rangeStart, rangeEnd));
        return rangeCount;
    }

    private static void AddRange(Span<PacketRange> ranges, ref int rangeCount, PacketRange range)
    {
        if ((uint)rangeCount >= (uint)ranges.Length)
        {
            // ACK generation only needs the newest retained ranges. When sparse
            // history exceeds the configured capacity, discard the oldest range
            // and keep tracking the newest ranges that will actually be encoded.
            ranges[1..].CopyTo(ranges);
            ranges[^1] = range;
            return;
        }

        ranges[rangeCount++] = range;
    }

    private static SentAckFrameState BuildAckFrameRanges(QuicAckFrame frame)
    {
        if (frame.FirstAckRange > frame.LargestAcknowledged)
        {
            throw new ArgumentException("The ACK frame is invalid.", nameof(frame));
        }

        int rangeCount = checked(1 + frame.AdditionalRangeCount);
        PacketRange[] ranges = ArrayPool<PacketRange>.Shared.Rent(rangeCount);
        ranges[0] = new PacketRange(frame.LargestAcknowledged - frame.FirstAckRange, frame.LargestAcknowledged);
        int rangeIndex = 1;
        foreach (QuicAckRange additionalRange in frame.AdditionalRangeSpan)
        {
            ranges[rangeIndex++] = new PacketRange(additionalRange.SmallestAcknowledged, additionalRange.LargestAcknowledged);
        }

        return new SentAckFrameState(ranges, rangeCount);
    }

    private static void ReturnAckFrameRanges(PacketRange[] ranges)
    {
        if (ranges.Length > 0)
        {
            ArrayPool<PacketRange>.Shared.Return(ranges);
        }
    }

    private void TrimOldestRangesIfNeeded(SpaceState state)
    {
        if (state.Receipts.RangeCount <= maximumRetainedAckRanges)
        {
            return;
        }

        PacketRange[]? rentedRanges = null;
        Span<PacketRange> ranges = stackalloc PacketRange[StackPacketRangeCapacity + 1];
        if (maximumRetainedAckRanges > StackPacketRangeCapacity)
        {
            rentedRanges = ArrayPool<PacketRange>.Shared.Rent(maximumRetainedAckRanges + 1);
            ranges = rentedRanges.AsSpan(0, maximumRetainedAckRanges + 1);
        }

        try
        {
            int rangeCount = BuildRanges(state.Receipts, ranges);
            if (rangeCount <= maximumRetainedAckRanges)
            {
                return;
            }

            int rangesToRemove = rangeCount - maximumRetainedAckRanges;
            for (int rangeIndex = 0; rangeIndex < rangesToRemove; rangeIndex++)
            {
                RemoveRange(state.Receipts, ranges[rangeIndex]);
            }

            RefreshLargestAckElicitingPacketNumber(state);
        }
        finally
        {
            if (rentedRanges is not null)
            {
                ArrayPool<PacketRange>.Shared.Return(rentedRanges);
            }
        }
    }

    private static void RemoveRange(QuicPacketReceiptStore receipts, PacketRange range)
    {
        receipts.RemoveRange(range.Smallest, range.Largest);
    }

    private SpaceState GetOrCreateSpaceState(QuicPacketNumberSpace packetNumberSpace)
    {
        if (!spaces.TryGetValue(packetNumberSpace, out SpaceState? state))
        {
            state = new SpaceState(InitialPacketNumberSpaceCapacity);
            spaces.Add(packetNumberSpace, state);
        }

        return state;
    }

    private bool TryGetSpaceState(QuicPacketNumberSpace packetNumberSpace, [NotNullWhen(true)] out SpaceState? state)
    {
        return spaces.TryGetValue(packetNumberSpace, out state);
    }

    private static void RefreshLargestAckElicitingPacketNumber(SpaceState state)
    {
        state.LargestAckElicitingPacketNumber = null;
        for (int index = 0; index < state.Receipts.Count; index++)
        {
            QuicPacketReceipt receipt = state.Receipts.GetReceipt(index);
            if (!receipt.AckEliciting)
            {
                continue;
            }

            state.LargestAckElicitingPacketNumber = state.Receipts.GetPacketNumber(index);
        }
    }

    private static ulong GetElapsedMicros(ulong laterMicros, ulong earlierMicros)
    {
        return laterMicros >= earlierMicros ? laterMicros - earlierMicros : 0;
    }

    private static ulong GetAckDelayMicros(ulong nowMicros, QuicPacketReceipt receipt)
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

    private readonly record struct SentAckFrameState(PacketRange[] AckedRanges, int AckedRangeCount);

    private sealed class SpaceState
    {
        internal SpaceState(int initialCapacity)
        {
            Receipts = new QuicPacketReceiptStore(initialCapacity);
            SentAckFrames = new Dictionary<ulong, SentAckFrameState>(initialCapacity);
        }

        internal QuicPacketReceiptStore Receipts { get; }
        internal Dictionary<ulong, SentAckFrameState> SentAckFrames { get; }

        internal bool ImmediateAckRequired { get; set; }

        internal ulong? LastAckFrameSentAtMicros { get; set; }

        internal ulong? LastAckFrameTriggerPacketNumber { get; set; }

        internal ulong? LargestAckElicitingPacketNumber { get; set; }

        internal QuicEcnCounts? EcnCounts { get; set; }

        internal void Clear()
        {
            foreach (SentAckFrameState sentAckFrame in SentAckFrames.Values)
            {
                ReturnAckFrameRanges(sentAckFrame.AckedRanges);
            }

            SentAckFrames.Clear();
            Receipts.ClearAndReturnStorage();
            ImmediateAckRequired = false;
            LastAckFrameSentAtMicros = null;
            LastAckFrameTriggerPacketNumber = null;
            LargestAckElicitingPacketNumber = null;
            EcnCounts = null;
        }
    }
}
