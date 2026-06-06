// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Diagnostics;

namespace Incursa.Quic;

internal sealed class QuicConnectionApplicationAckState
{
    private const ulong MicrosecondsPerSecond = 1_000_000UL;
    private long? pendingApplicationAckDelayDueTicks;

    internal long? GetDueTicks(QuicConnectionPhase phase)
    {
        return phase is QuicConnectionPhase.Establishing or QuicConnectionPhase.Active
            ? pendingApplicationAckDelayDueTicks
            : null;
    }

    internal bool TryUpdateDueTicks(
        QuicConnectionPhase phase,
        bool canSendApplicationAckPackets,
        QuicSenderFlowController flowController,
        ulong localMaxAckDelayMicros,
        ulong nowMicros,
        long nowTicks)
    {
        long? nextDueTicks = ComputeApplicationAckDelayDueTicks(
            phase,
            canSendApplicationAckPackets,
            flowController,
            localMaxAckDelayMicros,
            nowMicros,
            nowTicks);
        if (pendingApplicationAckDelayDueTicks == nextDueTicks)
        {
            return false;
        }

        pendingApplicationAckDelayDueTicks = nextDueTicks;
        return true;
    }

    internal void ClearDueTicks()
    {
        pendingApplicationAckDelayDueTicks = null;
    }

    internal void MarkAckFrameSent(
        QuicSenderFlowController flowController,
        QuicAckFrame ackFrame,
        ulong? packetNumber,
        ulong sentAtMicros,
        bool ackOnlyPacket)
    {
        if (packetNumber.HasValue)
        {
            flowController.MarkAckFrameSent(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber.Value,
                ackFrame,
                sentAtMicros,
                ackOnlyPacket);
        }
        else
        {
            flowController.MarkAckFrameSent(
                QuicPacketNumberSpace.ApplicationData,
                sentAtMicros,
                ackOnlyPacket);
        }

        pendingApplicationAckDelayDueTicks = null;
    }

    private long? ComputeApplicationAckDelayDueTicks(
        QuicConnectionPhase phase,
        bool canSendApplicationAckPackets,
        QuicSenderFlowController flowController,
        ulong localMaxAckDelayMicros,
        ulong nowMicros,
        long nowTicks)
    {
        if (phase is not QuicConnectionPhase.Establishing and not QuicConnectionPhase.Active
            || !canSendApplicationAckPackets)
        {
            return null;
        }

        if (flowController.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                localMaxAckDelayMicros)
            || !flowController.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                localMaxAckDelayMicros))
        {
            return null;
        }

        return pendingApplicationAckDelayDueTicks
            ?? SaturatingAdd(nowTicks, ConvertMicrosToTicks(localMaxAckDelayMicros));
    }

    private static long ConvertMicrosToTicks(ulong micros)
    {
        if (micros == 0)
        {
            return 0;
        }

        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;

        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + (MicrosecondsPerSecond - 1);

        ulong ticks = roundedUp / MicrosecondsPerSecond;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
    }

    private static long SaturatingAdd(long left, long right)
    {
        if (right <= 0)
        {
            return left;
        }

        if (left > long.MaxValue - right)
        {
            return long.MaxValue;
        }

        return left + right;
    }
}

internal static class QuicConnectionAckHelpers
{
    // CONTEXT: ACK payload assembly keeps a stack fast path
    // SEE: code:src/Incursa.Quic/QuicConnectionAckHelpers.cs#TryBuildLongHeaderAckPiggybackFramePayload
    // SEE: code:src/Incursa.Quic/QuicConnectionAckHelpers.cs#TryBuildOutboundAckPayloadLease
    // The 512-byte scratch buffer covers the common ACK payload sizes so the
    // piggyback path can format without first renting from the pool. Keep the
    // stack allocation unless the hot path is re-benchmarked.
    private const int MinimumAckPayloadBufferLength = 512;

    internal static bool TryBuildApplicationAckPiggybackPayload(
        ReadOnlyMemory<byte> payload,
        QuicSenderFlowController flowController,
        ulong nowMicros,
        out byte[] piggybackedPayload,
        out int piggybackedPayloadLength,
        out QuicAckFrame ackFrame)
    {
        piggybackedPayload = [];
        piggybackedPayloadLength = 0;
        ackFrame = null!;

        if (!TryBuildApplicationAckPiggybackFrame(
            payload,
            flowController,
            nowMicros,
            out int ackPayloadLength,
            out ackFrame))
        {
            return false;
        }

        int computedPiggybackedPayloadLength = checked(ackPayloadLength + payload.Length);
        QuicBufferLease piggybackedPayloadLease = QuicBufferPool.RentLease(computedPiggybackedPayloadLength);
        try
        {
            Span<byte> buffer = piggybackedPayloadLease.Span;
            if (!TryFormatOutboundAckFramePayload(ackFrame, buffer.Slice(0, ackPayloadLength), out int formattedAckPayloadLength)
                || formattedAckPayloadLength != ackPayloadLength)
            {
                return false;
            }

            payload.Span.CopyTo(buffer.Slice(ackPayloadLength));
            piggybackedPayloadLease.SetLength(computedPiggybackedPayloadLength);
            piggybackedPayload = piggybackedPayloadLease.TransferOwnership(out piggybackedPayloadLength);
            return true;
        }
        finally
        {
            piggybackedPayloadLease.Dispose();
        }
    }

    internal static bool TryBuildApplicationAckPiggybackFrame(
        ReadOnlyMemory<byte> payload,
        QuicSenderFlowController flowController,
        ulong nowMicros,
        out int ackPayloadLength,
        out QuicAckFrame ackFrame)
    {
        ackPayloadLength = 0;
        ackFrame = null!;

        if (payload.IsEmpty
            || !flowController.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                maxAckDelayMicros: 0)
            || !flowController.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                out ackFrame)
            || !QuicFrameCodec.TryGetAckFramePayloadLength(ackFrame, out ackPayloadLength))
        {
            return false;
        }

        return true;
    }

    internal static bool TryBuildLongHeaderAckPiggybackFramePayload(
        QuicPacketNumberSpace packetNumberSpace,
        QuicSenderFlowController flowController,
        ulong nowMicros,
        out QuicBufferLease ackFramePayload,
        out int ackFramePayloadLength,
        out QuicAckFrame ackFrame)
    {
        ackFramePayload = default;
        ackFramePayloadLength = 0;
        ackFrame = null!;

        if (!flowController.ShouldIncludeAckFrameWithOutgoingPacket(
                packetNumberSpace,
                nowMicros,
                maxAckDelayMicros: 0)
            || !flowController.TryBuildAckFrame(
                packetNumberSpace,
                nowMicros,
                out ackFrame))
        {
            return false;
        }

        Span<byte> framePayloadBuffer = stackalloc byte[MinimumAckPayloadBufferLength];
        if (!TryFormatOutboundAckFramePayload(ackFrame, framePayloadBuffer, out int frameBytesWritten))
        {
            return false;
        }

        ackFramePayload = QuicBufferPool.RentLease(frameBytesWritten);
        try
        {
            framePayloadBuffer.Slice(0, frameBytesWritten).CopyTo(ackFramePayload.Span);
            ackFramePayload.SetLength(frameBytesWritten);
        }
        catch
        {
            ackFramePayload.Dispose();
            ackFramePayload = default;
            return false;
        }

        ackFramePayloadLength = frameBytesWritten;
        return true;
    }

    internal static bool TryBuildOutboundAckPayload(
        QuicAckFrame ackFrame,
        int minimumPayloadLength,
        out byte[] payload)
    {
        payload = [];

        Span<byte> ackFramePayload = stackalloc byte[MinimumAckPayloadBufferLength];
        if (!TryFormatOutboundAckFramePayload(ackFrame, ackFramePayload, out int frameBytesWritten))
        {
            return false;
        }

        byte[] buffer = new byte[Math.Max(minimumPayloadLength, frameBytesWritten)];
        ackFramePayload.Slice(0, frameBytesWritten).CopyTo(buffer.AsSpan());
        payload = buffer;
        return true;
    }

    internal static bool TryBuildOutboundAckPayloadLease(
        QuicAckFrame ackFrame,
        int minimumPayloadLength,
        out QuicBufferLease payload)
    {
        payload = default;

        int payloadBufferLength = Math.Max(minimumPayloadLength, MinimumAckPayloadBufferLength);
        payload = QuicBufferPool.RentLease(payloadBufferLength);
        try
        {
            Span<byte> buffer = payload.Span;
            if (!TryFormatOutboundAckFramePayload(ackFrame, buffer, out int frameBytesWritten))
            {
                payload.Dispose();
                payload = default;
                return false;
            }

            int payloadLength = Math.Max(minimumPayloadLength, frameBytesWritten);
            if (payloadLength > frameBytesWritten)
            {
                buffer.Slice(frameBytesWritten, payloadLength - frameBytesWritten).Fill(0);
            }

            payload.SetLength(payloadLength);
            return true;
        }
        catch
        {
            payload.Dispose();
            payload = default;
            return false;
        }
    }

    internal static IEnumerable<ulong> EnumerateAcknowledgedPacketNumbers(QuicAckFrame ackFrame)
    {
        if (ackFrame.LargestAcknowledged < ackFrame.FirstAckRange)
        {
            yield break;
        }

        ulong largestAcknowledged = ackFrame.LargestAcknowledged;
        ulong smallestAcknowledged = largestAcknowledged - ackFrame.FirstAckRange;
        for (ulong packetNumber = smallestAcknowledged; ; packetNumber++)
        {
            yield return packetNumber;
            if (packetNumber == largestAcknowledged)
            {
                break;
            }
        }

        for (int rangeIndex = 0; rangeIndex < ackFrame.AdditionalRangeCount; rangeIndex++)
        {
            QuicAckRange range = ackFrame.GetAdditionalRange(rangeIndex);
            for (ulong packetNumber = range.SmallestAcknowledged; ; packetNumber++)
            {
                yield return packetNumber;
                if (packetNumber == range.LargestAcknowledged)
                {
                    break;
                }
            }
        }
    }

    internal static bool TryFormatOutboundAckFramePayload(
        QuicAckFrame ackFrame,
        Span<byte> destination,
        out int frameBytesWritten)
    {
        return QuicFrameCodec.TryFormatAckFrame(ackFrame, destination, out frameBytesWritten)
            && frameBytesWritten > 0
            && frameBytesWritten <= destination.Length;
    }
}
