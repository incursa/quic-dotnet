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
    private const int MinimumAckPayloadBufferLength = 512;

    internal static bool TryBuildApplicationAckPiggybackPayload(
        ReadOnlyMemory<byte> payload,
        QuicSenderFlowController flowController,
        ulong nowMicros,
        out byte[] piggybackedPayload,
        out QuicAckFrame ackFrame)
    {
        piggybackedPayload = [];
        ackFrame = new QuicAckFrame();

        if (payload.IsEmpty
            || !flowController.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                maxAckDelayMicros: 0)
            || !flowController.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                out ackFrame)
            || !TryBuildOutboundAckFramePayload(ackFrame, out byte[] ackPayload))
        {
            return false;
        }

        piggybackedPayload = new byte[checked(ackPayload.Length + payload.Length)];
        ackPayload.CopyTo(piggybackedPayload.AsSpan());
        payload.Span.CopyTo(piggybackedPayload.AsSpan(ackPayload.Length));
        return true;
    }

    internal static bool TryBuildLongHeaderAckPiggybackFramePayload(
        QuicPacketNumberSpace packetNumberSpace,
        QuicSenderFlowController flowController,
        ulong nowMicros,
        out byte[] ackFramePayload,
        out QuicAckFrame ackFrame)
    {
        ackFramePayload = [];
        ackFrame = new QuicAckFrame();

        if (!flowController.ShouldIncludeAckFrameWithOutgoingPacket(
                packetNumberSpace,
                nowMicros,
                maxAckDelayMicros: 0)
            || !flowController.TryBuildAckFrame(
                packetNumberSpace,
                nowMicros,
                out ackFrame)
            || !TryBuildOutboundAckFramePayload(ackFrame, out ackFramePayload))
        {
            return false;
        }

        return true;
    }

    internal static bool TryBuildOutboundAckPayload(
        QuicAckFrame ackFrame,
        int minimumPayloadLength,
        out byte[] payload)
    {
        payload = [];

        if (!TryBuildOutboundAckFramePayload(ackFrame, out byte[] ackFramePayload))
        {
            return false;
        }

        byte[] buffer = new byte[Math.Max(minimumPayloadLength, ackFramePayload.Length)];
        ackFramePayload.CopyTo(buffer.AsSpan());
        payload = buffer;
        return true;
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

        foreach (QuicAckRange range in ackFrame.AdditionalRanges)
        {
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

    private static bool TryBuildOutboundAckFramePayload(QuicAckFrame ackFrame, out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[MinimumAckPayloadBufferLength];
        if (!QuicFrameCodec.TryFormatAckFrame(ackFrame, buffer, out int frameBytesWritten)
            || frameBytesWritten <= 0
            || frameBytesWritten > buffer.Length)
        {
            return false;
        }

        payload = buffer.AsSpan(0, frameBytesWritten).ToArray();
        return true;
    }
}
