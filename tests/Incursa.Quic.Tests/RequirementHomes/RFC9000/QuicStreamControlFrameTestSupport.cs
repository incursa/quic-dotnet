namespace Incursa.Quic.Tests;

internal static class QuicStreamControlFrameTestSupport
{
    internal static bool TryFindResetStreamFrame(
        ReadOnlySpan<byte> payload,
        out QuicResetStreamFrame frame,
        out int frameOffset,
        out int bytesConsumed)
    {
        frame = default;
        frameOffset = default;
        bytesConsumed = default;

        return TryFindControlFrame(
            payload,
            (ReadOnlySpan<byte> candidate, out QuicResetStreamFrame parsed, out int consumed) =>
                QuicFrameCodec.TryParseResetStreamFrame(candidate, out parsed, out consumed),
            out frame,
            out frameOffset,
            out bytesConsumed);
    }

    internal static bool TryFindStopSendingFrame(
        ReadOnlySpan<byte> payload,
        out QuicStopSendingFrame frame,
        out int frameOffset,
        out int bytesConsumed)
    {
        frame = default;
        frameOffset = default;
        bytesConsumed = default;

        return TryFindControlFrame(
            payload,
            (ReadOnlySpan<byte> candidate, out QuicStopSendingFrame parsed, out int consumed) =>
                QuicFrameCodec.TryParseStopSendingFrame(candidate, out parsed, out consumed),
            out frame,
            out frameOffset,
            out bytesConsumed);
    }

    private delegate bool TryParseControlFrame<TFrame>(
        ReadOnlySpan<byte> payload,
        out TFrame frame,
        out int bytesConsumed);

    private static bool TryFindControlFrame<TFrame>(
        ReadOnlySpan<byte> payload,
        TryParseControlFrame<TFrame> tryParseFrame,
        out TFrame frame,
        out int frameOffset,
        out int bytesConsumed)
        where TFrame : struct
    {
        frame = default;
        frameOffset = default;
        bytesConsumed = default;

        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (!tryParseFrame(remaining, out frame, out bytesConsumed))
            {
                return false;
            }

            frameOffset = offset;
            return true;
        }

        return false;
    }
}
