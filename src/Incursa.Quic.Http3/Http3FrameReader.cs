// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Incrementally parses HTTP/3 frames from stream bytes.
/// </summary>
public sealed class Http3FrameReader
{
    private const int CapacityGrowthFactor = 2;
    private const int MaxRetainedPendingCapacity = 64 * 1024;

    private readonly Func<ulong, Http3Exception?>? frameTypeValidator;
    private byte[] pending = [];
    private int pendingCount;

    /// <summary>
    /// Initializes a new instance of the <see cref="Http3FrameReader" /> class.
    /// </summary>
    public Http3FrameReader(Func<ulong, Http3Exception?>? frameTypeValidator = null)
    {
        this.frameTypeValidator = frameTypeValidator;
    }

    /// <summary>
    /// Gets the number of buffered bytes that have not yet formed a complete frame.
    /// </summary>
    public int PendingByteCount => pendingCount;

    /// <summary>
    /// Parses all complete frames available in <paramref name="source" />.
    /// </summary>
    public Http3Frame[] Read(ReadOnlySpan<byte> source, bool endOfStream = false)
    {
        bool hadPending = pendingCount != 0;
        ReadOnlySpan<byte> readable;
        if (hadPending)
        {
            AppendPending(source);
            readable = pending.AsSpan(0, pendingCount);
        }
        else
        {
            readable = source;
        }

        int index = 0;
        Http3Frame? firstFrame = null;
        List<Http3Frame>? additionalFrames = null;

        while (index < readable.Length)
        {
            int frameStart = index;
            if (!TryReadVariableLengthInteger(readable, ref index, out ulong frameType))
            {
                index = frameStart;
                break;
            }

            if (!TryReadVariableLengthInteger(readable, ref index, out ulong payloadLength))
            {
                index = frameStart;
                break;
            }

            if (payloadLength > int.MaxValue)
            {
                throw new Http3Exception(Http3ErrorCode.ExcessiveLoad, "The HTTP/3 frame payload is too large for this parser.");
            }

            if (readable.Length - index < (int)payloadLength)
            {
                index = frameStart;
                break;
            }

            if (frameTypeValidator?.Invoke(frameType) is { } exception)
            {
                throw exception;
            }

            byte[] payload = readable.Slice(index, (int)payloadLength).ToArray();
            index += (int)payloadLength;
            Http3Frame frame = ParseFrame(frameType, payload);
            if (firstFrame is null)
            {
                firstFrame = frame;
            }
            else
            {
                (additionalFrames ??= []).Add(frame);
            }
        }

        if (index == readable.Length)
        {
            ClearPending();
        }
        else if (hadPending)
        {
            int remaining = readable.Length - index;
            readable[index..].CopyTo(pending);
            pendingCount = remaining;
        }
        else
        {
            StorePending(readable[index..]);
        }

        if (endOfStream && pendingCount != 0)
        {
            throw new Http3Exception(Http3ErrorCode.FrameError, "The HTTP/3 stream ended with a truncated frame.");
        }

        if (firstFrame is null)
        {
            return [];
        }

        if (additionalFrames is null)
        {
            return [firstFrame];
        }

        Http3Frame[] frames = new Http3Frame[additionalFrames.Count + 1];
        frames[0] = firstFrame;
        additionalFrames.CopyTo(frames, 1);
        return frames;
    }

    /// <summary>
    /// Signals stream completion and fails if a partial frame remains buffered.
    /// </summary>
    public Http3Frame[] Complete()
    {
        return Read([], endOfStream: true);
    }

    internal static Http3Frame ParseFrame(ulong frameType, byte[] payload)
    {
        return frameType switch
        {
            (ulong)Http3FrameType.Data => new Http3DataFrame(payload),
            (ulong)Http3FrameType.Headers => new Http3HeadersFrame(payload),
            (ulong)Http3FrameType.CancelPush => ParseCancelPush(payload),
            (ulong)Http3FrameType.Settings => ParseSettings(payload),
            (ulong)Http3FrameType.PushPromise => ParsePushPromise(payload),
            (ulong)Http3FrameType.GoAway => ParseGoAway(payload),
            (ulong)Http3FrameType.MaxPushId => ParseMaxPushId(payload),
            _ => new Http3UnknownFrame(frameType, payload),
        };
    }

    private static Http3CancelPushFrame ParseCancelPush(byte[] payload)
    {
        ulong value = ParseSingleVariableLengthIntegerPayload(payload);
        return new Http3CancelPushFrame(value, payload);
    }

    private static Http3GoAwayFrame ParseGoAway(byte[] payload)
    {
        ulong value = ParseSingleVariableLengthIntegerPayload(payload);
        return new Http3GoAwayFrame(value, payload);
    }

    private static Http3MaxPushIdFrame ParseMaxPushId(byte[] payload)
    {
        ulong value = ParseSingleVariableLengthIntegerPayload(payload);
        return new Http3MaxPushIdFrame(value, payload);
    }

    private static Http3PushPromiseFrame ParsePushPromise(byte[] payload)
    {
        int index = 0;
        if (!TryReadVariableLengthInteger(payload, ref index, out ulong pushId))
        {
            throw new Http3Exception(Http3ErrorCode.FrameError, "The HTTP/3 PUSH_PROMISE frame payload is truncated.");
        }

        byte[] encodedFieldSection = payload.AsSpan(index).ToArray();
        return new Http3PushPromiseFrame(pushId, encodedFieldSection, payload);
    }

    private static Http3SettingsFrame ParseSettings(byte[] payload)
    {
        int index = 0;
        List<Http3Setting> settings = [];
        while (index < payload.Length)
        {
            if (!TryReadVariableLengthInteger(payload, ref index, out ulong identifier)
                || !TryReadVariableLengthInteger(payload, ref index, out ulong value))
            {
                throw new Http3Exception(Http3ErrorCode.FrameError, "The HTTP/3 SETTINGS frame payload is truncated.");
            }

            settings.Add(new Http3Setting(identifier, value));
        }

        return new Http3SettingsFrame(settings, payload, Http3SettingsParser.Parse(settings));
    }

    private static ulong ParseSingleVariableLengthIntegerPayload(byte[] payload)
    {
        int index = 0;
        if (!TryReadVariableLengthInteger(payload, ref index, out ulong value) || index != payload.Length)
        {
            throw new Http3Exception(Http3ErrorCode.FrameError, "The HTTP/3 frame payload length is invalid.");
        }

        return value;
    }

    private static bool TryReadVariableLengthInteger(ReadOnlySpan<byte> source, ref int index, out ulong value)
    {
        value = default;
        if (index >= source.Length)
        {
            return false;
        }

        if (Http3VariableLengthInteger.TryParse(source[index..], out value, out int bytesConsumed))
        {
            index += bytesConsumed;
            return true;
        }

        return false;
    }

    private void AppendPending(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return;
        }

        int requiredCapacity = checked(pendingCount + source.Length);
        EnsurePendingCapacity(requiredCapacity);
        source.CopyTo(pending.AsSpan(pendingCount));
        pendingCount = requiredCapacity;
    }

    private void StorePending(ReadOnlySpan<byte> source)
    {
        EnsurePendingCapacity(source.Length);
        source.CopyTo(pending);
        pendingCount = source.Length;
    }

    private void EnsurePendingCapacity(int requiredCapacity)
    {
        if (pending.Length >= requiredCapacity)
        {
            return;
        }

        int doubledCapacity = requiredCapacity;
        if (pending.Length != 0)
        {
            doubledCapacity = pending.Length <= int.MaxValue / CapacityGrowthFactor
                ? pending.Length * CapacityGrowthFactor
                : int.MaxValue;
        }

        Array.Resize(ref pending, Math.Max(requiredCapacity, doubledCapacity));
    }

    private void ClearPending()
    {
        pendingCount = 0;
        if (pending.Length > MaxRetainedPendingCapacity)
        {
            pending = [];
        }
    }
}
