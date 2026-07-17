// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

internal sealed class Http3StreamingFrameReader : IDisposable
{
    private const int MaximumFrameHeaderLength = 16;
    private const int MaximumDataSegmentLength = 64 * 1024;

    private readonly Func<ulong, Http3Exception?>? frameTypeValidator;
    private readonly byte[] header = new byte[MaximumFrameHeaderLength];
    private int headerCount;
    private ulong frameType;
    private int framePayloadLength;
    private int remainingPayloadLength;
    private byte[]? bufferedPayload;
    private List<byte[]>? rentedDataBuffers;
    private int bufferedPayloadCapacity;
    private int bufferedPayloadCount;
    private int disposed;
    private bool readingPayload;

    public Http3StreamingFrameReader(Func<ulong, Http3Exception?>? frameTypeValidator = null)
    {
        this.frameTypeValidator = frameTypeValidator;
    }

    public int PendingByteCount => headerCount + bufferedPayloadCount;

    public void Read(ReadOnlyMemory<byte> source, Queue<Http3StreamingFramePart> output)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(output);

        while (!source.IsEmpty)
        {
            if (!readingPayload)
            {
                ReadHeader(ref source, output);
                continue;
            }

            if (frameType == (ulong)Http3FrameType.Data)
            {
                if (bufferedPayload is null)
                {
                    bufferedPayloadCapacity = Math.Min(remainingPayloadLength, MaximumDataSegmentLength);
                    bufferedPayload = QuicBufferPool.RentBytes(bufferedPayloadCapacity);
                    (rentedDataBuffers ??= new List<byte[]>(16)).Add(bufferedPayload);
                }

                int dataCount = Math.Min(source.Length, bufferedPayloadCapacity - bufferedPayloadCount);
                source.Span[..dataCount].CopyTo(bufferedPayload.AsSpan(bufferedPayloadCount));
                source = source[dataCount..];
                bufferedPayloadCount += dataCount;
                remainingPayloadLength -= dataCount;
                if (bufferedPayloadCount == bufferedPayloadCapacity || remainingPayloadLength == 0)
                {
                    bool endsFrame = remainingPayloadLength == 0;
                    output.Enqueue(Http3StreamingFramePart.FromData(
                        bufferedPayload.AsMemory(0, bufferedPayloadCount),
                        endsFrame,
                        framePayloadLength));
                    bufferedPayload = null;
                    bufferedPayloadCapacity = 0;
                    bufferedPayloadCount = 0;
                    if (endsFrame)
                    {
                        ResetFrame();
                    }
                }

                continue;
            }

            int payloadCount = Math.Min(remainingPayloadLength, source.Length);
            source.Span[..payloadCount].CopyTo(bufferedPayload!.AsSpan(bufferedPayloadCount));
            source = source[payloadCount..];
            bufferedPayloadCount += payloadCount;
            remainingPayloadLength -= payloadCount;
            if (remainingPayloadLength == 0)
            {
                output.Enqueue(Http3StreamingFramePart.FromFrame(Http3FrameReader.ParseFrame(frameType, bufferedPayload!)));
                ResetFrame();
            }
        }
    }

    public void Complete()
    {
        if (headerCount != 0 || readingPayload)
        {
            throw new Http3Exception(Http3ErrorCode.FrameError, "The HTTP/3 stream ended with a truncated frame.");
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        if (rentedDataBuffers is null)
        {
            return;
        }

        foreach (byte[] buffer in rentedDataBuffers)
        {
            QuicBufferPool.ReturnBytes(buffer);
        }

        rentedDataBuffers.Clear();
    }

    private void ReadHeader(ref ReadOnlyMemory<byte> source, Queue<Http3StreamingFramePart> output)
    {
        header[headerCount++] = source.Span[0];
        source = source[1..];

        int index = 0;
        if (!Http3VariableLengthInteger.TryParse(header.AsSpan(0, headerCount), out ulong parsedFrameType, out int typeBytes))
        {
            EnsureHeaderCanGrow();
            return;
        }

        index += typeBytes;
        if (!Http3VariableLengthInteger.TryParse(header.AsSpan(index, headerCount - index), out ulong payloadLength, out int lengthBytes))
        {
            EnsureHeaderCanGrow();
            return;
        }

        index += lengthBytes;
        if (index != headerCount)
        {
            throw new Http3Exception(Http3ErrorCode.FrameError, "The HTTP/3 frame header length is invalid.");
        }

        if (payloadLength > int.MaxValue)
        {
            throw new Http3Exception(Http3ErrorCode.ExcessiveLoad, "The HTTP/3 frame payload is too large for this parser.");
        }

        if (frameTypeValidator?.Invoke(parsedFrameType) is { } exception)
        {
            throw exception;
        }

        frameType = parsedFrameType;
        framePayloadLength = checked((int)payloadLength);
        remainingPayloadLength = framePayloadLength;
        readingPayload = true;
        headerCount = 0;

        if (framePayloadLength == 0)
        {
            if (frameType == (ulong)Http3FrameType.Data)
            {
                output.Enqueue(Http3StreamingFramePart.FromData(ReadOnlyMemory<byte>.Empty, endsFrame: true, framePayloadLength));
            }
            else
            {
                output.Enqueue(Http3StreamingFramePart.FromFrame(Http3FrameReader.ParseFrame(frameType, [])));
            }

            ResetFrame();
            return;
        }

        if (frameType != (ulong)Http3FrameType.Data)
        {
            bufferedPayload = new byte[framePayloadLength];
        }
    }

    private void EnsureHeaderCanGrow()
    {
        if (headerCount == header.Length)
        {
            throw new Http3Exception(Http3ErrorCode.FrameError, "The HTTP/3 frame header is truncated or invalid.");
        }
    }

    private void ResetFrame()
    {
        frameType = 0;
        framePayloadLength = 0;
        remainingPayloadLength = 0;
        bufferedPayload = null;
        bufferedPayloadCapacity = 0;
        bufferedPayloadCount = 0;
        readingPayload = false;
    }
}

internal readonly record struct Http3StreamingFramePart(
    Http3Frame? Frame,
    ReadOnlyMemory<byte> Data,
    bool IsData,
    bool EndsFrame,
    int FramePayloadLength)
{
    public static Http3StreamingFramePart FromFrame(Http3Frame frame)
    {
        return new Http3StreamingFramePart(frame, default, IsData: false, EndsFrame: true, checked((int)frame.Length));
    }

    public static Http3StreamingFramePart FromData(ReadOnlyMemory<byte> data, bool endsFrame, int framePayloadLength)
    {
        return new Http3StreamingFramePart(null, data, IsData: true, endsFrame, framePayloadLength);
    }
}
