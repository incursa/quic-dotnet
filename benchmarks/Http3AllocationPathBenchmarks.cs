using System.Buffers;
using BenchmarkDotNet.Attributes;
using Incursa.Qpack;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks allocation-heavy HTTP/3 request and response shapes identified by the P2 traces.
/// </summary>
[MemoryDiagnoser]
public class Http3AllocationPathBenchmarks
{
    private static readonly byte[] PlaintextBody = "Hello, World!"u8.ToArray();
    private static readonly byte[] JsonBody = """{"message":"Hello, World!"}"""u8.ToArray();

    private QPackFieldLine[] plaintextRequestHeaders = [];
    private QPackFieldLine[] jsonRequestHeaders = [];
    private QPackFieldLine[] plaintextResponseHeaders = [];
    private QPackFieldLine[] jsonResponseHeaders = [];
    private byte[] plaintextHeadersFrame = [];
    private byte[] jsonHeadersFrame = [];
    private byte[] plaintextDataFrame = [];
    private byte[] jsonDataFrame = [];
    private byte[] plaintextRequestHeadersFrame = [];
    private byte[] jsonRequestHeadersFrame = [];
    private byte[] plaintextResponseFrames = [];
    private byte[] jsonResponseFrames = [];

    /// <summary>
    /// Prepares realistic tiny HTTP/3 endpoint request and response frame shapes.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        plaintextRequestHeaders =
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost:5444"),
            new QPackFieldLine(":path", "/plaintext"),
            new QPackFieldLine("user-agent", "h2load"),
            new QPackFieldLine("accept", "*/*"),
        ];
        jsonRequestHeaders =
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost:5444"),
            new QPackFieldLine(":path", "/json"),
            new QPackFieldLine("user-agent", "h2load"),
            new QPackFieldLine("accept", "*/*"),
        ];
        plaintextResponseHeaders = BuildResponseHeaders("text/plain", PlaintextBody.Length);
        jsonResponseHeaders = BuildResponseHeaders("application/json", JsonBody.Length);

        plaintextHeadersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(plaintextResponseHeaders));
        jsonHeadersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(jsonResponseHeaders));
        plaintextDataFrame = Http3FrameWriter.WriteData(PlaintextBody);
        jsonDataFrame = Http3FrameWriter.WriteData(JsonBody);
        plaintextRequestHeadersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(plaintextRequestHeaders));
        jsonRequestHeadersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(jsonRequestHeaders));
        plaintextResponseFrames = BufferResponseFrames(plaintextHeadersFrame, PlaintextBody);
        jsonResponseFrames = BufferResponseFrames(jsonHeadersFrame, JsonBody);
    }

    /// <summary>
    /// Measures request HEADERS frame parsing for a tiny plaintext GET request.
    /// </summary>
    [Benchmark]
    public int FrameReader_ReadPlaintextHeaders()
    {
        Http3FrameReader reader = new();
        Http3Frame[] frames = reader.Read(plaintextRequestHeadersFrame);
        return CountFramePayloadBytes(frames) ^ reader.PendingByteCount;
    }

    /// <summary>
    /// Measures request HEADERS frame parsing for a tiny JSON GET request.
    /// </summary>
    [Benchmark]
    public int FrameReader_ReadJsonHeaders()
    {
        Http3FrameReader reader = new();
        Http3Frame[] frames = reader.Read(jsonRequestHeadersFrame);
        return CountFramePayloadBytes(frames) ^ reader.PendingByteCount;
    }

    /// <summary>
    /// Measures the append and pending-slice path for a fragmented request HEADERS frame.
    /// </summary>
    [Benchmark]
    public int FrameReader_ReadFragmentedPlaintextHeaders()
    {
        Http3FrameReader reader = new();
        int split = plaintextRequestHeadersFrame.Length / 2;
        Http3Frame[] first = reader.Read(plaintextRequestHeadersFrame.AsSpan(0, split));
        Http3Frame[] second = reader.Read(plaintextRequestHeadersFrame.AsSpan(split));
        return CountFramePayloadBytes(first) ^ CountFramePayloadBytes(second) ^ reader.PendingByteCount;
    }

    /// <summary>
    /// Measures public static QPACK field-section encoding for a tiny plaintext response.
    /// </summary>
    [Benchmark]
    public int ResponseHeaders_EncodePlaintextFieldSection()
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(plaintextResponseHeaders);
        return encoded.Length;
    }

    /// <summary>
    /// Measures public static QPACK field-section encoding for a tiny JSON response.
    /// </summary>
    [Benchmark]
    public int ResponseHeaders_EncodeJsonFieldSection()
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(jsonResponseHeaders);
        return encoded.Length;
    }

    /// <summary>
    /// Measures response HEADERS and DATA frame buffering for the plaintext response shape.
    /// </summary>
    [Benchmark]
    public int ResponseFrames_BufferPlaintext()
    {
        byte[] frames = BufferResponseFrames(plaintextHeadersFrame, PlaintextBody);
        return frames.Length;
    }

    /// <summary>
    /// Measures response HEADERS and DATA frame buffering for the JSON response shape.
    /// </summary>
    [Benchmark]
    public int ResponseFrames_BufferJson()
    {
        byte[] frames = BufferResponseFrames(jsonHeadersFrame, JsonBody);
        return frames.Length;
    }

    /// <summary>
    /// Measures the combined response field-section, HEADERS frame, DATA frame, and final buffer shape.
    /// </summary>
    [Benchmark]
    public int ResponseFrames_EncodeAndBufferPlaintext()
    {
        byte[] encodedFieldSection = QPackEncoder.EncodeFieldSection(plaintextResponseHeaders);
        byte[] frames = BufferEncodedResponseFrames(encodedFieldSection, PlaintextBody);
        return frames.Length;
    }

    /// <summary>
    /// Measures the STREAM payload builder shape for a tiny plaintext HTTP/3 response payload.
    /// </summary>
    [Benchmark]
    public int QuicStreamPayload_BuildPlaintextResponsePayload()
    {
        byte[] payload = BuildOutboundStreamPayload(0, 0, plaintextResponseFrames, fin: true);
        return payload.Length;
    }

    /// <summary>
    /// Measures the STREAM payload builder shape for a tiny JSON HTTP/3 response payload.
    /// </summary>
    [Benchmark]
    public int QuicStreamPayload_BuildJsonResponsePayload()
    {
        byte[] payload = BuildOutboundStreamPayload(0, 0, jsonResponseFrames, fin: true);
        return payload.Length;
    }

    /// <summary>
    /// Measures the queued-send selection and payload-combine shape used by pending application-send flushes.
    /// </summary>
    [Benchmark]
    public int QuicStreamPayload_CombineTwoQueuedPayloads()
    {
        byte[] first = BuildOutboundStreamPayload(0, 0, plaintextDataFrame, fin: false);
        byte[] second = BuildOutboundStreamPayload(4, 0, jsonDataFrame, fin: true);
        QuicApplicationSendQueue queue = new();
        queue.Enqueue(0, 0, first);
        queue.Enqueue(4, 0, second);

        PendingApplicationSendRequest[] queuedWrites = queue.GetSortedQueuedWrites();
        int batchCount = QuicApplicationSendQueue.SelectQueuedApplicationSendBatchCount(queuedWrites, 4096);
        ReadOnlySpan<PendingApplicationSendRequest> selectedWrites = queuedWrites.AsSpan(0, batchCount);
        byte[] combined = CombinePayloads(selectedWrites);
        ulong[] streamIds = QuicApplicationSendQueue.BuildDistinctStreamIds(selectedWrites);
        return combined.Length ^ streamIds.Length;
    }

    private static QPackFieldLine[] BuildResponseHeaders(string contentType, int contentLength)
    {
        return
        [
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("server", "incursa"),
            new QPackFieldLine("date", "Wed, 27 May 2026 15:00:00 GMT"),
            new QPackFieldLine("content-type", contentType),
            new QPackFieldLine("content-length", contentLength.ToString()),
        ];
    }

    private static byte[] BufferResponseFrames(byte[] headersFrame, ReadOnlySpan<byte> body)
    {
        ArrayBufferWriter<byte> writer = new(headersFrame.Length + GetFrameLength((ulong)Http3FrameType.Data, body.Length));
        writer.Write(headersFrame);
        Http3FrameWriter.WriteFrame(writer, (ulong)Http3FrameType.Data, body);
        return writer.WrittenSpan.ToArray();
    }

    private static byte[] BufferEncodedResponseFrames(byte[] encodedFieldSection, ReadOnlySpan<byte> body)
    {
        ArrayBufferWriter<byte> writer = new(
            GetFrameLength((ulong)Http3FrameType.Headers, encodedFieldSection.Length)
            + GetFrameLength((ulong)Http3FrameType.Data, body.Length));
        Http3FrameWriter.WriteFrame(writer, (ulong)Http3FrameType.Headers, encodedFieldSection);
        Http3FrameWriter.WriteFrame(writer, (ulong)Http3FrameType.Data, body);
        return writer.WrittenSpan.ToArray();
    }

    private static int GetFrameLength(ulong frameType, int payloadLength)
    {
        return checked(GetVariableLengthIntegerLength(frameType) + GetVariableLengthIntegerLength((ulong)payloadLength) + payloadLength);
    }

    private static int GetVariableLengthIntegerLength(ulong value)
    {
        if (value <= 0x3FUL)
        {
            return 1;
        }

        if (value <= 0x3FFFUL)
        {
            return 2;
        }

        if (value <= 0x3FFF_FFFFUL)
        {
            return 4;
        }

        return 8;
    }

    private static byte[] BuildOutboundStreamPayload(
        ulong streamId,
        ulong offset,
        ReadOnlySpan<byte> streamData,
        bool fin)
    {
        byte frameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        int minimumProtectedPayloadLength =
            QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;
        byte[] buffer = new byte[Math.Max(minimumProtectedPayloadLength, streamData.Length + 32)];
        if (!QuicFrameCodec.TryFormatStreamFrame(
            frameType,
            streamId,
            offset,
            streamData,
            buffer,
            out int frameBytesWritten))
        {
            throw new InvalidOperationException("The benchmark stream payload could not be formatted.");
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        return buffer;
    }

    private static byte[] CombinePayloads(ReadOnlySpan<PendingApplicationSendRequest> selectedWrites)
    {
        int combinedPayloadLength = 0;
        foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
        {
            combinedPayloadLength = checked(combinedPayloadLength + queuedWrite.StreamPayload.Length);
        }

        byte[] combinedPayload = new byte[combinedPayloadLength];
        int copyOffset = 0;
        foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
        {
            queuedWrite.StreamPayload.CopyTo(combinedPayload.AsSpan(copyOffset));
            copyOffset += queuedWrite.StreamPayload.Length;
        }

        return combinedPayload;
    }

    private static int CountFramePayloadBytes(ReadOnlySpan<Http3Frame> frames)
    {
        int total = 0;
        foreach (Http3Frame frame in frames)
        {
            total += frame switch
            {
                Http3DataFrame dataFrame => dataFrame.Data.Length,
                Http3HeadersFrame headersFrame => headersFrame.EncodedFieldSection.Length,
                Http3UnknownFrame unknownFrame => unknownFrame.Payload.Length,
                _ => 1,
            };
        }

        return total;
    }
}
