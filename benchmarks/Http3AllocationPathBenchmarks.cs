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
    private byte[] plaintextRequestFieldSection = [];
    private byte[] jsonRequestFieldSection = [];
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
        plaintextRequestFieldSection = QPackEncoder.EncodeFieldSection(plaintextRequestHeaders);
        jsonRequestFieldSection = QPackEncoder.EncodeFieldSection(jsonRequestHeaders);

        plaintextHeadersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(plaintextResponseHeaders));
        jsonHeadersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(jsonResponseHeaders));
        plaintextDataFrame = Http3FrameWriter.WriteData(PlaintextBody);
        jsonDataFrame = Http3FrameWriter.WriteData(JsonBody);
        plaintextRequestHeadersFrame = Http3FrameWriter.WriteHeaders(plaintextRequestFieldSection);
        jsonRequestHeadersFrame = Http3FrameWriter.WriteHeaders(jsonRequestFieldSection);
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
    /// Measures QPACK request field-section decoding for a tiny plaintext GET request.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodePlaintextFieldSection()
    {
        QPackFieldLine[] headers = DecodeRequestHeaders(plaintextRequestFieldSection);
        return CountHeaderCharactersList(headers);
    }

    /// <summary>
    /// Measures QPACK request field-section decoding for a tiny JSON GET request.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeJsonFieldSection()
    {
        QPackFieldLine[] headers = DecodeRequestHeaders(jsonRequestFieldSection);
        return CountHeaderCharactersList(headers);
    }

    /// <summary>
    /// Measures the decode-only request header stage for a tiny plaintext GET request.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeOnly_Plaintext()
    {
        QPackFieldLine[] headers = DecodeRequestHeaders(plaintextRequestFieldSection);
        return CountHeaderCharacters(headers);
    }

    /// <summary>
    /// Measures the decode-only request header stage for a tiny JSON GET request.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeOnly_Json()
    {
        QPackFieldLine[] headers = DecodeRequestHeaders(jsonRequestFieldSection);
        return CountHeaderCharacters(headers);
    }

    /// <summary>
    /// Measures pseudo-header validation using pre-decoded plaintext request fields.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_ValidateOnly_Plaintext()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(plaintextRequestHeaders, validateContentLength: false);
        return CountHeaderCharacters(plaintextRequestHeaders) ^ (result.Method?.Length ?? 0) ^ (result.Path?.Length ?? 0);
    }

    /// <summary>
    /// Measures request message validator receive/copy behavior using pre-decoded plaintext request fields.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_ValidatorReceiveOnly_Plaintext()
    {
        Http3RequestMessageValidator validator = new();
        validator.ReceiveHeaders(plaintextRequestHeaders);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        return CountHeaderCharactersList(headers);
    }

    /// <summary>
    /// Measures request message validator receive behavior when the decoded field array is server-owned.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_OwnedValidatorReceiveOnly_Plaintext()
    {
        Http3RequestMessageValidator validator = new();
        validator.ReceiveOwnedHeaders(plaintextRequestHeaders);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        return CountHeaderCharactersList(headers);
    }

    /// <summary>
    /// Measures request object materialization using already validated plaintext request fields.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_MaterializeOnly_Plaintext()
    {
        Http3Request request = new(
            "GET",
            "https",
            "localhost:5444",
            "/plaintext",
            plaintextRequestHeaders);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length;
    }

    /// <summary>
    /// Measures validation and request object materialization using pre-decoded plaintext request fields.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_ValidateMaterializeOnly_Plaintext()
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(plaintextRequestHeaders, validateContentLength: false);
        Http3Request request = new(
            result.Method ?? string.Empty,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            plaintextRequestHeaders);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length;
    }

    /// <summary>
    /// Measures decode plus validation without validator receive/copy or request materialization.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeValidateOnly_Plaintext()
    {
        QPackFieldLine[] headers = DecodeRequestHeaders(plaintextRequestFieldSection);
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        return CountHeaderCharacters(headers) ^ (result.Method?.Length ?? 0) ^ (result.Path?.Length ?? 0);
    }

    /// <summary>
    /// Measures decode, server-owned validator receive, validation, and request object materialization for plaintext.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeValidateMaterialize_Plaintext()
    {
        QPackFieldLine[] decoded = DecodeRequestHeaders(plaintextRequestFieldSection);
        Http3RequestMessageValidator validator = new();
        validator.ReceiveOwnedHeaders(decoded);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        Http3Request request = new(
            result.Method ?? string.Empty,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length;
    }

    /// <summary>
    /// Measures decode, server-owned validator receive, validation, and request object materialization for JSON.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeValidateMaterialize_Json()
    {
        QPackFieldLine[] decoded = DecodeRequestHeaders(jsonRequestFieldSection);
        Http3RequestMessageValidator validator = new();
        validator.ReceiveOwnedHeaders(decoded);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        Http3Request request = new(
            result.Method ?? string.Empty,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length;
    }

    /// <summary>
    /// Measures request field-section decode plus HTTP/3 pseudo-header validation.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeAndValidatePlaintext()
    {
        QPackFieldLine[] headers = DecodeRequestHeaders(plaintextRequestFieldSection);
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        return CountHeaderCharacters(headers) ^ (result.Method?.Length ?? 0) ^ (result.Path?.Length ?? 0);
    }

    /// <summary>
    /// Measures the current no-body GET request decode, validation, validator, and request materialization shape.
    /// </summary>
    [Benchmark]
    public int RequestHeaders_DecodeValidateAndMaterializeNoBodyPlaintext()
    {
        QPackFieldLine[] decoded = DecodeRequestHeaders(plaintextRequestFieldSection);
        Http3RequestMessageValidator validator = new();
        validator.ReceiveOwnedHeaders(decoded);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        Http3Request request = new(
            result.Method ?? string.Empty,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length;
    }

    /// <summary>
    /// Measures the HEADERS-only GET lifecycle shape without DATA frame body storage.
    /// </summary>
    [Benchmark]
    public int RequestLifecycle_HeadersOnlyGetPlaintext()
    {
        QPackFieldLine[] decoded = DecodeRequestHeaders(plaintextRequestFieldSection);
        Http3RequestMessageValidator validator = new();
        ArrayBufferWriter<byte>? body = null;
        validator.ReceiveOwnedHeaders(decoded);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        if (result.Method != "GET")
        {
            throw new InvalidOperationException("The benchmark request was expected to be a GET request.");
        }

        Http3Request request = new(
            result.Method,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length ^ (body?.WrittenCount ?? 0);
    }

    /// <summary>
    /// Measures the HEADERS-only JSON GET lifecycle shape without DATA frame body storage.
    /// </summary>
    [Benchmark]
    public int RequestLifecycle_HeadersOnlyGetJson()
    {
        QPackFieldLine[] decoded = DecodeRequestHeaders(jsonRequestFieldSection);
        Http3RequestMessageValidator validator = new();
        ArrayBufferWriter<byte>? body = null;
        validator.ReceiveOwnedHeaders(decoded);
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, validateContentLength: false);
        if (result.Method != "GET")
        {
            throw new InvalidOperationException("The benchmark request was expected to be a GET request.");
        }

        Http3Request request = new(
            result.Method,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length ^ (body?.WrittenCount ?? 0);
    }

    /// <summary>
    /// Measures request lifecycle behavior once an empty DATA frame forces body writer use.
    /// </summary>
    [Benchmark]
    public int RequestLifecycle_GetWithEmptyData()
    {
        QPackFieldLine[] decoded = DecodeRequestHeaders(plaintextRequestFieldSection);
        Http3RequestMessageValidator validator = new();
        ArrayBufferWriter<byte>? body = null;
        validator.ReceiveOwnedHeaders(decoded);
        validator.ReceiveData(0);
        body ??= new ArrayBufferWriter<byte>();
        body.Write(ReadOnlySpan<byte>.Empty);
        validator.Complete();
        IReadOnlyList<QPackFieldLine> headers = validator.Headers ?? throw new InvalidOperationException("No headers were decoded.");
        Http3Request request = CreateRequest(headers, body.WrittenMemory);
        return request.Headers.Count ^ request.Path.Length ^ request.Body.Length ^ body.WrittenCount;
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

    private static QPackFieldLine[] DecodeRequestHeaders(ReadOnlyMemory<byte> encodedFieldSection)
    {
        QPackDecoder decoder = new(0, 0);
        QPackFieldSectionDecodeResult result = decoder.DecodeFieldSection(0, encodedFieldSection);
        if (result.IsBlocked)
        {
            throw new InvalidOperationException("The benchmark request field section unexpectedly blocked.");
        }

        return result.FieldLines;
    }

    private static int CountHeaderCharacters(ReadOnlySpan<QPackFieldLine> headers)
    {
        int total = 0;
        foreach (QPackFieldLine header in headers)
        {
            total += header.Name.Length + header.Value.Length;
        }

        return total;
    }

    private static int CountHeaderCharactersList(IReadOnlyList<QPackFieldLine> headers)
    {
        int total = 0;
        foreach (QPackFieldLine header in headers)
        {
            total += header.Name.Length + header.Value.Length;
        }

        return total;
    }

    private static Http3Request CreateRequest(IReadOnlyList<QPackFieldLine> headers, ReadOnlyMemory<byte> body)
    {
        Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(headers, checked((ulong)body.Length));
        return new Http3Request(
            result.Method ?? string.Empty,
            result.Scheme ?? string.Empty,
            result.Authority ?? string.Empty,
            result.Path ?? string.Empty,
            headers,
            body);
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
