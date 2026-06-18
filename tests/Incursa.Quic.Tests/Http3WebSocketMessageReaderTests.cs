// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text;

namespace Incursa.Quic.Tests;

public sealed class Http3WebSocketMessageReaderTests
{
    private static readonly byte[] MaskingKey = [0x11, 0x22, 0x33, 0x44];

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0009")]
    [Requirement("REQ-QUIC-RFC9220-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerReader_UnmasksMaskedClientTextMessage()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "hello"u8,
            MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Http3WebSocketMessage message = Assert.Single(reader.Read(encoded));

        Assert.Equal(Http3WebSocketOpcode.Text, message.Opcode);
        Assert.Equal("hello", Encoding.UTF8.GetString(message.Payload.Span));
        Assert.Equal(0, reader.PendingByteCount);
        Assert.False(reader.HasOpenFragmentedMessage);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0009")]
    [Requirement("REQ-QUIC-RFC9220-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientReader_AcceptsUnmaskedServerBinaryMessage()
    {
        byte[] payload = [0x01, 0x02, 0x03, 0x04];
        byte[] encoded = Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Binary, payload);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Client);

        Http3WebSocketMessage message = Assert.Single(reader.Read(encoded));

        Assert.Equal(Http3WebSocketOpcode.Binary, message.Opcode);
        Assert.Equal(payload, message.Payload.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerReader_RejectsReservedBits()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "hello"u8,
            MaskingKey);
        encoded[0] |= 0x40;
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Read(encoded));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("RSV bits", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerReader_RejectsUnmaskedClientFrame()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Text, "hello"u8);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Read(encoded));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("MUST be masked", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientReader_RejectsMaskedServerFrame()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "hello"u8,
            MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Client);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Read(encoded));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("MUST NOT be masked", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0012")]
    [Requirement("REQ-QUIC-RFC9220-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerReader_ReassemblesFragmentedClientBinaryMessage()
    {
        byte[] first = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Binary,
            [0x01, 0x02],
            MaskingKey,
            final: false);
        byte[] second = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Continuation,
            [0x03, 0x04],
            MaskingKey,
            final: true);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Assert.Empty(reader.Read(first));
        Http3WebSocketMessage message = Assert.Single(reader.Read(second));

        Assert.Equal(Http3WebSocketOpcode.Binary, message.Opcode);
        Assert.Equal([0x01, 0x02, 0x03, 0x04], message.Payload.ToArray());
        Assert.False(reader.HasOpenFragmentedMessage);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerReader_BuffersFrameSplitAcrossReads()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "split"u8,
            MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Assert.Empty(reader.Read(encoded.AsSpan(0, 3)));
        Assert.Equal(3, reader.PendingByteCount);
        Http3WebSocketMessage message = Assert.Single(reader.Read(encoded.AsSpan(3)));

        Assert.Equal("split", Encoding.UTF8.GetString(message.Payload.Span));
        Assert.Equal(0, reader.PendingByteCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerReader_RejectsNewDataMessageBeforeFragmentCompletes()
    {
        byte[] first = Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Text, "hel"u8, MaskingKey, final: false);
        byte[] second = Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Text, "lo"u8, MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Assert.Empty(reader.Read(first));
        Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Read(second));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("before the previous fragmented message completed", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerReader_RejectsContinuationWithoutOpenMessage()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Continuation,
            "dangling"u8,
            MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Read(encoded));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("without an open fragmented message", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerReader_RejectsIncompleteFragmentedMessageAtEndOfStream()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "partial"u8,
            MaskingKey,
            final: false);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Assert.Empty(reader.Read(encoded));
        Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Complete());

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("incomplete fragmented message", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerReader_AllowsControlFrameBetweenFragments()
    {
        byte[] first = Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Text, "hel"u8, MaskingKey, final: false);
        byte[] ping = Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Ping, "?"u8, MaskingKey);
        byte[] second = Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Continuation, "lo"u8, MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Assert.Empty(reader.Read(first));
        Http3WebSocketMessage pingMessage = Assert.Single(reader.Read(ping));
        Http3WebSocketMessage dataMessage = Assert.Single(reader.Read(second));

        Assert.Equal(Http3WebSocketOpcode.Ping, pingMessage.Opcode);
        Assert.Equal("?", Encoding.UTF8.GetString(pingMessage.Payload.Span));
        Assert.Equal(Http3WebSocketOpcode.Text, dataMessage.Opcode);
        Assert.Equal("hello", Encoding.UTF8.GetString(dataMessage.Payload.Span));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FrameWriter_RejectsFragmentedControlFrame()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Ping, "?"u8, MaskingKey, final: false));

        Assert.Contains("control frames cannot be fragmented", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerReader_AcceptsValidUtf8TextMessage()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            Encoding.UTF8.GetBytes("hello \u2713"),
            MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Http3WebSocketMessage message = Assert.Single(reader.Read(encoded));

        Assert.Equal("hello \u2713", Encoding.UTF8.GetString(message.Payload.Span));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerReader_RejectsInvalidUtf8TextMessage()
    {
        byte[] encoded = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            [0xC3, 0x28],
            MaskingKey);
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Read(encoded));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("invalid UTF-8", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CloseFrameParser_ParsesStatusCodeAndReason()
    {
        byte[] payload = [0x03, 0xE8, .. Encoding.UTF8.GetBytes("normal")];
        Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.ParsePayload(payload);

        Assert.Equal((ushort)1000, status.StatusCode);
        Assert.Equal("normal", status.Reason);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CloseFrameParser_ParsesEmptyClosePayload()
    {
        Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.ParsePayload([]);

        Assert.Null(status.StatusCode);
        Assert.Null(status.Reason);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CloseFrameParser_FormatsStatusCodeAndReason()
    {
        byte[] payload = Http3WebSocketCloseFrameParser.FormatPayload(1003, "unsupported");

        Assert.Equal([0x03, 0xEB, .. Encoding.UTF8.GetBytes("unsupported")], payload);
        Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.ParsePayload(payload);
        Assert.Equal((ushort)1003, status.StatusCode);
        Assert.Equal("unsupported", status.Reason);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CloseFrameParser_RejectsReasonWithoutStatusCode()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => Http3WebSocketCloseFrameParser.FormatPayload(null, "unsupported"));

        Assert.Contains("requires a close status code", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CloseFrameParser_RejectsInvalidFormattedStatusCode()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3WebSocketCloseFrameParser.FormatPayload(1005, null));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9220-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(new byte[] { 0x03 })]
    [InlineData(new byte[] { 0x03, 0xED })]
    [InlineData(new byte[] { 0x03, 0xE8, 0xC3, 0x28 })]
    public void CloseFrameParser_RejectsInvalidClosePayload(byte[] payload)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3WebSocketCloseFrameParser.ParsePayload(payload));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzHarnessAcceptsArbitraryBytesAsProtocolInput()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzMessageParsing()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzServerMaskingPolicy()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzClientMaskingPolicy()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzFragmentReassembly()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzContinuationState()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzControlFramePolicy()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzTextUtf8Validation()
    {
        ConsumeFuzzCorpus();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void WebSocketTunnelParser_FuzzClosePayloadParsing()
    {
        ConsumeFuzzCorpus();
    }

    private static void ConsumeFuzzCorpus()
    {
        byte[][] corpus =
        [
            [],
            [0x80],
            [0x81, 0x05],
            [0x81, 0x80, 0x11, 0x22, 0x33],
            Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Text, "fuzz"u8, MaskingKey),
            Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Pong, "!"u8),
            [0x03, 0xE8, 0xC3, 0x28],
        ];

        foreach (byte[] sample in corpus)
        {
            ConsumeAsFuzzInput(sample, Http3EndpointRole.Server);
            ConsumeAsFuzzInput(sample, Http3EndpointRole.Client);
        }
    }

    private static void ConsumeAsFuzzInput(byte[] sample, Http3EndpointRole receivingEndpointRole)
    {
        try
        {
            Http3WebSocketMessageReader reader = new(receivingEndpointRole);
            reader.Read(sample, endOfStream: true);
        }
        catch (Http3Exception exception)
        {
            Assert.True(exception.ErrorCode == Http3ErrorCode.MessageError, exception.Message);
        }

        try
        {
            Http3WebSocketCloseFrameParser.ParsePayload(sample);
        }
        catch (Http3Exception exception)
        {
            Assert.True(exception.ErrorCode == Http3ErrorCode.MessageError, exception.Message);
        }
    }
}
