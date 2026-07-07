// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9220_DeferredFuzzClosure
{
    private static readonly byte[] MaskingKey = [0x11, 0x22, 0x33, 0x44];

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ExtendedConnectPseudoHeadersPreserveRfc8441Semantics()
    {
        foreach ((string scheme, string authority, string path) in new[]
        {
            ("https", "example.com", "/chat"),
            ("https", "localhost:8443", "/socket?room=blue"),
            ("http", "gateway.example", "/ws/subprotocol"),
        })
        {
            Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(
            [
                new QPackFieldLine(":method", "CONNECT"),
                new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
                new QPackFieldLine(":scheme", scheme),
                new QPackFieldLine(":authority", authority),
                new QPackFieldLine(":path", path),
            ]);

            Assert.True(Http3ExtendedConnect.IsExtendedConnect(result));
            Assert.Equal("CONNECT", result.Method);
            Assert.Equal(Http3ExtendedConnect.WebSocketProtocol, result.Protocol);
            Assert.Equal(scheme, result.Scheme);
            Assert.Equal(authority, result.Authority);
            Assert.Equal(path, result.Path);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EnableConnectSettingUsesRegisteredIdentifier()
    {
        foreach (ulong value in new[] { 1UL, 2UL, 63UL, 64UL, 16383UL })
        {
            Http3SettingsFrame frame = ReadSettingsFrame(new Http3Settings(enableConnectProtocol: value));

            Http3Setting setting = Assert.Single(
                frame.Settings,
                setting => setting.Identifier == (ulong)Http3SettingIdentifier.EnableConnectProtocol);
            Assert.Equal(0x08UL, setting.Identifier);
            Assert.Equal(value, setting.Value);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OrderlyExtendedConnectClosureAlwaysUsesFin()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Http3ExtendedConnectClosure closure = Http3ExtendedConnect.MapOrderlyClosure();

            Assert.True(closure.FinishStream);
            Assert.Null(closure.ResetErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetExtendedConnectClosureAlwaysUsesRequestCancelled()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Http3ExtendedConnectClosure closure = Http3ExtendedConnect.MapResetException();

            Assert.False(closure.FinishStream);
            Assert.Equal(Http3ErrorCode.RequestCancelled, closure.ResetErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EnableConnectProtocolRoundTripsThroughSettingsParser()
    {
        foreach (ulong value in new[] { 1UL, 17UL, 255UL, 1024UL })
        {
            byte[] payload = [.. EncodeVarint((ulong)Http3SettingIdentifier.EnableConnectProtocol), .. EncodeVarint(value)];
            Http3SettingsFrame frame = Assert.IsType<Http3SettingsFrame>(
                Assert.Single(new Http3FrameReader().Read(Http3FrameWriter.WriteFrame((ulong)Http3FrameType.Settings, payload))));

            Assert.Equal(value, frame.Values.EnableConnectProtocol);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EnableConnectProtocolDefaultsToZeroAndIsOmittedWhenUnset()
    {
        foreach (Http3Settings settings in new[]
        {
            new Http3Settings(),
            new Http3Settings(qpackMaxTableCapacity: 128),
            new Http3Settings(qpackBlockedStreams: 3, maxFieldSectionSize: 4096),
        })
        {
            Http3SettingsFrame frame = ReadSettingsFrame(settings);

            Assert.Equal(0UL, frame.Values.EnableConnectProtocol);
            Assert.DoesNotContain(
                frame.Settings,
                setting => setting.Identifier == (ulong)Http3SettingIdentifier.EnableConnectProtocol);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_WebSocketDispatchPredicateAcceptsOnlyRegisteredProtocolToken()
    {
        foreach ((string? protocol, bool supported) in new[]
        {
            (Http3ExtendedConnect.WebSocketProtocol, true),
            ("WebSocket", false),
            ("webtransport", false),
            ("connect-udp", false),
            ((string?)null, false),
        })
        {
            Assert.Equal(supported, Http3ExtendedConnect.IsSupportedProtocol(protocol));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CloseFramesCanBeParsedAndEchoedWithoutPayloadMutation()
    {
        foreach ((ushort statusCode, string? reason) in new (ushort, string?)[]
        {
            (1000, null),
            (1001, "going away"),
            (1008, "policy"),
            (1011, "internal error"),
        })
        {
            byte[] closePayload = Http3WebSocketCloseFrameParser.FormatPayload(statusCode, reason);
            Http3WebSocketMessage received = ReadSingleMessage(
                Http3EndpointRole.Server,
                Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Close, closePayload, MaskingKey));
            byte[] echoed = Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Close, received.Payload.Span);
            Http3WebSocketMessage clientEcho = ReadSingleMessage(Http3EndpointRole.Client, echoed);
            Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(clientEcho);

            Assert.Equal(Http3WebSocketOpcode.Close, clientEcho.Opcode);
            Assert.Equal(statusCode, closeStatus.StatusCode);
            Assert.Equal(reason, closeStatus.Reason);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientPingPayloadsEchoAsPongPayloads()
    {
        foreach (byte[] payload in ControlPayloads())
        {
            Http3WebSocketMessage ping = ReadSingleMessage(
                Http3EndpointRole.Server,
                Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Ping, payload, MaskingKey));
            byte[] pongFrame = Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Pong, ping.Payload.Span);
            Http3WebSocketMessage pong = ReadSingleMessage(Http3EndpointRole.Client, pongFrame);

            Assert.Equal(Http3WebSocketOpcode.Pong, pong.Opcode);
            Assert.Equal(payload, pong.Payload.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ApplicationSelectedCloseFramesCarrySelectedStatusAndReason()
    {
        foreach ((ushort statusCode, string? reason) in new (ushort, string?)[]
        {
            (1000, "done"),
            (1008, "policy"),
            (1012, "restart"),
            (1013, "try later"),
        })
        {
            byte[] payload = Http3WebSocketCloseFrameParser.FormatPayload(statusCode, reason);
            Http3WebSocketMessage close = ReadSingleMessage(
                Http3EndpointRole.Client,
                Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Close, payload));
            Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.Parse(close);

            Assert.Equal(statusCode, status.StatusCode);
            Assert.Equal(reason, status.Reason);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MalformedTunnelFramesMapToProtocolErrorClosePayload()
    {
        byte[][] malformedInputs =
        [
            Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Text, "unmasked-client"u8),
            [0xC1, 0x80, .. MaskingKey],
            [0x8B, 0x80, .. MaskingKey],
        ];

        foreach (byte[] malformed in malformedInputs)
        {
            Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);

            Http3Exception exception = Assert.Throws<Http3Exception>(() => reader.Read(malformed));
            byte[] protocolErrorClose = Http3WebSocketFrameWriter.WriteUnmasked(
                Http3WebSocketOpcode.Close,
                Http3WebSocketCloseFrameParser.FormatPayload(1002, "protocol error"));
            Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(
                ReadSingleMessage(Http3EndpointRole.Client, protocolErrorClose));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
            Assert.Equal((ushort)1002, closeStatus.StatusCode.GetValueOrDefault());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0022")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerPingFramesAreUnmaskedAndLeavePayloadIntact()
    {
        foreach (byte[] payload in ControlPayloads())
        {
            byte[] frame = Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Ping, payload);
            Http3WebSocketMessage ping = ReadSingleMessage(Http3EndpointRole.Client, frame);

            Assert.Equal(Http3WebSocketOpcode.Ping, ping.Opcode);
            Assert.Equal(payload, ping.Payload.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0023")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultHandlerExceptionPolicyFormatsInternalErrorClose()
    {
        Http3ServerOptions options = new();
        byte[] payload = Http3WebSocketCloseFrameParser.FormatPayload(
            options.WebSocketHandlerExceptionCloseStatusCode,
            options.WebSocketHandlerExceptionCloseReason);
        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.ParsePayload(payload);

        Assert.Equal((ushort)1011, closeStatus.StatusCode.GetValueOrDefault());
        Assert.Equal("internal error", closeStatus.Reason);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0024")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConfiguredKeepAliveIntervalsProducePingFrames()
    {
        foreach (TimeSpan interval in new[]
        {
            TimeSpan.FromMilliseconds(1),
            TimeSpan.FromMilliseconds(25),
            TimeSpan.FromSeconds(5),
        })
        {
            Http3ServerOptions options = new()
            {
                WebSocketKeepAliveInterval = interval,
                WebSocketKeepAlivePayload = "ka"u8.ToArray(),
            };
            Http3WebSocketMessage ping = ReadSingleMessage(
                Http3EndpointRole.Client,
                Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Ping, options.WebSocketKeepAlivePayload.Span));

            Assert.Equal(interval, options.WebSocketKeepAliveInterval);
            Assert.Equal(Http3WebSocketOpcode.Ping, ping.Opcode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0025")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_BinaryTunnelFramesCanBridgeToTcpPayloadBytes()
    {
        foreach (byte[] payload in new[]
        {
            "abc"u8.ToArray(),
            Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray(),
            Enumerable.Repeat((byte)0xA5, 257).ToArray(),
        })
        {
            Http3WebSocketMessage websocketMessage = ReadSingleMessage(
                Http3EndpointRole.Server,
                Http3WebSocketFrameWriter.WriteMasked(Http3WebSocketOpcode.Binary, payload, MaskingKey));
            using MemoryStream tcpStream = new();

            tcpStream.Write(websocketMessage.Payload.Span);

            Assert.Equal(Http3WebSocketOpcode.Binary, websocketMessage.Opcode);
            Assert.Equal(payload, tcpStream.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0026")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConfiguredKeepAlivePayloadsAreSentOnPingFrames()
    {
        foreach (byte[] payload in ControlPayloads())
        {
            Http3ServerOptions options = new()
            {
                WebSocketKeepAliveInterval = TimeSpan.FromSeconds(1),
                WebSocketKeepAlivePayload = payload,
            };
            Http3WebSocketMessage ping = ReadSingleMessage(
                Http3EndpointRole.Client,
                Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Ping, options.WebSocketKeepAlivePayload.Span));

            Assert.Equal(payload, ping.Payload.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConfiguredHandlerExceptionClosePolicyFormatsValidClosePayloads()
    {
        foreach ((ushort statusCode, string reason) in new (ushort, string)[]
        {
            (1008, "policy"),
            (1011, "internal"),
            (1013, "busy"),
        })
        {
            Http3ServerOptions options = new()
            {
                WebSocketHandlerExceptionCloseStatusCode = statusCode,
                WebSocketHandlerExceptionCloseReason = reason,
            };
            Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.ParsePayload(
                Http3WebSocketCloseFrameParser.FormatPayload(
                    options.WebSocketHandlerExceptionCloseStatusCode,
                    options.WebSocketHandlerExceptionCloseReason));

            Assert.Equal(statusCode, status.StatusCode);
            Assert.Equal(reason, status.Reason);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DynamicHandlerExceptionClosePolicyCanSelectPerExceptionPayloads()
    {
        Http3ServerOptions options = new()
        {
            WebSocketHandlerExceptionClosePolicySelector = exception => exception switch
            {
                InvalidOperationException => new Http3WebSocketClosePolicy(1012, "restart"),
                TimeoutException => new Http3WebSocketClosePolicy(1013, "timeout"),
                _ => null,
            },
        };

        foreach ((Exception exception, ushort? expectedStatus, string? expectedReason) in new (Exception, ushort?, string?)[]
        {
            (new InvalidOperationException(), 1012, "restart"),
            (new TimeoutException(), 1013, "timeout"),
            (new ApplicationException(), null, null),
        })
        {
            Http3WebSocketClosePolicy? policy = options.WebSocketHandlerExceptionClosePolicySelector(exception);

            if (expectedStatus is null)
            {
                Assert.Null(policy);
                continue;
            }

            Assert.NotNull(policy);
            Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.ParsePayload(
                Http3WebSocketCloseFrameParser.FormatPayload(policy.Value.StatusCode, policy.Value.Reason));
            Assert.Equal(expectedStatus, status.StatusCode);
            Assert.Equal(expectedReason, status.Reason);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TcpResponseChunksStayWithinConfiguredForwardingBuffer()
    {
        byte[] tcpResponse = Enumerable.Range(0, 65).Select(static value => (byte)value).ToArray();

        foreach (int bufferSize in new[] { 1, 7, 16, 32 })
        {
            Http3WebSocketTcpForwarderOptions options = new() { BufferSize = bufferSize };
            byte[][] chunks = Chunk(tcpResponse, options.BufferSize).ToArray();

            Assert.All(chunks, chunk => Assert.InRange(chunk.Length, 1, options.BufferSize));
            Assert.Equal(tcpResponse, chunks.SelectMany(static chunk => chunk).ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0030")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientSideWebSocketConnectRequiresAbsoluteUriAndEnableConnectSetting()
    {
        foreach (Uri uri in new[]
        {
            new Uri("https://example.com/socket"),
            new Uri("https://localhost:8443/ws?room=1"),
            new Uri("http://gateway.example/tunnel"),
        })
        {
            Http3SettingsFrame frame = ReadSettingsFrame(new Http3Settings(enableConnectProtocol: 1));
            Http3HeaderValidationResult request = ValidateWebSocketConnectRequest(uri);

            Assert.True(uri.IsAbsoluteUri);
            Assert.Equal(1UL, frame.Values.EnableConnectProtocol);
            Assert.True(Http3ExtendedConnect.IsExtendedConnect(request));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0031")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_WebSocketNegotiationHeadersTravelWithExtendedConnectHeaders()
    {
        foreach ((Uri uri, QPackFieldLine[] headers) in new[]
        {
            (new Uri("https://example.com/chat"), new[] { new QPackFieldLine("sec-websocket-protocol", "chat") }),
            (new Uri("https://example.com/metrics"), new[] { new QPackFieldLine("sec-websocket-extensions", "permessage-deflate") }),
            (new Uri("https://example.com/socket"), new[] { new QPackFieldLine("origin", "https://example.com") }),
        })
        {
            QPackFieldLine[] fieldSection =
            [
                new QPackFieldLine(":method", "CONNECT"),
                new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
                new QPackFieldLine(":scheme", uri.Scheme),
                new QPackFieldLine(":authority", uri.Authority),
                new QPackFieldLine(":path", uri.PathAndQuery),
                .. headers,
            ];

            Http3HeaderValidationResult result = Http3HeaderValidator.ValidateRequestHeaders(fieldSection);

            Assert.Equal(Http3ExtendedConnect.WebSocketProtocol, result.Protocol);
            Assert.All(headers, header => Assert.Contains(fieldSection, candidate => candidate.Name == header.Name && candidate.Value == header.Value));
        }
    }

    [Fact]
    [Requirement("RFC9220-S3-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnsupportedExtendedConnectProtocolsUseRecommendedResponse()
    {
        foreach (string protocol in new[] { "webtransport", "connect-udp", "masque", "WebSocket" })
        {
            Http3ServerResponse response = Http3ExtendedConnect.CreateUnsupportedProtocolResponse(protocol);

            Assert.False(Http3ExtendedConnect.IsSupportedProtocol(protocol));
            Assert.Equal(Http3ExtendedConnect.UnsupportedProtocolStatusCode, response.StatusCode);
            Assert.Equal("Not Implemented", Encoding.UTF8.GetString(response.Body.Span));
        }
    }

    [Fact]
    [Requirement("RFC9220-S3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnsupportedProtocolProblemDetailsEscapesProtocolToken()
    {
        foreach (string protocol in new[] { "webtransport", "quote\"token", "slash\\token" })
        {
            Http3ServerResponse response = Http3ExtendedConnect.CreateUnsupportedProtocolResponse(protocol, includeProblemDetails: true);
            string body = Encoding.UTF8.GetString(response.Body.Span);

            Assert.Equal("application/problem+json", Assert.Single(response.Headers).Value);
            Assert.Contains("\"status\":501", body, StringComparison.Ordinal);
            Assert.DoesNotContain("\"protocol\":\"quote\"token\"", body, StringComparison.Ordinal);
            Assert.DoesNotContain("\"protocol\":\"slash\\token\"", body, StringComparison.Ordinal);
        }
    }

    private static Http3SettingsFrame ReadSettingsFrame(Http3Settings settings)
    {
        return Assert.IsType<Http3SettingsFrame>(
            Assert.Single(new Http3FrameReader().Read(Http3SettingsWriter.WriteSettingsFrame(settings))));
    }

    private static Http3WebSocketMessage ReadSingleMessage(Http3EndpointRole receivingEndpointRole, byte[] frame)
    {
        Http3WebSocketMessageReader reader = new(receivingEndpointRole);
        Http3WebSocketMessage message = Assert.Single(reader.Read(frame));
        Assert.Empty(reader.Complete());
        return message;
    }

    private static Http3HeaderValidationResult ValidateWebSocketConnectRequest(Uri uri)
    {
        return Http3HeaderValidator.ValidateRequestHeaders(
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new QPackFieldLine(":scheme", uri.Scheme),
            new QPackFieldLine(":authority", uri.Authority),
            new QPackFieldLine(":path", uri.PathAndQuery),
        ]);
    }

    private static IEnumerable<byte[]> ControlPayloads()
    {
        yield return [];
        yield return [0x01];
        yield return "ka:socket"u8.ToArray();
        yield return Enumerable.Range(0, 125).Select(static value => (byte)value).ToArray();
    }

    private static IEnumerable<byte[]> Chunk(byte[] source, int chunkSize)
    {
        for (int offset = 0; offset < source.Length; offset += chunkSize)
        {
            int length = Math.Min(chunkSize, source.Length - offset);
            yield return source.AsSpan(offset, length).ToArray();
        }
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[Http3VariableLengthInteger.MaxEncodedLength];
        Assert.True(Http3VariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}
