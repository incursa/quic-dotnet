// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks RFC 9220 WebSocket-over-HTTP/3 frame parsing and message reassembly.
/// </summary>
[MemoryDiagnoser]
public class Http3WebSocketMessageReaderBenchmarks
{
    private static readonly byte[] MaskingKey = [0x11, 0x22, 0x33, 0x44];

    private byte[] maskedTextFrame = [];
    private byte[] maskedUtf8TextFrame = [];
    private byte[] fragmentedBinaryFrames = [];
    private byte[] closePayload = [];

    /// <summary>
    /// Prepares deterministic WebSocket tunnel payloads.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        maskedTextFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "benchmark-message"u8,
            MaskingKey);
        maskedUtf8TextFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "benchmark-message-\u2713"u8,
            MaskingKey);
        fragmentedBinaryFrames = Concat(
            Http3WebSocketFrameWriter.WriteMasked(
                Http3WebSocketOpcode.Binary,
                CreateDeterministicBytes(128),
                MaskingKey,
                final: false),
            Http3WebSocketFrameWriter.WriteMasked(
                Http3WebSocketOpcode.Continuation,
                CreateDeterministicBytes(128),
                MaskingKey,
                final: true));
        closePayload = [0x03, 0xE8, .. "normal"u8.ToArray()];
    }

    /// <summary>
    /// Measures parsing a single masked client text frame.
    /// </summary>
    [Benchmark]
    public int ReadMaskedClientTextMessage()
    {
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);
        Http3WebSocketMessage[] messages = reader.Read(maskedTextFrame);
        return CountPayloadBytes(messages) ^ reader.PendingByteCount;
    }

    /// <summary>
    /// Measures reassembling a fragmented masked client binary message.
    /// </summary>
    [Benchmark]
    public int ReadFragmentedClientBinaryMessage()
    {
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);
        Http3WebSocketMessage[] messages = reader.Read(fragmentedBinaryFrames);
        return CountPayloadBytes(messages) ^ reader.PendingByteCount;
    }

    /// <summary>
    /// Measures parsing and UTF-8 validation for a masked client text message.
    /// </summary>
    [Benchmark]
    public int ReadMaskedClientUtf8TextMessage()
    {
        Http3WebSocketMessageReader reader = new(Http3EndpointRole.Server);
        Http3WebSocketMessage[] messages = reader.Read(maskedUtf8TextFrame);
        return CountPayloadBytes(messages) ^ reader.PendingByteCount;
    }

    /// <summary>
    /// Measures parsing a WebSocket close status and UTF-8 reason payload.
    /// </summary>
    [Benchmark]
    public int ParseClosePayloadWithReason()
    {
        Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.ParsePayload(closePayload);
        return (status.StatusCode ?? 0) ^ (status.Reason?.Length ?? 0);
    }

    private static int CountPayloadBytes(ReadOnlySpan<Http3WebSocketMessage> messages)
    {
        int total = 0;
        foreach (Http3WebSocketMessage message in messages)
        {
            total += message.Payload.Length;
        }

        return total;
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        byte[] combined = new byte[first.Length + second.Length];
        first.CopyTo(combined, 0);
        second.CopyTo(combined, first.Length);
        return combined;
    }

    private static byte[] CreateDeterministicBytes(int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(index % 251);
        }

        return bytes;
    }
}
