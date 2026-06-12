// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;
using Incursa.Qpack;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks RFC 9204 QPACK field-section and dynamic-state paths.
/// </summary>
[MemoryDiagnoser]
public class QPackFieldSectionBenchmarks
{
    private static readonly QPackFieldLine[] CommonRequest =
    [
        new(":method", "GET"),
        new(":scheme", "https"),
        new(":authority", "example.com"),
        new(":path", "/index.html"),
        new("user-agent", "incursa-test"),
    ];

    private byte[] encodedCommonResponse = [];
    private byte[] appendixB1FieldSection = [];
    private byte[] appendixB2EncoderStream = [];
    private byte[] blockedDynamicFieldSection = [];

    /// <summary>
    /// Prepares deterministic field-section and encoder-stream inputs.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        encodedCommonResponse = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("content-type", "text/plain"),
            new QPackFieldLine("content-length", "5"),
            new QPackFieldLine("server", "incursa"),
            new QPackFieldLine("cache-control", "no-cache"),
        ]);
        appendixB1FieldSection = Convert.FromHexString("0000510B2F696E6465782E68746D6C");
        appendixB2EncoderStream = Convert.FromHexString(
            "3FBD01C00F7777772E6578616D706C652E636F6DC10C2F73616D706C652F70617468");
        blockedDynamicFieldSection = Convert.FromHexString("03811011");
    }

    /// <summary>
    /// Measures deterministic static and literal field-section encoding.
    /// </summary>
    [Benchmark]
    public int FieldSection_EncodeCommonRequest()
    {
        return QPackEncoder.EncodeFieldSection(CommonRequest).Length;
    }

    /// <summary>
    /// Measures static and literal field-section decoding.
    /// </summary>
    [Benchmark]
    public int FieldSection_DecodeCommonResponse()
    {
        return QPackDecoder.DecodeFieldSection(encodedCommonResponse).Length;
    }

    /// <summary>
    /// Measures RFC 9204 Appendix B.1 static-name-reference decoding.
    /// </summary>
    [Benchmark]
    public int FieldSection_DecodeAppendixB1StaticNameReference()
    {
        return QPackDecoder.DecodeFieldSection(appendixB1FieldSection)[0].Value.Length;
    }

    /// <summary>
    /// Measures dynamic field-section blocking and unblocking when missing entries arrive.
    /// </summary>
    [Benchmark]
    public int DynamicState_BlockThenUnblockFieldSection()
    {
        QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        QPackFieldSectionDecodeResult blocked = decoder.DecodeFieldSection(4, blockedDynamicFieldSection);
        QPackFieldSectionDecodeResult[] unblocked = decoder.DecodeEncoderStream(appendixB2EncoderStream);
        return (blocked.IsBlocked ? 1 : 0) ^ unblocked.Length;
    }

    /// <summary>
    /// Measures dynamic-reference field-section encoding after encoder-stream inserts.
    /// </summary>
    [Benchmark]
    public int DynamicState_EncodeDynamicReferences()
    {
        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        encoder.TrySetDynamicTableCapacity(220, out _);
        encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out _);
        encoder.TryInsert(new QPackFieldLine(":path", "/sample/path"), out _);
        QPackFieldSectionEncodeResult encoded = encoder.EncodeFieldSection(
            4,
            [
                new QPackFieldLine(":authority", "www.example.com"),
                new QPackFieldLine(":path", "/sample/path"),
            ]);
        return encoded.EncodedFieldSection.Length ^ checked((int)encoded.RequiredInsertCount);
    }
}
