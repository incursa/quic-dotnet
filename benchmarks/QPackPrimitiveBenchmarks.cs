// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using BenchmarkDotNet.Attributes;
using Incursa.Qpack;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks RFC 9204 QPACK primitive codec paths.
/// </summary>
[MemoryDiagnoser]
public class QPackPrimitiveBenchmarks
{
    private byte[] maxInteger = [];
    private byte[] rawString = [];
    private byte[] huffmanString = [];

    /// <summary>
    /// Prepares deterministic primitive encodings.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        maxInteger = QPackInteger.Encode(QPackInteger.MaxValue, prefixBitCount: 8);
        rawString = Convert.FromHexString("0B2F696E6465782E68746D6C");
        huffmanString = Convert.FromHexString("8CF1E3C2E5F23A6BA0AB90F4FF");
    }

    /// <summary>
    /// Measures encoding the largest supported prefixed integer.
    /// </summary>
    [Benchmark]
    public int Integer_EncodeMaxValue()
    {
        return QPackInteger.Encode(QPackInteger.MaxValue, prefixBitCount: 8).Length;
    }

    /// <summary>
    /// Measures decoding the largest supported prefixed integer.
    /// </summary>
    [Benchmark]
    public ulong Integer_DecodeMaxValue()
    {
        return QPackInteger.Decode(maxInteger, prefixBitCount: 8, out int bytesConsumed) ^ checked((ulong)bytesConsumed);
    }

    /// <summary>
    /// Measures writing a raw string literal.
    /// </summary>
    [Benchmark]
    public int StringLiteral_WriteRaw()
    {
        ArrayBufferWriter<byte> writer = new();
        QPackStringLiteral.Write(writer, "/index.html", prefixBitCount: 8);
        return writer.WrittenCount;
    }

    /// <summary>
    /// Measures reading a raw string literal.
    /// </summary>
    [Benchmark]
    public int StringLiteral_ReadRaw()
    {
        return QPackStringLiteral.Read(rawString, prefixBitCount: 8, out int bytesConsumed).Length ^ bytesConsumed;
    }

    /// <summary>
    /// Measures reading a Huffman-coded string literal.
    /// </summary>
    [Benchmark]
    public int StringLiteral_ReadHuffman()
    {
        return QPackStringLiteral.Read(huffmanString, prefixBitCount: 8, out int bytesConsumed).Length ^ bytesConsumed;
    }

    /// <summary>
    /// Measures RFC 9204 static table lookup at the highest valid index.
    /// </summary>
    [Benchmark]
    public int StaticTable_LookupLastEntry()
    {
        if (!QPackStaticTable.TryGet(98, out QPackFieldLine fieldLine))
        {
            throw new InvalidOperationException("The benchmark static table lookup failed.");
        }

        return fieldLine.Name.Length ^ fieldLine.Value.Length;
    }
}
