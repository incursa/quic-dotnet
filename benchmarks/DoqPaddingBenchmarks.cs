// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;
using Incursa.Quic.Dns;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks DNS over QUIC EDNS(0) padding overhead for representative request payloads.
/// </summary>
[MemoryDiagnoser]
public class DoqPaddingBenchmarks
{
    private byte[] queryWithoutOpt = [];
    private byte[] queryWithOpt = [];
    private byte[] nearMaximumMessage = [];

    /// <summary>
    /// Gets or sets the configured EDNS(0) padding block size.
    /// </summary>
    [Params(0, 32, 128)]
    public int BlockSize { get; set; } = 32;

    /// <summary>
    /// Prepares stable DNS messages used by the padding benchmark cases.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        queryWithoutOpt =
        [
            0x00, 0x00, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x07, 0x65, 0x78, 0x61,
            0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        queryWithOpt = DoqPadding.PadMessage(queryWithoutOpt, blockSize: 32);
        nearMaximumMessage = new byte[DoqMessageCodec.MaxPayloadLength - 32];
    }

    /// <summary>
    /// Measures padding a common DNS query without an existing OPT record.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PadQueryWithoutExistingOpt()
    {
        return DoqPadding.PadMessage(queryWithoutOpt, BlockSize).Length;
    }

    /// <summary>
    /// Measures padding a DNS query that already carries an OPT record.
    /// </summary>
    [Benchmark]
    public int PadQueryWithExistingOpt()
    {
        return DoqPadding.PadMessage(queryWithOpt, BlockSize).Length;
    }

    /// <summary>
    /// Measures padding behavior near the RFC 9250 65535-byte DNS message limit.
    /// </summary>
    [Benchmark]
    public int PadNearMaximumMessage()
    {
        return DoqPadding.PadMessage(nearMaximumMessage, BlockSize).Length;
    }
}
