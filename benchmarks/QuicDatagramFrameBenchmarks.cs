// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks RFC 9221 DATAGRAM frame parse and format hot paths.
/// </summary>
[MemoryDiagnoser]
public class QuicDatagramFrameBenchmarks
{
    private byte[] datagramWithoutLengthFrame = [];
    private byte[] datagramWithLengthFrame = [];
    private QuicDatagramFrame datagramWithoutLengthTemplate = new();
    private QuicDatagramFrame datagramWithLengthTemplate = new();
    private byte[] destination = [];

    /// <summary>
    /// Prepares representative DATAGRAM frames plus output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        byte[] smallPayload = [0xA0, 0xA1, 0xA2, 0xA3];
        byte[] largePayload = new byte[1024];
        for (int i = 0; i < largePayload.Length; i++)
        {
            largePayload[i] = unchecked((byte)i);
        }

        datagramWithoutLengthTemplate = new QuicDatagramFrame
        {
            FrameType = QuicFrameCodec.DatagramWithoutLengthFrameType,
            DatagramData = smallPayload,
        };
        datagramWithLengthTemplate = new QuicDatagramFrame
        {
            FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
            DatagramData = largePayload,
        };

        datagramWithoutLengthFrame = Format(datagramWithoutLengthTemplate);
        datagramWithLengthFrame = Format(datagramWithLengthTemplate);
        destination = new byte[QuicVariableLengthInteger.MaxEncodedLength + largePayload.Length + 1];
    }

    /// <summary>
    /// Measures parsing DATAGRAM frames without an explicit Length field.
    /// </summary>
    [Benchmark]
    public int ParseDatagramWithoutLength()
    {
        return QuicFrameCodec.TryParseDatagramFrame(datagramWithoutLengthFrame, out QuicDatagramFrame frame, out int bytesConsumed)
            ? bytesConsumed ^ frame.DatagramData.Length
            : -1;
    }

    /// <summary>
    /// Measures parsing DATAGRAM frames with an explicit Length field.
    /// </summary>
    [Benchmark]
    public int ParseDatagramWithLength()
    {
        return QuicFrameCodec.TryParseDatagramFrame(datagramWithLengthFrame, out QuicDatagramFrame frame, out int bytesConsumed)
            ? bytesConsumed ^ frame.DatagramData.Length
            : -1;
    }

    /// <summary>
    /// Measures formatting DATAGRAM frames without an explicit Length field.
    /// </summary>
    [Benchmark]
    public int FormatDatagramWithoutLength()
    {
        return QuicFrameCodec.TryFormatDatagramFrame(datagramWithoutLengthTemplate, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures formatting DATAGRAM frames with an explicit Length field, which is the runtime's outbound send shape.
    /// </summary>
    [Benchmark]
    public int FormatDatagramWithLength()
    {
        return QuicFrameCodec.TryFormatDatagramFrame(datagramWithLengthTemplate, destination, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    private static byte[] Format(QuicDatagramFrame frame)
    {
        byte[] buffer = new byte[QuicVariableLengthInteger.MaxEncodedLength + frame.DatagramData.Length + 1];
        if (!QuicFrameCodec.TryFormatDatagramFrame(frame, buffer, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to prepare a DATAGRAM frame benchmark payload.");
        }

        return buffer[..bytesWritten];
    }
}
