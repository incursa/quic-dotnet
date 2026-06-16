// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Text;
using BenchmarkDotNet.Attributes;
using Incursa.Quic.Dns;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks RFC 9461 DNS ServiceMode SVCB RDATA parsing.
/// </summary>
[MemoryDiagnoser]
public class DnsServiceBindingWireRecordBenchmarks
{
    private byte[] serviceModeRData = [];

    /// <summary>
    /// Prepares a deterministic DNS ServiceMode SVCB RDATA payload.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        serviceModeRData =
        [
            .. WriteUInt16(1),
            .. EncodeDomainName("resolver.example."),
            .. CreateSvcParam(1, [3, (byte)'d', (byte)'o', (byte)'q', 2, (byte)'h', (byte)'3']),
            .. CreateSvcParam(3, [0x22, 0x95]),
            .. CreateSvcParam(7, Encoding.UTF8.GetBytes("/dns-query{?dns}")),
        ];
    }

    /// <summary>
    /// Measures parsing a ServiceMode SVCB RDATA value into RFC 9461 scalar inputs.
    /// </summary>
    [Benchmark]
    public int ParseServiceModeRData()
    {
        DnsServiceBindingWireRecord parsed =
            DnsServiceBindingWireRecord.ParseServiceModeRData("resolver.example", serviceModeRData);
        return parsed.Priority ^ parsed.ServiceBinding.AlpnProtocols.Count ^ (parsed.ServiceBinding.Port ?? 0);
    }

    private static byte[] CreateSvcParam(ushort key, byte[] value)
    {
        byte[] parameter = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt16BigEndian(parameter, key);
        BinaryPrimitives.WriteUInt16BigEndian(parameter.AsSpan(2), checked((ushort)value.Length));
        value.CopyTo(parameter.AsSpan(4));
        return parameter;
    }

    private static byte[] EncodeDomainName(string name)
    {
        List<byte> encoded = [];
        foreach (string label in name.TrimEnd('.').Split('.'))
        {
            encoded.Add(checked((byte)label.Length));
            encoded.AddRange(Encoding.ASCII.GetBytes(label));
        }

        encoded.Add(0);
        return [.. encoded];
    }

    private static byte[] WriteUInt16(ushort value)
    {
        byte[] buffer = new byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
        return buffer;
    }
}
