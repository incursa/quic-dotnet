// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Text;

namespace Incursa.Quic.Tests.RequirementHomes.RFC9461;

public sealed class REQ_QUIC_RFC9461_0039
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0039")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ParseServiceModeRData_DecodesPriorityTargetNameAndRegisteredSvcParams()
    {
        byte[] rdata = CreateServiceModeRData(
            priority: 1,
            targetName: "resolver.example.",
            svcParams:
            [
                CreateSvcParam(1, [3, (byte)'d', (byte)'o', (byte)'q', 2, (byte)'h', (byte)'3']),
                CreateSvcParam(3, [0x22, 0x95]),
                CreateSvcParam(7, Encoding.UTF8.GetBytes("/dns-query{?dns}")),
            ]);

        DnsServiceBindingWireRecord parsed =
            DnsServiceBindingWireRecord.ParseServiceModeRData("Resolver.Example", rdata);

        Assert.Equal(1, parsed.Priority);
        Assert.Equal("resolver.example.", parsed.TargetName);
        Assert.Equal("resolver.example", parsed.ServiceBinding.AuthenticationName);
        Assert.Equal(["doq", "h3"], parsed.ServiceBinding.AlpnProtocols);
        Assert.Equal(8853, parsed.ServiceBinding.Port);
        Assert.Equal("/dns-query{?dns}", parsed.ServiceBinding.DohPathTemplate);
        Assert.Equal([1, 3, 7], parsed.ServiceParameters.Select(parameter => (int)parameter.Key));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9461-0039")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [MemberData(nameof(MalformedRData))]
    public void ParseServiceModeRData_RejectsMalformedAliasCompressedAndUnsortedWireData(byte[] rdata)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            DnsServiceBindingWireRecord.ParseServiceModeRData("resolver.example", rdata));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0039")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ParseServiceModeRData_PreservesUnknownSortedSvcParamsAsHttpsServiceParameters()
    {
        byte[] rdata = CreateServiceModeRData(
            priority: ushort.MaxValue,
            targetName: ".",
            svcParams:
            [
                CreateSvcParam(1, [3, (byte)'d', (byte)'o', (byte)'q']),
                CreateSvcParam(4, [192, 0, 2, 53]),
                CreateSvcParam(42, [0xDE, 0xAD, 0xBE, 0xEF]),
            ]);

        DnsServiceBindingWireRecord parsed =
            DnsServiceBindingWireRecord.ParseServiceModeRData("resolver.example", rdata);

        Assert.Equal(ushort.MaxValue, parsed.Priority);
        Assert.Equal(".", parsed.TargetName);
        Assert.Equal("C0000235", parsed.ServiceBinding.HttpsServiceParameters["key00004"]);
        Assert.Equal("DEADBEEF", parsed.ServiceBinding.HttpsServiceParameters["key00042"]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0039")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ParseServiceModeRData_RepresentativeTruncationsAndMutationsAreDeterministic()
    {
        byte[] valid = CreateServiceModeRData(
            priority: 2,
            targetName: "resolver.example.",
            svcParams:
            [
                CreateSvcParam(1, [3, (byte)'d', (byte)'o', (byte)'q']),
                CreateSvcParam(7, Encoding.UTF8.GetBytes("/dns-query{?dns}")),
            ]);

        for (int length = 0; length <= valid.Length; length++)
        {
            byte[] candidate = valid[..length];
            try
            {
                DnsServiceBindingWireRecord parsed =
                    DnsServiceBindingWireRecord.ParseServiceModeRData("resolver.example", candidate);
                Assert.InRange(parsed.Priority, 1, ushort.MaxValue);
            }
            catch (ArgumentException)
            {
            }
        }

        for (int bit = 0; bit < Math.Min(valid.Length, 24); bit++)
        {
            byte[] mutated = valid.ToArray();
            mutated[bit] ^= 0x80;
            try
            {
                _ = DnsServiceBindingWireRecord.ParseServiceModeRData("resolver.example", mutated);
            }
            catch (ArgumentException)
            {
            }
        }
    }

    public static IEnumerable<object[]> MalformedRData()
    {
        yield return Row([]);
        yield return Row([0x00, 0x00, 0x00]);
        yield return Row([0x00, 0x01, 0xC0, 0x00]);
        yield return Row(CreateServiceModeRData(1, "resolver.example.", [CreateSvcParam(1, [0])]));
        yield return Row(CreateServiceModeRData(1, "resolver.example.", [CreateSvcParam(7, Encoding.UTF8.GetBytes("/dns-query{?dns}")), CreateSvcParam(1, [3, (byte)'d', (byte)'o', (byte)'q'])]));
        yield return Row(CreateServiceModeRData(1, "resolver.example.", [CreateSvcParam(1, [3, (byte)'d', (byte)'o'])]));
        yield return Row(CreateServiceModeRData(1, "resolver.example.", [CreateSvcParam(3, [0x35])]));
        yield return Row(CreateServiceModeRData(1, "resolver.example.", [CreateSvcParam(7, [])]));
    }

    private static object[] Row(byte[] rdata)
    {
        return [rdata];
    }

    private static byte[] CreateServiceModeRData(
        ushort priority,
        string targetName,
        IEnumerable<byte[]> svcParams)
    {
        List<byte> rdata = [];
        Span<byte> priorityBytes = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(priorityBytes, priority);
        rdata.AddRange(priorityBytes.ToArray());
        rdata.AddRange(EncodeDomainName(targetName));
        foreach (byte[] parameter in svcParams)
        {
            rdata.AddRange(parameter);
        }

        return [.. rdata];
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
        if (name == ".")
        {
            return [0];
        }

        List<byte> encoded = [];
        foreach (string label in name.TrimEnd('.').Split('.'))
        {
            encoded.Add(checked((byte)label.Length));
            encoded.AddRange(Encoding.ASCII.GetBytes(label));
        }

        encoded.Add(0);
        return [.. encoded];
    }
}
