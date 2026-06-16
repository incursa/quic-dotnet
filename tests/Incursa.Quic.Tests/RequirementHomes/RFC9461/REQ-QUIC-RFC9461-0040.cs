// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Text;

namespace Incursa.Quic.Tests.RequirementHomes.RFC9461;

public sealed class REQ_QUIC_RFC9461_0040
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0040")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResolveAliasModeChain_ReturnsServiceModeRecordsAtTheFinalTarget()
    {
        DnsServiceBindingAliasRecord firstAlias = DnsServiceBindingAliasRecord.ParseAliasModeRData(
            "_853._dns.resolver.example.",
            CreateAliasModeRData("alias-a.example."));
        DnsServiceBindingAliasRecord secondAlias = DnsServiceBindingAliasRecord.Create(
            "alias-a.example.",
            "svc.example.");
        DnsServiceBindingNamedRecord serviceRecord = DnsServiceBindingNamedRecord.Create(
            "svc.example.",
            ParseServiceModeRecord("resolver.example", "svc-target.example.", ["doq"]));

        DnsServiceBindingAliasResolution resolution = DnsServiceBindingAliasResolver.Resolve(
            "_853._dns.resolver.example.",
            [firstAlias, secondAlias],
            [serviceRecord]);

        Assert.True(resolution.Succeeded);
        Assert.Equal(DnsServiceBindingAliasResolutionStatus.Succeeded, resolution.Status);
        Assert.Equal("svc.example.", resolution.ResolvedName);
        Assert.Equal(["_853._dns.resolver.example.", "alias-a.example."], resolution.AliasChain);
        Assert.Same(serviceRecord, Assert.Single(resolution.ServiceRecords));

        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            resolution.ServiceRecords[0].ServiceRecord.ServiceBinding,
            DnsServiceBindingSelectionOptions.Create(["doq"])));
        Assert.Equal(DnsServiceBindingProtocol.DnsOverQuic, endpoint.Protocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0040")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResolveAliasModeChain_DetectsLoopsAndMissingTargets()
    {
        DnsServiceBindingAliasResolution loop = DnsServiceBindingAliasResolver.Resolve(
            "_853._dns.resolver.example.",
            [
                DnsServiceBindingAliasRecord.Create("_853._dns.resolver.example.", "alias-a.example."),
                DnsServiceBindingAliasRecord.Create("alias-a.example.", "_853._dns.resolver.example."),
            ],
            []);

        Assert.Equal(DnsServiceBindingAliasResolutionStatus.AliasLoop, loop.Status);
        Assert.Equal("_853._dns.resolver.example.", loop.ResolvedName);

        DnsServiceBindingAliasResolution missing = DnsServiceBindingAliasResolver.Resolve(
            "_853._dns.resolver.example.",
            [DnsServiceBindingAliasRecord.Create("_853._dns.resolver.example.", "missing.example.")],
            []);

        Assert.Equal(DnsServiceBindingAliasResolutionStatus.MissingTarget, missing.Status);
        Assert.Equal("missing.example.", missing.ResolvedName);
        Assert.Empty(missing.ServiceRecords);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9461-0040")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [MemberData(nameof(MalformedAliasModeRData))]
    public void ParseAliasModeRData_RejectsMalformedServiceModeCompressedAndParamBearingData(byte[] rdata)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            DnsServiceBindingAliasRecord.ParseAliasModeRData("_853._dns.resolver.example.", rdata));
    }

    public static IEnumerable<object[]> MalformedAliasModeRData()
    {
        yield return Row([]);
        yield return Row([0x00, 0x00]);
        yield return Row(CreateServiceModeRData("target.example.", []));
        yield return Row([0x00, 0x00, 0xC0, 0x00]);
        yield return Row([.. CreateAliasModeRData("target.example."), 0x00, 0x01, 0x00, 0x00]);
    }

    private static object[] Row(byte[] rdata)
    {
        return [rdata];
    }

    private static DnsServiceBindingWireRecord ParseServiceModeRecord(
        string authenticationName,
        string targetName,
        IEnumerable<string> alpnProtocols)
    {
        List<byte> alpnValue = [];
        foreach (string alpnProtocol in alpnProtocols)
        {
            byte[] encoded = Encoding.ASCII.GetBytes(alpnProtocol);
            alpnValue.Add(checked((byte)encoded.Length));
            alpnValue.AddRange(encoded);
        }

        return DnsServiceBindingWireRecord.ParseServiceModeRData(
            authenticationName,
            CreateServiceModeRData(targetName, [CreateSvcParam(1, [.. alpnValue])]));
    }

    private static byte[] CreateAliasModeRData(string targetName)
    {
        List<byte> rdata = [];
        Span<byte> priorityBytes = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(priorityBytes, 0);
        rdata.AddRange(priorityBytes.ToArray());
        rdata.AddRange(EncodeDomainName(targetName));
        return [.. rdata];
    }

    private static byte[] CreateServiceModeRData(string targetName, IEnumerable<byte[]> svcParams)
    {
        List<byte> rdata = [];
        Span<byte> priorityBytes = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(priorityBytes, 1);
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
