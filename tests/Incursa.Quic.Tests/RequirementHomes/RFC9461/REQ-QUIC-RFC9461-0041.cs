// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Incursa.Quic.Tests.RequirementHomes.RFC9461;

public sealed class REQ_QUIC_RFC9461_0041
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0041")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ParseResponseMessage_DecodesSvcbAnswersAndAdditionalAddresses()
    {
        byte[] message = CreateDnsResponse(
            questionName: "_853._dns.resolver.example.",
            answers:
            [
                CreateResourceRecord(
                    ownerName: "pointer:12",
                    type: DnsServiceBindingRecord.SvcbResourceRecordType,
                    rdata: CreateAliasModeRData("svc.example.")),
                CreateResourceRecord(
                    ownerName: "svc.example.",
                    type: DnsServiceBindingRecord.SvcbResourceRecordType,
                    rdata: CreateServiceModeRData("target.example.", [CreateSvcParam(1, [3, (byte)'d', (byte)'o', (byte)'q'])])),
            ],
            authorities: [],
            additionals:
            [
                CreateResourceRecord("svc.example.", 1, [192, 0, 2, 53]),
                CreateResourceRecord("svc.example.", 28, [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35]),
            ]);

        DnsServiceBindingResponseMessage parsed =
            DnsServiceBindingResponseMessage.Parse("resolver.example", message);

        DnsServiceBindingQuestion question = Assert.Single(parsed.Questions);
        Assert.Equal("_853._dns.resolver.example.", question.Name);
        Assert.Equal(DnsServiceBindingRecord.SvcbResourceRecordType, question.Type);

        DnsServiceBindingAliasRecord alias = Assert.Single(parsed.AliasRecords);
        Assert.Equal("_853._dns.resolver.example.", alias.OwnerName);
        Assert.Equal("svc.example.", alias.TargetName);

        DnsServiceBindingNamedRecord service = Assert.Single(parsed.ServiceRecords);
        Assert.Equal("svc.example.", service.OwnerName);
        Assert.Equal("target.example.", service.ServiceRecord.TargetName);

        Assert.Equal([IPAddress.Parse("192.0.2.53"), IPAddress.Parse("2001:db8::35")], parsed.AdditionalAddresses.Select(address => address.Address));

        DnsServiceBindingAliasResolution resolution = DnsServiceBindingAliasResolver.Resolve(
            question.Name,
            parsed.AliasRecords,
            parsed.ServiceRecords);
        Assert.True(resolution.Succeeded);

        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            resolution.ServiceRecords[0].ServiceRecord.ServiceBinding,
            DnsServiceBindingSelectionOptions.Create(["doq"])));
        Assert.Equal(DnsServiceBindingProtocol.DnsOverQuic, endpoint.Protocol);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9461-0041")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [MemberData(nameof(MalformedMessages))]
    public void ParseResponseMessage_RejectsMalformedTruncatedLoopingAndInvalidAddressData(byte[] message)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            DnsServiceBindingResponseMessage.Parse("resolver.example", message));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0041")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ParseResponseMessage_SkipsUnsupportedRecordsAndNonInternetAdditionalAddresses()
    {
        byte[] message = CreateDnsResponse(
            questionName: "_853._dns.resolver.example.",
            answers:
            [
                CreateResourceRecord("other.example.", 16, Encoding.ASCII.GetBytes("text")),
            ],
            authorities:
            [
                CreateResourceRecord("resolver.example.", 2, EncodeDomainName("ns.example.")),
            ],
            additionals:
            [
                CreateResourceRecord("svc.example.", 1, [192, 0, 2, 53], dnsClass: 255),
            ]);

        DnsServiceBindingResponseMessage parsed =
            DnsServiceBindingResponseMessage.Parse("resolver.example", message);

        Assert.Empty(parsed.AliasRecords);
        Assert.Empty(parsed.ServiceRecords);
        Assert.Empty(parsed.AdditionalAddresses);
    }

    public static IEnumerable<object[]> MalformedMessages()
    {
        yield return Row([0x00, 0x01, 0x81]);
        yield return Row(CreateDnsResponse(
            questionName: "_853._dns.resolver.example.",
            answers: [CreateResourceRecord("pointer:12", DnsServiceBindingRecord.SvcbResourceRecordType, [0x00])],
            authorities: [],
            additionals: []));
        yield return Row(CreateLoopingAnswerMessage());
        yield return Row(CreateDnsResponse(
            questionName: "_853._dns.resolver.example.",
            answers: [],
            authorities: [],
            additionals: [CreateResourceRecord("svc.example.", 1, [192, 0, 2])]));
    }

    private static object[] Row(byte[] message)
    {
        return [message];
    }

    private static byte[] CreateDnsResponse(
        string questionName,
        IReadOnlyList<byte[]> answers,
        IReadOnlyList<byte[]> authorities,
        IReadOnlyList<byte[]> additionals)
    {
        List<byte> message = [];
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..], checked((ushort)answers.Count));
        BinaryPrimitives.WriteUInt16BigEndian(header[8..], checked((ushort)authorities.Count));
        BinaryPrimitives.WriteUInt16BigEndian(header[10..], checked((ushort)additionals.Count));
        message.AddRange(header.ToArray());
        message.AddRange(EncodeDomainName(questionName));
        message.AddRange([0x00, 0x40, 0x00, 0x01]);
        foreach (byte[] answer in answers)
        {
            message.AddRange(answer);
        }

        foreach (byte[] authority in authorities)
        {
            message.AddRange(authority);
        }

        foreach (byte[] additional in additionals)
        {
            message.AddRange(additional);
        }

        return [.. message];
    }

    private static byte[] CreateLoopingAnswerMessage()
    {
        List<byte> message = [];
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..], 1);
        message.AddRange(header.ToArray());
        message.AddRange([0xC0, 0x0C]);
        message.AddRange([0x00, 0x40, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        return [.. message];
    }

    private static byte[] CreateResourceRecord(string ownerName, ushort type, byte[] rdata, ushort dnsClass = 1)
    {
        List<byte> record = [];
        if (ownerName.StartsWith("pointer:", StringComparison.Ordinal))
        {
            ushort pointer = ushort.Parse(ownerName["pointer:".Length..], System.Globalization.CultureInfo.InvariantCulture);
            record.Add(0xC0);
            record.Add(checked((byte)pointer));
        }
        else
        {
            record.AddRange(EncodeDomainName(ownerName));
        }

        Span<byte> trailer = stackalloc byte[10];
        BinaryPrimitives.WriteUInt16BigEndian(trailer, type);
        BinaryPrimitives.WriteUInt16BigEndian(trailer[2..], dnsClass);
        BinaryPrimitives.WriteUInt32BigEndian(trailer[4..], 60);
        BinaryPrimitives.WriteUInt16BigEndian(trailer[8..], checked((ushort)rdata.Length));
        record.AddRange(trailer.ToArray());
        record.AddRange(rdata);
        return [.. record];
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
