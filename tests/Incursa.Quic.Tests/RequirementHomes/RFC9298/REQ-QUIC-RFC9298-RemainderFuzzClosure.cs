// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_RemainderFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamReferenceMeansEntireConnectionWithoutMultiplexedStreams()
    {
        Assert.Equal(
            Http3ConnectUdpStreamReferenceScope.EntireConnection,
            Http3ConnectUdpConversionPolicy.GetStreamReferenceScope(httpVersionSupportsMultiplexingStreams: false));
        Assert.Equal(
            Http3ConnectUdpStreamReferenceScope.RequestStream,
            Http3ConnectUdpConversionPolicy.GetStreamReferenceScope(httpVersionSupportsMultiplexingStreams: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpTunnelsUseSectionFiveHttpDatagramFormat()
    {
        foreach ((byte[] payload, ulong streamId) in new[]
        {
            (Array.Empty<byte>(), 0UL),
            ("payload"u8.ToArray(), 4UL),
            (new byte[] { 0xCA, 0xFE, 0x00, 0x01 }, 12UL),
        })
        {
            Http3Datagram datagram = Http3ConnectUdpConversionPolicy.ConvertUdpPacketToHttpDatagram(
                payload,
                streamId,
                tunnelClosed: false);
            Http3ConnectUdpDatagram connectUdpDatagram = Http3ConnectUdpDatagram.ParseFromHttp3Datagram(datagram);

            Assert.Equal(Http3ConnectUdpDatagram.UdpPayloadContextId, connectUdpDatagram.ContextId);
            Assert.Equal(payload, connectUdpDatagram.Payload);
            Assert.Equal(payload, Http3ConnectUdpConversionPolicy.ConvertHttpDatagramToUdpPacket(datagram, tunnelClosed: false));
        }

        Http3Datagram nonUdpPayload = new Http3ConnectUdpDatagram(contextId: 2, [0xAA]).ToHttp3Datagram(associatedStreamId: 0);
        AssertDatagramError(() => Http3ConnectUdpConversionPolicy.ConvertHttpDatagramToUdpPacket(nonUdpPayload, tunnelClosed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyConvertsDatagramsAndUdpPacketsUntilTunnelCloses()
    {
        Assert.True(Http3ConnectUdpConversionPolicy.ShouldConvertDatagramsAndUdpPackets(requestSuccessful: true, tunnelClosed: false));
        Assert.False(Http3ConnectUdpConversionPolicy.ShouldConvertDatagramsAndUdpPackets(requestSuccessful: false, tunnelClosed: false));
        Assert.False(Http3ConnectUdpConversionPolicy.ShouldConvertDatagramsAndUdpPackets(requestSuccessful: true, tunnelClosed: true));

        Http3Datagram datagram = Http3ConnectUdpConversionPolicy.ConvertUdpPacketToHttpDatagram("client-packet"u8, associatedStreamId: 0, tunnelClosed: false);

        Assert.Equal("client-packet"u8.ToArray(), Http3ConnectUdpConversionPolicy.ConvertHttpDatagramToUdpPacket(datagram, tunnelClosed: false));
        AssertDatagramError(() => Http3ConnectUdpConversionPolicy.ConvertUdpPacketToHttpDatagram("late"u8, associatedStreamId: 0, tunnelClosed: true));
        AssertDatagramError(() => Http3ConnectUdpConversionPolicy.ConvertHttpDatagramToUdpPacket(datagram, tunnelClosed: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0096")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EarlyDatagramsAreDroppedOrBufferedBeforeRequest()
    {
        Assert.Equal(
            Http3ConnectUdpEarlyDatagramAction.DropSilently,
            Http3ConnectUdpEarlyDatagramPolicy.ClassifyEarlyDatagram(correspondingRequestKnown: false, temporaryBufferAvailable: false));
        Assert.Equal(
            Http3ConnectUdpEarlyDatagramAction.BufferTemporarily,
            Http3ConnectUdpEarlyDatagramPolicy.ClassifyEarlyDatagram(correspondingRequestKnown: false, temporaryBufferAvailable: true));
        Assert.Equal(
            Http3ConnectUdpEarlyDatagramAction.Process,
            Http3ConnectUdpEarlyDatagramPolicy.ClassifyEarlyDatagram(correspondingRequestKnown: true, temporaryBufferAvailable: false));
        Assert.Equal(
            Http3ConnectUdpEarlyDatagramAction.Process,
            Http3ConnectUdpEarlyDatagramPolicy.ClassifyEarlyDatagram(correspondingRequestKnown: true, temporaryBufferAvailable: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0097")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_BufferedEarlyDatagramsApplyBufferingLimits()
    {
        Assert.True(Http3ConnectUdpEarlyDatagramPolicy.ShouldApplyBufferingLimits(bufferingEarlyDatagrams: true));
        Assert.False(Http3ConnectUdpEarlyDatagramPolicy.ShouldApplyBufferingLimits(bufferingEarlyDatagrams: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0098")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientMaySendOptimisticDatagramsBeforeResponse()
    {
        Assert.True(Http3ConnectUdpEarlyDatagramPolicy.ClientMaySendOptimisticDatagramsBeforeResponse);
        Assert.Equal(
            Http3ConnectUdpEarlyDatagramAction.BufferTemporarily,
            Http3ConnectUdpEarlyDatagramPolicy.ClassifyEarlyDatagram(correspondingRequestKnown: false, temporaryBufferAvailable: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0116")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyDisallowsUdpProxyingToVulnerableTargets()
    {
        foreach (IPAddress address in new[]
        {
            IPAddress.Parse("127.0.0.1"),
            IPAddress.IPv6Loopback,
            IPAddress.Parse("169.254.10.20"),
            IPAddress.Parse("fe80::1"),
            IPAddress.Parse("224.0.0.1"),
            IPAddress.Parse("ff02::1"),
            IPAddress.Broadcast,
            IPAddress.Any,
            IPAddress.IPv6Any,
        })
        {
            Assert.True(Http3ConnectUdpTargetPolicy.IsVulnerableTarget(address));
        }

        IPAddress proxyAddress = IPAddress.Parse("192.0.2.10");
        Assert.True(Http3ConnectUdpTargetPolicy.IsVulnerableTarget(proxyAddress, [proxyAddress]));
        Assert.False(Http3ConnectUdpTargetPolicy.IsVulnerableTarget(IPAddress.Parse("192.0.2.55"), [proxyAddress]));
        Assert.False(Http3ConnectUdpTargetPolicy.IsVulnerableTarget(IPAddress.Parse("2001:db8::55"), [proxyAddress]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0117")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyMayUseDestinationIpProhibitedProxyStatus()
    {
        QPackFieldLine header = Http3ConnectUdpTargetPolicy.CreateDestinationIpProhibitedProxyStatusHeader();
        IReadOnlyList<QPackFieldLine> setupErrorHeaders = Http3ConnectUdpTunnelSetupPolicy.BuildSetupErrorResponseHeaders(
            Http3ConnectUdpTargetPolicy.DestinationIpProhibitedErrorType);

        Assert.Equal("proxy-status", header.Name);
        Assert.Equal($"error={Http3ConnectUdpTargetPolicy.DestinationIpProhibitedErrorType}", header.Value);
        Assert.Contains(setupErrorHeaders, value => value.Name == "proxy-status" && value.Value == header.Value);
        Assert.DoesNotContain("connection_timeout", header.Value, StringComparison.Ordinal);
    }

    private static void AssertDatagramError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }
}
