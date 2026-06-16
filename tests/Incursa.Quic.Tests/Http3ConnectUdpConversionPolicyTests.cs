// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpConversionPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConversionPolicy_UsesEntireConnectionScopeWhenHttpVersionDoesNotMultiplexStreams()
    {
        Assert.Equal(
            Http3ConnectUdpStreamReferenceScope.EntireConnection,
            Http3ConnectUdpConversionPolicy.GetStreamReferenceScope(httpVersionSupportsMultiplexingStreams: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConversionPolicy_UsesRequestStreamScopeWhenHttpVersionMultiplexesStreams()
    {
        Assert.Equal(
            Http3ConnectUdpStreamReferenceScope.RequestStream,
            Http3ConnectUdpConversionPolicy.GetStreamReferenceScope(httpVersionSupportsMultiplexingStreams: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0021")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConversionPolicy_EncodesUdpPayloadsUsingSectionFiveHttpDatagramFormat()
    {
        Http3Datagram datagram = Http3ConnectUdpConversionPolicy.ConvertUdpPacketToHttpDatagram(
            "payload"u8,
            associatedStreamId: 0,
            tunnelClosed: false);
        Http3ConnectUdpDatagram connectUdpDatagram = Http3ConnectUdpDatagram.ParseFromHttp3Datagram(datagram);

        Assert.Equal(Http3ConnectUdpDatagram.UdpPayloadContextId, connectUdpDatagram.ContextId);
        Assert.Equal("payload"u8.ToArray(), connectUdpDatagram.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0021")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConversionPolicy_RejectsNonUdpPayloadContextIdsForSectionFiveUdpPackets()
    {
        Http3Datagram datagram = new Http3ConnectUdpDatagram(contextId: 2, "payload"u8.ToArray()).ToHttp3Datagram(associatedStreamId: 0);

        Assert.Throws<Http3Exception>(() => Http3ConnectUdpConversionPolicy.ConvertHttpDatagramToUdpPacket(datagram, tunnelClosed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0033")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConversionPolicy_ConvertsHttpDatagramsAndUdpPacketsWhileTunnelIsOpen()
    {
        Http3Datagram datagram = Http3ConnectUdpConversionPolicy.ConvertUdpPacketToHttpDatagram(
            "client-packet"u8,
            associatedStreamId: 0,
            tunnelClosed: false);
        byte[] udpPacket = Http3ConnectUdpConversionPolicy.ConvertHttpDatagramToUdpPacket(datagram, tunnelClosed: false);

        Assert.True(Http3ConnectUdpConversionPolicy.ShouldConvertDatagramsAndUdpPackets(requestSuccessful: true, tunnelClosed: false));
        Assert.Equal("client-packet"u8.ToArray(), udpPacket);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0033")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConversionPolicy_StopsConvertingAfterTunnelCloses()
    {
        Assert.False(Http3ConnectUdpConversionPolicy.ShouldConvertDatagramsAndUdpPackets(requestSuccessful: true, tunnelClosed: true));
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpConversionPolicy.ConvertUdpPacketToHttpDatagram(
            "client-packet"u8,
            associatedStreamId: 0,
            tunnelClosed: true));
    }
}
