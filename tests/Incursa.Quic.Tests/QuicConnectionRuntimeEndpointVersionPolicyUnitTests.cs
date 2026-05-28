// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeEndpointVersionPolicyUnitTests
{
    [Fact]
    public void ReceiveDatagram_RejectsVersion1InitialPacketsBelowTheMinimumPayloadSize()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], []));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(packet, new QuicConnectionPathIdentity("127.0.0.1"));

        Assert.Equal(QuicConnectionIngressDisposition.Malformed, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }

    [Fact]
    public void ReceiveDatagram_DoesNotApplyTheVersion1InitialFloorToNonVersion1LongHeaders()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 0x11223344,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x01]);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(packet, new QuicConnectionPathIdentity("127.0.0.1"));

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }

    [Fact]
    public void ReceiveDatagram_RoutesShortHeaderPacketsWithClearedFixedBit()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.123");
        byte[] routeId = [0x10, 0x11];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [.. routeId, 0x99]);
        packet[0] = (byte)(packet[0] & ~QuicPacketHeaderBits.FixedBitMask);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(packet, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
    }
}
