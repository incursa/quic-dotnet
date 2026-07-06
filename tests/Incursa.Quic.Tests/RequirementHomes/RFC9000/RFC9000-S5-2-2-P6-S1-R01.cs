// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-2-2-P6-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0273
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClassifyUnroutedDatagram_BuffersZeroRttWhenThePreInitialBufferHasCapacity()
    {
        byte[] datagram = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            destinationConnectionId: [0xD0, 0xD1],
            sourceConnectionId: [0xE0, 0xE1]);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false,
                maximumBufferedZeroRttDatagramsPerConnection: 2);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.BufferZeroRtt, action);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClassifyUnroutedDatagram_DropsZeroRttWhenThePreInitialBufferIsDisabled()
    {
        byte[] datagram = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            destinationConnectionId: [0xD2, 0xD3],
            sourceConnectionId: [0xE2, 0xE3]);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false,
                maximumBufferedZeroRttDatagramsPerConnection: 0);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, action);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ZeroRttPreInitialBuffer_EnforcesThePerConnectionLimitAndDrainsForTheLateInitial()
    {
        byte[] initialDestinationConnectionId = [0xC1, 0xC2, 0xC3, 0xC4];
        byte[] firstDatagram = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            destinationConnectionId: initialDestinationConnectionId,
            sourceConnectionId: [0xF1]);
        byte[] secondDatagram = QuicS17P2P3TestSupport.BuildZeroRttPacket(
            destinationConnectionId: initialDestinationConnectionId,
            sourceConnectionId: [0xF2]);
        QuicConnectionPathIdentity pathIdentity = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity();
        QuicListenerZeroRttPreInitialBuffer buffer = new(maximumDatagramsPerConnection: 1);

        Assert.True(buffer.TryBuffer(initialDestinationConnectionId, firstDatagram, pathIdentity));
        Assert.False(buffer.TryBuffer(initialDestinationConnectionId, secondDatagram, pathIdentity));
        Assert.Equal(1, buffer.CountForConnectionId(initialDestinationConnectionId));

        QuicListenerBufferedZeroRttDatagram[] drained = buffer.Drain(initialDestinationConnectionId);

        QuicListenerBufferedZeroRttDatagram bufferedDatagram = Assert.Single(drained);
        Assert.True(firstDatagram.AsSpan().SequenceEqual(bufferedDatagram.Datagram.Span));
        Assert.Equal(pathIdentity, bufferedDatagram.PathIdentity);
        Assert.Equal(0, buffer.CountForConnectionId(initialDestinationConnectionId));
        Assert.Empty(buffer.Drain(initialDestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClassifyUnroutedDatagramFuzz_BuffersOnlyWithinTheConfiguredZeroRttLimit()
    {
        (byte[] DestinationConnectionId, int Limit, QuicListenerPreAcceptanceDatagramAction ExpectedAction)[] cases =
        [
            ([0xA0], 1, QuicListenerPreAcceptanceDatagramAction.BufferZeroRtt),
            ([0xA1, 0xA2], 2, QuicListenerPreAcceptanceDatagramAction.BufferZeroRtt),
            ([0xA3, 0xA4, 0xA5, 0xA6], 0, QuicListenerPreAcceptanceDatagramAction.Drop),
            ([0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE], -1, QuicListenerPreAcceptanceDatagramAction.Drop),
        ];

        foreach ((byte[] destinationConnectionId, int limit, QuicListenerPreAcceptanceDatagramAction expectedAction) in cases)
        {
            byte[] datagram = QuicS17P2P3TestSupport.BuildZeroRttPacket(
                destinationConnectionId: destinationConnectionId,
                sourceConnectionId: [0xB0, 0xB1]);

            QuicListenerPreAcceptanceDatagramAction action =
                QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                    datagram,
                    QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                    retryBootstrapEnabled: false,
                    maximumBufferedZeroRttDatagramsPerConnection: limit);

            Assert.Equal(expectedAction, action);
        }
    }
}
