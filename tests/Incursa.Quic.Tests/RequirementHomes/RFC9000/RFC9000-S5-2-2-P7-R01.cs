// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-2-2-P7-R01")]
public sealed class REQ_QUIC_RFC9000_0275
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClassifyUnroutedDatagram_DropsShortHeaderPacketsThatDoNotMatchAConnection()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram([0x90, 0x91]);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, action);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClassifyUnroutedDatagram_DoesNotDropEligibleUnsupportedVersionInitialPackets()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.SendVersionNegotiation, action);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClassifyUnroutedDatagramFuzz_DropsUnmatchedShortHeaderPackets()
    {
        byte[][] destinationConnectionIds =
        [
            [0x01],
            [0x02, 0x03],
            [0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
        ];

        foreach (byte[] destinationConnectionId in destinationConnectionIds)
        {
            byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram(destinationConnectionId);

            QuicListenerPreAcceptanceDatagramAction action =
                QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                    datagram,
                    QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                    retryBootstrapEnabled: false);

            Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, action);
        }
    }
}
