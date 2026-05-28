// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0275")]
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
}
