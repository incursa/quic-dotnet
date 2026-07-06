// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-2-2-P1-S3-R01")]
public sealed class REQ_QUIC_RFC9000_0267
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClassifyUnroutedDatagram_DropsUndersizedUnsupportedVersionPackets()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1);

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
    public void ClassifyUnroutedDatagram_DoesNotDropLargeUnsupportedVersionPacketsBeforeNegotiation()
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
    [Requirement("RFC9000-S5-2-2-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClassifyUnroutedDatagramFuzz_DropsUndersizedUnsupportedVersionPackets()
    {
        int[] undersizedPayloadSizes =
        [
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 256,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 128,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 2,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1,
        ];

        foreach (int undersizedPayloadSize in undersizedPayloadSizes)
        {
            byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(
                undersizedPayloadSize);

            QuicListenerPreAcceptanceDatagramAction action =
                QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                    datagram,
                    QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                    retryBootstrapEnabled: false);

            Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, action);
        }
    }
}
