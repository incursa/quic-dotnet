// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0280")]
public sealed class REQ_QUIC_RFC9000_0280
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClassifyUnroutedDatagram_AnswersEachEligibleNewConnectionAttemptWithVersionNegotiation()
    {
        byte[] firstDatagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
        byte[] secondDatagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        Assert.Equal(
            QuicListenerPreAcceptanceDatagramAction.SendVersionNegotiation,
            Classify(firstDatagram));
        Assert.Equal(
            QuicListenerPreAcceptanceDatagramAction.SendVersionNegotiation,
            Classify(secondDatagram));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClassifyUnroutedDatagram_DoesNotAnswerPacketsThatCannotInitiateNewConnections()
    {
        byte[] shortHeaderDatagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram();
        byte[] supportedInitialDatagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1InitialDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        Assert.Equal(
            QuicListenerPreAcceptanceDatagramAction.Drop,
            Classify(shortHeaderDatagram));
        Assert.Equal(
            QuicListenerPreAcceptanceDatagramAction.AdmitInitial,
            Classify(supportedInitialDatagram));
    }

    private static QuicListenerPreAcceptanceDatagramAction Classify(byte[] datagram)
    {
        return QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
            datagram,
            QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
            retryBootstrapEnabled: false);
    }
}
