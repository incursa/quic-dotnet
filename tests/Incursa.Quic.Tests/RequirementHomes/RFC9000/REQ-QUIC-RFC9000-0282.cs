// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0282")]
public sealed class REQ_QUIC_RFC9000_0282
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldSendVersionNegotiation_AllowsOmittingUndersizedDatagrams()
    {
        int undersizedDatagramLength = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1;
        byte[] undersizedDatagram =
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(undersizedDatagramLength);

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicS5P2P2ServerPreAcceptanceTestSupport.UnsupportedVersion,
            undersizedDatagramLength,
            QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions));
        Assert.Equal(
            QuicListenerPreAcceptanceDatagramAction.Drop,
            Classify(undersizedDatagram));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClassifyUnroutedDatagram_AnswersWhenDatagramMeetsTheVersionMinimum()
    {
        byte[] minimumSizedDatagram =
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(
                QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicS5P2P2ServerPreAcceptanceTestSupport.UnsupportedVersion,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions));
        Assert.Equal(
            QuicListenerPreAcceptanceDatagramAction.SendVersionNegotiation,
            Classify(minimumSizedDatagram));
    }

    private static QuicListenerPreAcceptanceDatagramAction Classify(byte[] datagram)
    {
        return QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
            datagram,
            QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
            retryBootstrapEnabled: false);
    }
}
