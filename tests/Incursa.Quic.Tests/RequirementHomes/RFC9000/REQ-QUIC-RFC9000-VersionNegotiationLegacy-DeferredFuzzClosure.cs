// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_VersionNegotiationLegacy_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0271")]
    [Requirement("REQ-QUIC-RFC9000-0280")]
    [Requirement("REQ-QUIC-RFC9000-0282")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreAcceptanceVersionNegotiationFuzz_ClassifiesInitialDatagramsByVersionAndSize()
    {
        int minimum = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;
        foreach (int datagramLength in new[] { minimum - 2, minimum - 1, minimum, minimum + 1 })
        {
            byte[] unsupportedDatagram =
                QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(datagramLength);
            byte[] supportedDatagram =
                QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1InitialDatagram(datagramLength);

            QuicListenerPreAcceptanceDatagramAction unsupportedAction = Classify(unsupportedDatagram);
            QuicListenerPreAcceptanceDatagramAction supportedAction = Classify(supportedDatagram);

            if (datagramLength < minimum)
            {
                Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, unsupportedAction);
                Assert.Equal(QuicListenerPreAcceptanceDatagramAction.SendProtocolViolationClose, supportedAction);
                Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                    QuicS5P2P2ServerPreAcceptanceTestSupport.UnsupportedVersion,
                    datagramLength,
                    QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions));
            }
            else
            {
                Assert.Equal(QuicListenerPreAcceptanceDatagramAction.SendVersionNegotiation, unsupportedAction);
                Assert.Equal(QuicListenerPreAcceptanceDatagramAction.AdmitInitial, supportedAction);
                Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                    QuicS5P2P2ServerPreAcceptanceTestSupport.UnsupportedVersion,
                    datagramLength,
                    QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions));
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0277")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DisableActiveMigrationTransportParameterFuzz_RoundTripsOnlyWhenAdvertised()
    {
        foreach (bool disableActiveMigration in new[] { false, true })
        {
            QuicTransportParameters parameters = new()
            {
                DisableActiveMigration = disableActiveMigration,
                MaxIdleTimeout = disableActiveMigration ? null : 30UL,
            };
            byte[] destination = new byte[16];

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Server,
                destination,
                out int bytesWritten));
            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination.AsSpan(0, bytesWritten),
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsed));

            Assert.Equal(disableActiveMigration, parsed.DisableActiveMigration);
            if (!disableActiveMigration)
            {
                Assert.Equal(30UL, parsed.MaxIdleTimeout);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0281")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitialDatagramPaddingFuzz_SizesClientInitialDatagramsToTheLargestKnownMinimum()
    {
        int minimum = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;
        foreach (int currentLength in new[] { 0, 1, 63, 64, minimum - 1, minimum, minimum + 1 })
        {
            Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(currentLength, out int paddingLength));
            int expectedPaddingLength = Math.Max(0, minimum - currentLength);
            Assert.Equal(expectedPaddingLength, paddingLength);

            byte[] destination = new byte[paddingLength];
            bool formatted = QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
                currentLength,
                destination,
                out int bytesWritten);

            Assert.True(formatted);
            Assert.Equal(paddingLength, bytesWritten);
            Assert.All(destination, value => Assert.Equal(0x00, value));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0283")]
    [Requirement("REQ-QUIC-RFC9000-0284")]
    [Requirement("REQ-QUIC-RFC9000-0285")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void VersionNegotiationResponseFuzz_IncludesAcceptedVersionsAndNeverAnswersVersionNegotiation()
    {
        uint[] supportedVersions = [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2, 0x1A2A3A4A];
        byte[][] connectionIds =
        [
            [],
            [0x11],
            [0x21, 0x22, 0x23, 0x24],
        ];

        foreach (byte[] clientDestinationConnectionId in connectionIds)
        {
            foreach (byte[] clientSourceConnectionId in connectionIds)
            {
                byte[] destination = new byte[128];
                Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                    0xAABBCCDD,
                    clientDestinationConnectionId,
                    clientSourceConnectionId,
                    supportedVersions,
                    destination,
                    out int bytesWritten));

                Assert.True(QuicPacketParser.TryParseVersionNegotiation(
                    destination.AsSpan(0, bytesWritten),
                    out QuicVersionNegotiationPacket packet));
                Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
                Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
                Assert.Equal(supportedVersions.Length, packet.SupportedVersionCount);
                foreach (uint supportedVersion in supportedVersions)
                {
                    Assert.True(packet.ContainsSupportedVersion(supportedVersion));
                }
            }
        }

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            supportedVersions));
        Assert.False(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            QuicVersionNegotiation.VersionNegotiationVersion,
            clientDestinationConnectionId: [0x01],
            clientSourceConnectionId: [0x02],
            supportedVersions,
            new byte[64],
            out _));
    }

    private static QuicListenerPreAcceptanceDatagramAction Classify(byte[] datagram)
    {
        return QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
            datagram,
            QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
            retryBootstrapEnabled: false);
    }
}
