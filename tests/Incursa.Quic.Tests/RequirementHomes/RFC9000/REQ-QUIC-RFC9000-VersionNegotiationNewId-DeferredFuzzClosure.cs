// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_VersionNegotiationNewId_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0969")]
    [Requirement("REQ-QUIC-RFC9000-0976")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationUnusedBitsDoNotAffectDiscardOrPacketNumberSpace()
    {
        foreach (VersionNegotiationCase testCase in VersionNegotiationCases())
        {
            byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
                testCase.HeaderControlBits,
                testCase.DestinationConnectionId,
                testCase.SourceConnectionId,
                testCase.SupportedVersions);

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket parsed));
            Assert.Equal(testCase.HeaderControlBits, parsed.HeaderControlBits);
            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(packet, out _));

            bool discard = QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
                parsed,
                testCase.SelectedVersion,
                testCase.HasSuccessfullyProcessedAnotherPacket);

            byte[] normalizedPacket = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits: 0x40,
                testCase.DestinationConnectionId,
                testCase.SourceConnectionId,
                testCase.SupportedVersions);
            Assert.True(QuicPacketParser.TryParseVersionNegotiation(normalizedPacket, out QuicVersionNegotiationPacket normalized));
            Assert.Equal(discard, QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
                normalized,
                testCase.SelectedVersion,
                testCase.HasSuccessfullyProcessedAnotherPacket));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0972")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationResponseEchoesClientSourceConnectionIdAsDestinationConnectionId()
    {
        int checkedCases = 0;
        foreach (VersionNegotiationCase testCase in VersionNegotiationCases())
        {
            if (testCase.SupportedVersions.Contains(testCase.SelectedVersion))
            {
                continue;
            }

            byte[] destination = new byte[128];

            Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                testCase.SelectedVersion,
                testCase.DestinationConnectionId,
                testCase.SourceConnectionId,
                testCase.SupportedVersions,
                destination,
                out int bytesWritten));
            Assert.True(QuicPacketParser.TryParseVersionNegotiation(
                destination.AsSpan(0, bytesWritten),
                out QuicVersionNegotiationPacket parsed));

            Assert.True(testCase.SourceConnectionId.AsSpan().SequenceEqual(parsed.DestinationConnectionId));
            Assert.True(testCase.DestinationConnectionId.AsSpan().SequenceEqual(parsed.SourceConnectionId));
            checkedCases++;
        }

        Assert.True(checkedCases > 0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0980")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiationSendPolicySendsAtMostOneResponseForOneDatagram()
    {
        foreach (VersionNegotiationCase testCase in VersionNegotiationCases())
        {
            bool firstResponse = QuicVersionNegotiation.ShouldSendVersionNegotiation(
                testCase.SelectedVersion,
                testCase.SupportedVersions,
                hasAlreadySentVersionNegotiation: false);
            bool repeatedResponse = QuicVersionNegotiation.ShouldSendVersionNegotiation(
                testCase.SelectedVersion,
                testCase.SupportedVersions,
                hasAlreadySentVersionNegotiation: true);

            Assert.Equal(!testCase.SupportedVersions.Contains(testCase.SelectedVersion), firstResponse);
            Assert.False(repeatedResponse);
        }
    }

    private static IEnumerable<VersionNegotiationCase> VersionNegotiationCases()
    {
        yield return new VersionNegotiationCase(0x40, [0xD0], [0x50], 0x1122_3344, [QuicVersionNegotiation.Version1], false);
        yield return new VersionNegotiationCase(0x7F, [0xD0, 0xD1], [0x50, 0x51], QuicVersionNegotiation.Version1, [QuicVersionNegotiation.Version1], false);
        yield return new VersionNegotiationCase(0x00, [], [], 0xAABB_CCDD, [QuicVersionNegotiation.Version1, 0x2233_4455], true);

        Random random = new(0x6000);
        for (int i = 0; i < 64; i++)
        {
            uint selectedVersion = i % 3 == 0 ? QuicVersionNegotiation.Version1 : (uint)random.Next();
            uint alternativeVersion = selectedVersion == QuicVersionNegotiation.Version1
                ? 0x1122_3344
                : QuicVersionNegotiation.Version1;
            uint[] supportedVersions = i % 2 == 0
                ? [QuicVersionNegotiation.Version1, alternativeVersion]
                : [alternativeVersion];

            yield return new VersionNegotiationCase(
                HeaderControlBits: (byte)random.Next(0, 0x80),
                DestinationConnectionId: QuicHeaderTestData.RandomBytes(random, random.Next(0, 21)),
                SourceConnectionId: QuicHeaderTestData.RandomBytes(random, random.Next(0, 21)),
                SelectedVersion: selectedVersion,
                SupportedVersions: supportedVersions,
                HasSuccessfullyProcessedAnotherPacket: i % 5 == 0);
        }
    }

    private sealed record VersionNegotiationCase(
        byte HeaderControlBits,
        byte[] DestinationConnectionId,
        byte[] SourceConnectionId,
        uint SelectedVersion,
        uint[] SupportedVersions,
        bool HasSuccessfullyProcessedAnotherPacket);
}
