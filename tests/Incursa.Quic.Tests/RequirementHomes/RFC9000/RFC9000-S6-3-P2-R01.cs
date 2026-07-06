// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S6-3-P2-R01")]
public sealed class REQ_QUIC_RFC9000_6321
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S6-3-P2-R01">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S6-3-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void IsReservedVersion_UsesTheReservedPattern()
    {
        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304));
        Assert.Equal((uint)0x0A1A2A3A, QuicVersionNegotiation.CreateReservedVersion(0x00112233));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S6-3-P2-R01">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S6-3-P2-R01")]
    public void ShouldDiscardVersionNegotiation_IgnoresReservedVersionAdvertisements()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);
        byte[] packet = new byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            QuicVersionNegotiation.Version1,
            [0x10, 0x11],
            [0x20],
            [reservedVersion],
            packet,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            packet.AsSpan(0, bytesWritten),
            out QuicVersionNegotiationPacket parsed));
        Assert.True(parsed.ContainsSupportedVersion(reservedVersion));
        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
            parsed,
            QuicVersionNegotiation.Version1,
            hasSuccessfullyProcessedAnotherPacket: false));
        Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            parsed,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReservedVersionAdvertisementFuzz_AllowsReservedVersionsInIgnoredVersionFields()
    {
        uint[] templates =
        [
            0x00000000,
            0x00112233,
            0x10203040,
            0x7fff0001,
            0xf0e0d0c0,
        ];

        for (int index = 0; index < templates.Length; index++)
        {
            uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(templates[index]);
            uint ordinaryUnsupportedVersion = (uint)(0x11223344 + index);
            byte[] packet = new byte[96];

            Assert.True(QuicVersionNegotiation.IsReservedVersion(reservedVersion));
            Assert.False(QuicVersionNegotiation.IsReservedVersion(ordinaryUnsupportedVersion));
            Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                QuicVersionNegotiation.Version1,
                [(byte)(0x10 + index), 0x11],
                [0x20, (byte)(0x21 + index)],
                [ordinaryUnsupportedVersion, reservedVersion],
                packet,
                out int bytesWritten));

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(
                packet.AsSpan(0, bytesWritten),
                out QuicVersionNegotiationPacket parsed));
            Assert.True(parsed.ContainsSupportedVersion(ordinaryUnsupportedVersion));
            Assert.True(parsed.ContainsSupportedVersion(reservedVersion));
            Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
                parsed,
                QuicVersionNegotiation.Version1,
                hasSuccessfullyProcessedAnotherPacket: false));
        }
    }
}
