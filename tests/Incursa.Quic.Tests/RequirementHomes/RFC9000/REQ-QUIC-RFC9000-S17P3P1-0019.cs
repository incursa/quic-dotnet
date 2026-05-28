// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0019")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_ExposesTheKeyPhaseBit()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x04, [0xA1, 0xA2]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(header.KeyPhase);
    }
}
