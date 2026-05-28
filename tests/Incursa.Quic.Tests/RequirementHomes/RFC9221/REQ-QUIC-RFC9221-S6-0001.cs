// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S6-0001")]
public sealed class REQ_QUIC_RFC9221_S6_0001
{
    [Theory]
    [InlineData(QuicPacketFrameLegality.DatagramWithoutLengthFrameType)]
    [InlineData(QuicPacketFrameLegality.DatagramWithLengthFrameType)]
    [Requirement("REQ-QUIC-RFC9221-S6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramFrameTypes_AreForbiddenInWeaklyProtectedPackets(ulong frameType)
    {
        Assert.True(QuicPacketFrameLegality.IsHandshakePacketForbiddenFrameType(frameType));
    }
}
