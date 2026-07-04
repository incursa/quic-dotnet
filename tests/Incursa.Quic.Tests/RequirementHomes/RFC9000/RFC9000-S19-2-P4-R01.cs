// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-2-P4-R01")]
public sealed class RFC9000_S19_2_P4_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPingFrame_ProducesAckElicitingKeepAliveProbe()
    {
        Span<byte> destination = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.Equal((byte)0x01, destination[0]);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(destination[0]));

        Assert.True(QuicFrameCodec.TryParsePingFrame(destination[..bytesWritten], out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
    }
}
