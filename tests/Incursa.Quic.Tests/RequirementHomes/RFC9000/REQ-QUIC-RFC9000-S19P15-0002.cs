// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
public sealed class REQ_QUIC_RFC9000_S19P15_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewConnectionIdFrame_EncodesType18AsASingleByteVarint()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        Span<byte> destination = stackalloc byte[64];

        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, destination, out int bytesWritten));
        Assert.True(bytesWritten > 0);
        Assert.Equal([QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType], destination[..1].ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsDifferentFrameType()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            0x06,
            0x04,
            connectionId,
            statelessResetToken);
        encoded[0] = 0x19;

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewConnectionIdFrame_RejectsNonMinimalEncodedType18()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrameWithEncodedType(
            encodedTypeLength: 2,
            sequenceNumber: 0x06,
            retirePriorTo: 0x04,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }
}
