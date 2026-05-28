// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
public sealed class REQ_QUIC_RFC9000_S19P15_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_PreservesTheAssociatedStatelessResetToken()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(8);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            0x06,
            0x04,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            expectedSequenceNumber: 0x06,
            expectedRetirePriorTo: 0x04,
            connectionId,
            statelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsFramesMissingTheStatelessResetToken()
    {
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            0x06,
            0x04,
            QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(8),
            QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken()[..15]);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatNewConnectionIdFrame_WritesTheStatelessResetTokenAfterTheConnectionId()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(8);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        Span<byte> destination = stackalloc byte[64];

        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, destination, out int bytesWritten));
        ReadOnlySpan<byte> encoded = destination[..bytesWritten];
        int tokenOffset = encoded.Length - QuicS19P15NewConnectionIdFrameTestSupport.StatelessResetTokenLength;
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(encoded[tokenOffset..]));
    }
}
