// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
public sealed class REQ_QUIC_RFC9000_S19P15_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_ParsesAndFormatsTheEncodedFields()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            frame.SequenceNumber,
            frame.RetirePriorTo,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            frame.SequenceNumber,
            frame.RetirePriorTo,
            connectionId,
            statelessResetToken);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewConnectionIdFrame_RejectsTruncatedInput()
    {
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            0x06,
            0x04,
            [0xAA],
            QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken());

        for (int length = 0; length < encoded.Length; length++)
        {
            QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded.AsSpan(0, length));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewConnectionIdFrame_PreservesSequenceBeforeRetirePriorToFieldOrder()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(4);
        byte[] statelessResetToken = QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken();
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            sequenceNumber: 0x1234,
            retirePriorTo: 0x04,
            connectionId,
            statelessResetToken);

        QuicS19P15NewConnectionIdFrameTestSupport.AssertParses(
            encoded,
            expectedSequenceNumber: 0x1234,
            expectedRetirePriorTo: 0x04,
            connectionId,
            statelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzNewConnectionIdFrame();
    }
}
