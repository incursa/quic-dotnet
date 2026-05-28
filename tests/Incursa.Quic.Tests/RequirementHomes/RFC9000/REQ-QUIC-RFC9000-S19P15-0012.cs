// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
public sealed class REQ_QUIC_RFC9000_S19P15_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewConnectionIdFrame_PreservesConnectionIdOfDeclaredLength()
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
    public void TryParseNewConnectionIdFrame_RejectsMissingConnectionIdBytes()
    {
        byte[] encoded = QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrameWithLengthBytes(
            [QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType],
            QuicVarintTestData.EncodeMinimal(0x06),
            QuicVarintTestData.EncodeMinimal(0x04),
            [8],
            QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(7),
            QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken());

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewConnectionIdFrame_PreservesMaximumLengthConnectionId()
    {
        byte[] connectionId = QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(20);
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
}
