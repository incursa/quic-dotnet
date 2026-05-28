// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P19-0005")]
public sealed class REQ_QUIC_RFC9000_S19P19_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseConnectionCloseFrame_PreservesVariableLengthTriggeringFrameType()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(triggeringFrameType: 0x1E, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal(0x1EUL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_RejectsTransportCloseMissingTriggeringFrameType()
    {
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1C, 0x00], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_PreservesMaximumVariableLengthTriggeringFrameType()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            triggeringFrameType: QuicVariableLengthInteger.MaxValue,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
