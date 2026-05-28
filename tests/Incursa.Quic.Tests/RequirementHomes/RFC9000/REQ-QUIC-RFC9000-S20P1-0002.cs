// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
public sealed class REQ_QUIC_RFC9000_S20P1_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_UsesNoErrorForGracefulConnectionClose()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: (ulong)QuicTransportErrorCode.NoError,
            triggeringFrameType: 0,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.NoError, parsed.ErrorCode);
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal(0UL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransportErrorCodeRegistry_DoesNotUseNoErrorForApplicationClose()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0x1234, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.NotEqual((ulong)QuicTransportErrorCode.NoError, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
