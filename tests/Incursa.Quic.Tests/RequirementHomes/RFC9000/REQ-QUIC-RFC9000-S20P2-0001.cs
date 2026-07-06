// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
public sealed class REQ_QUIC_RFC9000_S20P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetStreamFrame_UsesApplicationProtocolErrorCodes()
    {
        QuicResetStreamFrame frame = new(streamId: 0x1234, applicationProtocolErrorCode: 0x5678, finalSize: 0x9A);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StopSendingFrame_UsesApplicationProtocolErrorCodes()
    {
        QuicStopSendingFrame frame = new(streamId: 0x1234, applicationProtocolErrorCode: 0x5678);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionCloseFrame_UsesApplicationProtocolErrorCodes()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(errorCode: 0x1234, reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.False(parsed.HasTriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionCloseFrame_DoesNotUseTransportErrorCodesForApplicationClose()
    {
        byte[] encoded = QuicConnectionCloseFrameProofSupport.BuildTransportClose(
            errorCode: 0x1234,
            triggeringFrameType: 0x02,
            reasonPhrase: []);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal(0x02UL, parsed.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ApplicationProtocolErrorCodeFrames_FuzzPreserveApplicationErrorCodes()
    {
        ulong[] applicationErrorCodes = [0, 1, 0x1234, 0x3FFF];

        foreach (ulong applicationErrorCode in applicationErrorCodes)
        {
            QuicResetStreamFrame resetFrame = new(streamId: 0x04, applicationErrorCode, finalSize: 0x20);
            byte[] resetEncoded = QuicFrameTestData.BuildResetStreamFrame(resetFrame);
            Assert.True(QuicFrameCodec.TryParseResetStreamFrame(resetEncoded, out QuicResetStreamFrame parsedReset, out int resetBytesConsumed));
            Assert.Equal(resetEncoded.Length, resetBytesConsumed);
            Assert.Equal(applicationErrorCode, parsedReset.ApplicationProtocolErrorCode);

            QuicStopSendingFrame stopSendingFrame = new(streamId: 0x04, applicationErrorCode);
            byte[] stopSendingEncoded = QuicFrameTestData.BuildStopSendingFrame(stopSendingFrame);
            Assert.True(QuicFrameCodec.TryParseStopSendingFrame(stopSendingEncoded, out QuicStopSendingFrame parsedStopSending, out int stopSendingBytesConsumed));
            Assert.Equal(stopSendingEncoded.Length, stopSendingBytesConsumed);
            Assert.Equal(applicationErrorCode, parsedStopSending.ApplicationProtocolErrorCode);

            byte[] applicationCloseEncoded = QuicConnectionCloseFrameProofSupport.BuildApplicationClose(applicationErrorCode, reasonPhrase: []);
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(applicationCloseEncoded, out QuicConnectionCloseFrame parsedApplicationClose, out int closeBytesConsumed));
            Assert.Equal(applicationCloseEncoded.Length, closeBytesConsumed);
            Assert.True(parsedApplicationClose.IsApplicationError);
            Assert.Equal(applicationErrorCode, parsedApplicationClose.ErrorCode);
        }
    }
}
