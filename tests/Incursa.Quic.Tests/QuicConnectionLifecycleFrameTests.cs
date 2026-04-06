using Incursa.Quic;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionLifecycleFrameTests
{
    [Fact]
    public void QuicConnectionCloseFrame_TransportClosePreservesTransportMetadata()
    {
        byte[] reasonPhrase = [0x62, 0x79, 0x65];

        QuicConnectionCloseFrame frame = new(
            QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x04,
            reasonPhrase);

        Assert.False(frame.IsApplicationError);
        Assert.Equal((byte)0x1C, frame.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.ProtocolViolation, frame.ErrorCode);
        Assert.True(frame.HasTriggeringFrameType);
        Assert.Equal(0x04UL, frame.TriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(frame.ReasonPhrase));
    }

    [Fact]
    public void QuicConnectionCloseFrame_ApplicationCloseDoesNotExposeTriggeringFrameType()
    {
        byte[] reasonPhrase = [0x61, 0x70, 0x70];

        QuicConnectionCloseFrame frame = new(0x1234, reasonPhrase);

        Assert.True(frame.IsApplicationError);
        Assert.Equal((byte)0x1D, frame.FrameType);
        Assert.Equal(0x1234UL, frame.ErrorCode);
        Assert.False(frame.HasTriggeringFrameType);
        Assert.Equal(0UL, frame.TriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(frame.ReasonPhrase));
    }

    [Fact]
    public void QuicHandshakeDoneFrame_ExposesTheWireFrameType()
    {
        QuicHandshakeDoneFrame frame = default;

        Assert.Equal((byte)0x1E, frame.FrameType);
    }
}
