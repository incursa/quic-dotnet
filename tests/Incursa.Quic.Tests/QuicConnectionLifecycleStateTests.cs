namespace Incursa.Quic.Tests;

public sealed class QuicConnectionLifecycleStateTests
{
    [Fact]
    public void TryEnterClosingState_ThenTryEnterDrainingState_ReplacesClosingWithDrainingAndStopsSendingPackets()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.CanSendPackets);
        Assert.True(state.TryEnterClosingState());
        Assert.True(state.IsClosing);
        Assert.False(state.IsDraining);
        Assert.False(state.CanSendPackets);

        Assert.True(state.TryEnterDrainingState());
        Assert.False(state.IsClosing);
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    public void TryEnterClosingState_ReturnsFalseAfterDraining()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryEnterDrainingState());
        Assert.False(state.TryEnterClosingState());
        Assert.False(state.IsClosing);
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    public void TryHandlePotentialStatelessReset_TransitionsToDrainingWhenTheTokenMatches()
    {
        byte[] statelessResetToken = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F];

        Span<byte> datagram = stackalloc byte[QuicStatelessReset.MinimumDatagramLength];
        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            datagram,
            out int bytesWritten));

        QuicConnectionLifecycleState state = new();
        Assert.True(state.TryHandlePotentialStatelessReset(datagram[..bytesWritten], statelessResetToken));
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
        Assert.False(state.TryHandlePotentialStatelessReset(datagram[..bytesWritten], statelessResetToken));
    }

    [Fact]
    public void TryHandlePotentialStatelessReset_ReturnsFalseForMalformedOrNonMatchingDatagrams()
    {
        byte[] matchingToken = [
            0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4A, 0x4B,
            0x4C, 0x4D, 0x4E, 0x4F];
        byte[] nonMatchingToken = [
            0x50, 0x51, 0x52, 0x53,
            0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5A, 0x5B,
            0x5C, 0x5D, 0x5E, 0x5F];

        Span<byte> datagram = stackalloc byte[QuicStatelessReset.MinimumDatagramLength];
        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(
            matchingToken,
            QuicStatelessReset.MinimumDatagramLength,
            datagram,
            out int bytesWritten));

        QuicConnectionLifecycleState state = new();
        Assert.False(state.TryHandlePotentialStatelessReset(datagram[..(bytesWritten - 1)], matchingToken));
        Assert.False(state.TryHandlePotentialStatelessReset(datagram[..bytesWritten], nonMatchingToken));
        Assert.False(state.IsDraining);
        Assert.True(state.CanSendPackets);
    }
}
