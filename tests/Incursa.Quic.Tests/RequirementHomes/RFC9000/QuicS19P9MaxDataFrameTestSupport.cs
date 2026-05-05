namespace Incursa.Quic.Tests;

internal static class QuicS19P9MaxDataFrameTestSupport
{
    internal const ulong ResetStreamFrameType = 0x04;

    internal static void AssertLocalFlowControlClose(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result,
        ulong triggeringFrameType)
    {
        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.FlowControlError, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.ApplicationErrorCode);
        Assert.Equal(triggeringFrameType, runtime.TerminalState.Value.Close.TriggeringFrameType);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
    }
}
