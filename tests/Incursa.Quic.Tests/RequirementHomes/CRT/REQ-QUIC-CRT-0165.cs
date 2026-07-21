// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0165")]
public sealed class REQ_QUIC_CRT_0165
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LegacyCurrentReceiveCreditModePreservesFrozenSelector()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        runtime.SetStreamWriteDispatcher(static (_, _, _, _, _) => true);
        runtime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.LegacyCurrent);

        RegisterDistinctStreamObservers(runtime, count: 15);
        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
        _ = runtime.RegisterStreamObserver(streamId: 60, static _ => { });
        Assert.True(runtime.ShouldUseBatchedReceiveCreditPath());
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(true, out QuicStreamId streamId, out _));

        Task write = runtime.WriteStreamAsync(streamId.Value, new byte[1024], CancellationToken.None).AsTask();

        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
        await runtime.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => write.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ImmediateReceiveCreditModeBypassesLegacySelector()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        RegisterDistinctStreamObservers(runtime, count: 16);
        runtime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.Immediate);

        Assert.False(runtime.ShouldUseBatchedReceiveCreditPath());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadDominantBatchReceiveCreditModeBypassesLegacyEligibility()
    {
        await using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        runtime.SetStreamWriteDispatcher(static (_, _, _, _, _) => true);
        runtime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.ReadDominantBatch);

        Assert.True(runtime.ShouldUseBatchedReceiveCreditPath());
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(true, out QuicStreamId streamId, out _));

        Task write = runtime.WriteStreamAsync(streamId.Value, new byte[1024], CancellationToken.None).AsTask();

        Assert.True(runtime.ShouldUseBatchedReceiveCreditPath());
        await runtime.DisposeAsync();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => write.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ReceiveCreditPolicyModeCanOnlyBeConfiguredOnce()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        runtime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.Immediate);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.LegacyCurrent));

        Assert.Equal("The receive-credit policy mode has already been configured.", exception.Message);
        Assert.Throws<ArgumentOutOfRangeException>(
            () => runtime.ConfigureReceiveCreditPolicyMode((QuicReceiveCreditPolicyMode)int.MaxValue));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForcedReadDominantBatchStillHonorsFinalReadGuard()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        runtime.ConfigureReceiveCreditPolicyMode(QuicReceiveCreditPolicyMode.ReadDominantBatch);
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4096,
            peerBidirectionalReceiveLimit: 4096);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            streamIdValue: 1,
            destination,
            useBatchedReceiveCredit: runtime.ShouldUseBatchedReceiveCreditPath(),
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.True(completed);
        Assert.Equal(4098UL, maxDataFrame.MaximumData);
        Assert.Equal(default, maxStreamDataFrame);
        Assert.True(state.TryGetStreamSnapshot(streamIdValue: 1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(4096UL, snapshot.ReceiveLimit);
    }

    private static void RegisterDistinctStreamObservers(QuicConnectionRuntime runtime, int count)
    {
        for (int index = 0; index < count; index++)
        {
            _ = runtime.RegisterStreamObserver((ulong)(index * 4), static _ => { });
        }
    }
}
