// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicTransportParameterCommitHelperTests
{
    [Fact]
    public void CreateLocalTransportParametersCommittedEvent_UsesLocalIdleTimeoutConversion()
    {
        QuicTransportParameters transportParameters = new()
        {
            MaxIdleTimeout = 123,
        };

        QuicConnectionTransportParametersCommittedEvent committedEvent =
            QuicTransportParameterCommitHelper.CreateLocalTransportParametersCommittedEvent(
                observedAtTicks: 42,
                transportParameters);

        Assert.Equal(42, committedEvent.ObservedAtTicks);
        Assert.Equal(QuicConnectionTransportState.None, committedEvent.TransportFlags);
        Assert.Equal(
            QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(transportParameters.MaxIdleTimeout),
            committedEvent.LocalMaxIdleTimeoutMicros);
        Assert.Null(committedEvent.PeerMaxIdleTimeoutMicros);
        Assert.Null(committedEvent.CurrentProbeTimeoutMicros);
    }

    [Fact]
    public void CreatePeerTransportParametersCommittedEvent_UsesPeerIdleTimeoutAndDisableActiveMigrationFlag()
    {
        QuicTransportParameters transportParameters = new()
        {
            MaxIdleTimeout = 456,
            DisableActiveMigration = true,
        };

        QuicConnectionTransportParametersCommittedEvent committedEvent =
            QuicTransportParameterCommitHelper.CreatePeerTransportParametersCommittedEvent(
                observedAtTicks: 84,
                transportParameters);

        Assert.Equal(84, committedEvent.ObservedAtTicks);
        Assert.Equal(
            QuicConnectionTransportState.PeerTransportParametersCommitted | QuicConnectionTransportState.DisableActiveMigration,
            committedEvent.TransportFlags);
        Assert.Equal(
            QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(transportParameters.MaxIdleTimeout),
            committedEvent.PeerMaxIdleTimeoutMicros);
        Assert.Null(committedEvent.LocalMaxIdleTimeoutMicros);
        Assert.Null(committedEvent.CurrentProbeTimeoutMicros);
    }

    [Fact]
    public void GetPositiveIncrement_ReturnsOnlyPositiveDifferenceAndClampsToIntMax()
    {
        Assert.Equal(0, QuicTransportParameterCommitHelper.GetPositiveIncrement(8, 8));
        Assert.Equal(0, QuicTransportParameterCommitHelper.GetPositiveIncrement(9, 8));
        Assert.Equal(5, QuicTransportParameterCommitHelper.GetPositiveIncrement(3, 8));
        Assert.Equal(
            int.MaxValue,
            QuicTransportParameterCommitHelper.GetPositiveIncrement(0, (ulong)int.MaxValue + 1UL));
    }
}
