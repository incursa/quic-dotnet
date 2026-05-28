// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14-0009">If an endpoint receives a datagram of a certain size, it MUST NOT assume that the sender sent the datagram at the same size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14-0009")]
public sealed class REQ_QUIC_RFC9000_S14_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandlePacketReceived_LeavesTheActivePathMaximumDatagramSizeAtTheRfcMinimumForAFreshLargeDatagram()
    {
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicConnectionPathIdentity activePath = new("203.0.113.9", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize + 80];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                activePath,
                datagram),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath.Value.Identity);
        Assert.Equal(
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes,
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes,
            runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
        Assert.Equal((ulong)datagram.Length, runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandlePacketReceived_DoesNotPromoteTheActivePathMaximumDatagramSizeOnLaterIngress()
    {
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443));

        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity activePath = runtime.ActivePath.Value.Identity;
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize + 150];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                activePath,
                datagram),
            nowTicks: 2);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes,
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes,
            runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
        Assert.Equal(
            (ulong)(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize + datagram.Length),
            runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void HandlePacketReceived_PreservesTheRfcMinimumAtTheBoundarySize()
    {
        using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicConnectionPathIdentity activePath = new("203.0.113.11", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                activePath,
                datagram),
            nowTicks: 3);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath.Value.Identity);
        Assert.Equal(
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes,
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes,
            runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
        Assert.Equal((ulong)datagram.Length, runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);
    }
}
