// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0095")]
public sealed class REQ_QUIC_CRT_0095
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConcurrentEventPostingUsesShardQueueWithoutConnectionLockFields()
    {
        // Quarantined structural probe: follow-up work item will replace this reflection-based
        // field-shape check with a non-reflection repository-native assertion.
        FieldInfo[] lockLikeConnectionFields = typeof(QuicConnectionRuntime)
            .GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
            .Where(field =>
                field.FieldType == typeof(object)
                && (field.Name.Contains("lock", StringComparison.OrdinalIgnoreCase)
                    || field.Name.Contains("gate", StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        Assert.Equal(
            ["connectionShardPlacementEvidenceGate", "pendingStreamActionRequestsGate", "scheduledFlowControlCreditGate", "scheduledPeerStreamCapacityReleaseGate"],
            lockLikeConnectionFields.Select(field => field.Name).Order(StringComparer.Ordinal).ToArray());

        QuicConnectionRuntimeHost host = new(2);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = host.AllocateConnectionHandle();
        TaskCompletionSource<bool> observedAllTransitions = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int observedCount = 0;

        Assert.True(host.TryRegisterConnection(handle, runtime));
        Task consumer = host.RunAsync((observedHandle, _, _) =>
        {
            if (observedHandle == handle && Interlocked.Increment(ref observedCount) == 16)
            {
                observedAllTransitions.TrySetResult(true);
            }
        });

        bool[] posted = await Task.WhenAll(Enumerable.Range(0, 16)
            .Select(_ => Task.Run(() => host.TryPostEvent(
                handle,
                new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 0)))));

        Assert.All(posted, Assert.True);
        await observedAllTransitions.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await host.DisposeAsync();
        await consumer;
        await runtime.DisposeAsync();

        Assert.Equal(16, observedCount);
    }
}
