// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0650">A connection ID from a connection that is reset by revealing the stateless reset token MUST NOT be reused for new connections at nodes that share a static key.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0650")]
public sealed class REQ_QUIC_RFC9000_0650
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptedStatelessResetTransitionsTheRuntimeToDraining()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.147");
        byte[] token = CreateToken(0xA2, 0xB2);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 1001UL, token));

        QuicConnectionTransitionResult transition = await AcceptStatelessResetAsync(endpoint, handle, pathIdentity, token);

        Assert.Equal(QuicConnectionPhase.Draining, transition.CurrentPhase);
        Assert.True(transition.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.StatelessReset, runtime.TerminalState?.Origin);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task TryRegisterStatelessResetToken_RejectsReusingTheResetConnectionIdAndStaticKeyCombinationWhileDraining()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.148");
        byte[] token = CreateToken(0xA3, 0xB3);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(firstHandle, 1002UL, token));

        QuicConnectionTransitionResult transition = await AcceptStatelessResetAsync(endpoint, firstHandle, pathIdentity, token);

        Assert.Equal(QuicConnectionPhase.Draining, transition.CurrentPhase);
        Assert.Equal(QuicConnectionPhase.Draining, firstRuntime.Phase);

        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, pathIdentity));
        Assert.False(endpoint.TryRegisterStatelessResetToken(secondHandle, 1002UL, token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AcceptedStatelessResetWithMinimumLengthInputsStillRejectsReuseWhileDraining()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.149");
        byte[] token = CreateToken(0xA4, 0xB4, connectionIdLength: 1, secretKeyLength: 1);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(firstHandle, 1003UL, token));

        QuicConnectionTransitionResult transition = await AcceptStatelessResetAsync(endpoint, firstHandle, pathIdentity, token);

        Assert.Equal(QuicConnectionPhase.Draining, transition.CurrentPhase);
        Assert.Equal(QuicConnectionPhase.Draining, firstRuntime.Phase);

        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, pathIdentity));
        Assert.False(endpoint.TryRegisterStatelessResetToken(secondHandle, 1003UL, token));
    }

    private static async Task<QuicConnectionTransitionResult> AcceptStatelessResetAsync(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        byte[] token)
    {
        TaskCompletionSource<QuicConnectionTransitionResult> observedTransition = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (postedHandle, _, transition) =>
            {
                if (postedHandle == handle
                    && transition.EventKind == QuicConnectionEventKind.AcceptedStatelessReset)
                {
                    observedTransition.TrySetResult(transition);
                }
            },
            cancellationToken: cancellation.Token);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, ingressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, ingressResult.HandlingKind);
        Assert.Equal(handle, ingressResult.Handle);

        QuicConnectionTransitionResult transition = await observedTransition.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();
        await consumer.WaitAsync(TimeSpan.FromSeconds(5));

        return transition;
    }

    private static byte[] CreateToken(
        byte connectionIdStart,
        byte secretKeyStart,
        int connectionIdLength = 4,
        int secretKeyLength = 8)
    {
        byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(
            start: connectionIdStart,
            length: connectionIdLength);
        byte[] secretKey = QuicStatelessResetRequirementTestData.CreateSecret(
            start: secretKeyStart,
            length: secretKeyLength);
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);

        return token.ToArray();
    }
}
