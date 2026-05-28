// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0651">The same stateless reset token MUST NOT be used for multiple connection IDs.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0651")]
public sealed class REQ_QUIC_RFC9000_0651
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterStatelessResetToken_AssociatesDistinctTokensWithDistinctConnectionIds()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.141");
        byte[] firstToken = QuicStatelessResetRequirementTestData.CreateToken(0x41);
        byte[] secondToken = QuicStatelessResetRequirementTestData.CreateToken(0x51);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 701UL, firstToken));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 702UL, secondToken));

        QuicConnectionIngressResult firstIngress = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(firstToken),
            pathIdentity);
        QuicConnectionIngressResult secondIngress = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(secondToken),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, firstIngress.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, firstIngress.HandlingKind);
        Assert.Equal(handle, firstIngress.Handle);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0UL, runtime.TransitionSequence);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, secondIngress.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, secondIngress.HandlingKind);
        Assert.Equal(handle, secondIngress.Handle);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterStatelessResetToken_RejectsReusingTheSameTokenForASecondConnectionId()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.142");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x62);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 703UL, token));
        Assert.False(endpoint.TryRegisterStatelessResetToken(handle, 704UL, token));

        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(token),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, ingressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, ingressResult.HandlingKind);
        Assert.Equal(handle, ingressResult.Handle);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryRetireStatelessResetToken_ReleasesTheTokenForAReplacementConnectionId()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.143");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x73);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 705UL, token));
        Assert.True(endpoint.TryRetireStatelessResetToken(handle, 705UL));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 706UL, token));

        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(token),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, ingressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, ingressResult.HandlingKind);
        Assert.Equal(handle, ingressResult.Handle);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
