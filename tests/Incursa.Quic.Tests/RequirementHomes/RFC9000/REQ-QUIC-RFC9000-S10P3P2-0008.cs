namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P2-0008">Endpoints are not required to compare new values against all previous values, but a duplicate value MAY be treated as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P2-0008")]
public sealed class REQ_QUIC_RFC9000_S10P3P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterStatelessResetToken_RejectsReusingTheSameTokenForASecondConnectionId()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.144");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x84);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 801UL, token));
        Assert.False(endpoint.TryRegisterStatelessResetToken(handle, 802UL, token));

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
    public void TryRetireStatelessResetToken_AllowsTheSameTokenToBeReusedAfterTheOriginalRegistrationIsRemoved()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.145");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x95);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 803UL, token));
        Assert.True(endpoint.TryRetireStatelessResetToken(handle, 803UL));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 804UL, token));

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
