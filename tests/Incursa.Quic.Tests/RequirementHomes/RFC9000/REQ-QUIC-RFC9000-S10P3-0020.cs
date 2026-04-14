namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0020">Tokens MUST be invalidated when their associated connection ID is retired via a RETIRE_CONNECTION_ID frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0020")]
public sealed class REQ_QUIC_RFC9000_S10P3_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRetireStatelessResetToken_RemovesTheRetiredTokenFromMatching()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.92");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x92);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 201UL, token));
        Assert.True(endpoint.TryRetireStatelessResetToken(handle, 201UL));

        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(token),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, ingressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, ingressResult.HandlingKind);
        Assert.Null(ingressResult.Handle);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRetireStatelessResetToken_PreservesOtherTokensOnTheSameEndpoint()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.93");
        byte[] retiredToken = QuicStatelessResetRequirementTestData.CreateToken(0x93);
        byte[] liveToken = QuicStatelessResetRequirementTestData.CreateToken(0xA3);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 202UL, retiredToken));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 203UL, liveToken));
        Assert.True(endpoint.TryRetireStatelessResetToken(handle, 202UL));

        QuicConnectionIngressResult retiredTokenResult = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(retiredToken),
            pathIdentity);
        QuicConnectionIngressResult liveTokenResult = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(liveToken),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, retiredTokenResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, retiredTokenResult.HandlingKind);
        Assert.Null(retiredTokenResult.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, liveTokenResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, liveTokenResult.HandlingKind);
        Assert.Equal(handle, liveTokenResult.Handle);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
