namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P1-0002">An endpoint MUST remember all stateless reset tokens associated with the connection IDs and remote addresses for datagrams it has recently sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P1-0002")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreateStatelessResetDatagram_UsesTheRememberedTokenForTheCurrentRemoteAddress()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity initialPath = new("203.0.113.80");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x80);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, initialPath));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 101UL, token));

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            101UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.True(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emissionResult.Disposition);
        Assert.Equal(initialPath, emissionResult.PathIdentity);
        Assert.Equal(99, emissionResult.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(emissionResult.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emissionResult.Datagram.Span, token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreateStatelessResetDatagram_ReturnsTokenUnavailableAfterTheTokenIsRetired()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity initialPath = new("203.0.113.81");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x81);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, initialPath));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 102UL, token));
        Assert.True(endpoint.TryRetireStatelessResetToken(handle, 102UL));

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            102UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.False(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable, emissionResult.Disposition);
        Assert.Null(emissionResult.PathIdentity);
        Assert.True(emissionResult.Datagram.IsEmpty);
    }
}
