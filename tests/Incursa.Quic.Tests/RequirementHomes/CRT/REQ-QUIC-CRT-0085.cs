namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0085")]
public sealed class REQ_QUIC_CRT_0085
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointEmissionPolicyLimitsStatelessResetEmissionPerRemoteAddress()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.80");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x80);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 181UL, token));

        QuicConnectionStatelessResetEmissionResult first = endpoint.TryCreateStatelessResetDatagram(
            handle,
            181UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: false);
        QuicConnectionStatelessResetEmissionResult second = endpoint.TryCreateStatelessResetDatagram(
            handle,
            181UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: false);

        Assert.True(first.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, first.Disposition);
        Assert.Equal(pathIdentity, first.PathIdentity);
        Assert.Equal(99, first.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(first.Datagram.Span));
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.RateLimited, second.Disposition);
        Assert.False(second.Emitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointEmissionPolicyRejectsResetResponsesThatWouldViolateLoopProtection()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.81");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x81);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 182UL, token));

        QuicConnectionStatelessResetEmissionResult result = endpoint.TryCreateStatelessResetDatagram(
            handle,
            182UL,
            triggeringPacketLength: QuicStatelessReset.MinimumDatagramLength,
            hasLoopPreventionState: false);

        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.LoopOrAmplificationPrevented, result.Disposition);
        Assert.False(result.Emitted);
        Assert.Equal(pathIdentity, result.PathIdentity);
    }
}
