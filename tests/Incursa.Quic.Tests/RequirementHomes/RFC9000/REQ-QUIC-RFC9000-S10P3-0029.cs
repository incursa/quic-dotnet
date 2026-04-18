namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0029">An endpoint that supports multiple versions of QUIC MUST generate a Stateless Reset that will be accepted by peers that support any version that the endpoint might support or might have supported prior to losing state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0029")]
public sealed class REQ_QUIC_RFC9000_S10P3_0029
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task TryCreateStatelessResetDatagram_RetainsTheConnectionVersionProfileAfterRuntimeDisposal()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            supportedVersions:
            [
                QuicVersionNegotiation.Version1,
                0x11223344u,
            ]);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.120");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0xA0);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 201UL, token));
        Assert.True(endpoint.TryGetRetainedVersionProfile(handle, out QuicConnectionVersionProfile retainedProfileBeforeDisposal));
        Assert.Equal(2, retainedProfileBeforeDisposal.SupportedVersions.Length);
        uint[] supportedVersions =
        [
            QuicVersionNegotiation.Version1,
            0x11223344u,
        ];
        Assert.True(retainedProfileBeforeDisposal.SupportedVersions.Span.SequenceEqual(supportedVersions));

        await runtime.DisposeAsync();

        Assert.True(endpoint.TryGetRetainedVersionProfile(handle, out QuicConnectionVersionProfile retainedProfileAfterDisposal));
        Assert.Equal(2, retainedProfileAfterDisposal.SupportedVersions.Length);
        Assert.True(retainedProfileAfterDisposal.SupportedVersions.Span.SequenceEqual(supportedVersions));

        QuicConnectionStatelessResetEmissionResult emissionResult = endpoint.TryCreateStatelessResetDatagram(
            handle,
            201UL,
            triggeringPacketLength: 100,
            hasLoopPreventionState: true);

        Assert.True(emissionResult.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, emissionResult.Disposition);
        Assert.Equal(pathIdentity, emissionResult.PathIdentity);
        Assert.Equal(99, emissionResult.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(emissionResult.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emissionResult.Datagram.Span, token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetRetainedVersionProfile_ReturnsFalseBeforeConnectionRegistration()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.False(endpoint.TryGetRetainedVersionProfile(handle, out _));
    }
}
