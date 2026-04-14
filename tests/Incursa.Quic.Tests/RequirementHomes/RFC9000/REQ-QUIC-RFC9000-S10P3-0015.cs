namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0015">An endpoint MAY send a Stateless Reset in response to a packet with a long header.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0015")]
public sealed class REQ_QUIC_RFC9000_S10P3_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreateStatelessResetDatagram_AllowsLongHeaderSizedTriggers()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.92");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x92);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 115UL, token));

        byte[] longHeaderPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x52,
            version: 0x01020304,
            destinationConnectionId: [0x11, 0x12, 0x13, 0x14],
            sourceConnectionId: [0x21, 0x22, 0x23, 0x24],
            versionSpecificData: [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B]);

        QuicConnectionStatelessResetEmissionResult result = endpoint.TryCreateStatelessResetDatagram(
            handle,
            115UL,
            triggeringPacketLength: longHeaderPacket.Length,
            hasLoopPreventionState: false);

        Assert.True(result.Emitted);
        Assert.Equal(QuicConnectionStatelessResetEmissionDisposition.Emitted, result.Disposition);
        Assert.Equal(pathIdentity, result.PathIdentity);
        Assert.Equal(longHeaderPacket.Length - 1, result.Datagram.Length);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(result.Datagram.Span));
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(result.Datagram.Span, token);
    }
}
