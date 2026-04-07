namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P2-0005")]
public sealed class REQ_QUIC_RFC9000_S8P2P2_0005
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P1-0005">An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit sending a datagram of this size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P2-0005">An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P2-0006">However, an endpoint MUST NOT expand the datagram containing the PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P3P1-0001">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatPathValidationDatagramPadding_WritesRepeatedPaddingFramesWhenAmplificationBudgetAllows()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));

        Span<byte> destination = stackalloc byte[13];
        Assert.True(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            1187,
            budget,
            destination,
            out int bytesWritten));

        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));

        for (int index = 0; index < bytesWritten; index++)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination[index..bytesWritten], out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);
        }
    }
}
