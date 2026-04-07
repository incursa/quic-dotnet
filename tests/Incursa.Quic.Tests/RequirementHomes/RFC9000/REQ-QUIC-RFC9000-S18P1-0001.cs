namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P1-0001")]
public sealed class REQ_QUIC_RFC9000_S18P1_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0003">Each endpoint MUST advertise a `max_idle_timeout`, and the effective value at an endpoint is the minimum of the two advertised values, or the sole advertised value if only one endpoint advertises a non-zero value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0001">Transport parameters with an identifier of the form 31 * N + 27 for integer values of N MUST be reserved to exercise the requirement that unknown transport parameters be ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0002">These transport parameters have no semantics and MAY carry arbitrary values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P4P2-0001">An endpoint MUST ignore transport parameters that it does not support.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S7P4P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseTransportParameters_IgnoresReservedGreaseParameters()
    {
        byte[] greaseTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xDE, 0xAD, 0xBE, 0xEF]);
        byte[] maxIdleTimeoutTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25));
        byte[] block = QuicTransportParameterTestData.BuildTransportParameterBlock(greaseTuple, maxIdleTimeoutTuple);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            block,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Equal(25UL, parsed.MaxIdleTimeout);
        Assert.Null(parsed.OriginalDestinationConnectionId);
        Assert.Null(parsed.StatelessResetToken);
        Assert.Null(parsed.PreferredAddress);
    }
}
