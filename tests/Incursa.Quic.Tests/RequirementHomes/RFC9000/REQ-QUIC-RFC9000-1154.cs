namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1154">A server that chooses a zero-length connection ID MUST NOT provide a preferred address.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1154")]
public sealed class REQ_QUIC_RFC9000_1154
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_AllowsPreferredAddressWhenServerSelectedNonZeroConnectionId()
    {
        QuicTransportParameters parameters = QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters();

        byte[] encoded = QuicPreferredAddressRequirementTestSupport.FormatAsServer(parameters);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId, parsed.InitialSourceConnectionId);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredConnectionId, parsed.PreferredAddress!.ConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-0215")]
    public void TryParseTransportParameters_RejectsPreferredAddressWithZeroLengthConnectionId()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            ipv6Port: 8443,
            connectionId: [],
            statelessResetToken: Enumerable.Range(0, 16).Select(value => (byte)(0xA0 + value)).ToArray());

        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            new QuicTransportParameters
            {
                PreferredAddress = new QuicPreferredAddress
                {
                    IPv4Address = [192, 0, 2, 1],
                    IPv4Port = 443,
                    IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                    IPv6Port = 8443,
                    ConnectionId = [],
                    StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0xA0 + value)).ToArray(),
                },
            },
            QuicTransportParameterRole.Server,
            stackalloc byte[128],
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-0215")]
    public void TryParseTransportParameters_RejectsPreferredAddressWhenServerSelectedZeroLengthConnectionId()
    {
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress();
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, []),
            QuicPreferredAddressRequirementTestSupport.BuildPreferredAddressTuple(preferredAddress));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters(initialSourceConnectionId: []),
            QuicTransportParameterRole.Server,
            stackalloc byte[128],
            out _));
    }
}
