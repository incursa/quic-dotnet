namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0277")]
public sealed class REQ_QUIC_RFC9000_0277
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatTransportParameters_DoesNotEmitDisableActiveMigrationWhenServerAllowsMigration()
    {
        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 30,
        };

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x01,
            QuicVarintTestData.EncodeMinimal(30));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.False(parsed.DisableActiveMigration);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0277">A server in a deployment that does not implement a solution to maintain connection continuity when the client address changes SHOULD indicate that migration is not supported by using the disable_active_migration transport parameter.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0277")]
    public void TryFormatTransportParameters_EncodesDisableActiveMigrationWhenServerDisallowsMigration()
    {
        QuicTransportParameters parameters = new()
        {
            DisableActiveMigration = true,
        };

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0C, []);

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.True(parsed.DisableActiveMigration);
    }
}
