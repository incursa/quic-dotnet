namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0017">A client MAY use a token from one connection for any connection attempt using the same QUIC version.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0017")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TokenForTheSameVersion_CanBeConsumedForAnInitialConnectionAttempt()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor(
            version: QuicVersionNegotiation.Version1);

        Assert.True(token.TryConsume(
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicVersionNegotiation.Version1,
            out ReadOnlyMemory<byte> consumedToken));
        Assert.True(consumedToken.Span.SequenceEqual(QuicS8P1P3TokenLifecycleTestSupport.NewToken));
    }
}
