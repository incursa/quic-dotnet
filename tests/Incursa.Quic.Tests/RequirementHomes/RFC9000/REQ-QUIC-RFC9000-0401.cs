namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0401">A client MAY use a token from any previous connection to that server.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0401")]
public sealed class REQ_QUIC_RFC9000_0401
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0401")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PreviousConnectionTokenForSameServer_IsIncludedInInitialPackets()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor();
        QuicClientConnectionSettings settings = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(
            token,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint);

        Assert.False(settings.InitialAddressValidationToken.IsEmpty);
        byte[][] initialTokens = QuicS8P1P3TokenLifecycleTestSupport.BootstrapAndReadInitialTokens(
            settings.InitialAddressValidationToken);

        Assert.All(
            initialTokens,
            encodedToken => Assert.True(
                encodedToken.AsSpan().SequenceEqual(QuicS8P1P3TokenLifecycleTestSupport.NewToken)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0401")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PreviousConnectionTokenForDifferentServer_IsNotIncludedInInitialPackets()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor(
            QuicS8P1P3TokenLifecycleTestSupport.OtherEndPoint);
        QuicClientConnectionSettings settings = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(
            token,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint);

        Assert.True(settings.InitialAddressValidationToken.IsEmpty);
        byte[][] initialTokens = QuicS8P1P3TokenLifecycleTestSupport.BootstrapAndReadInitialTokens(
            settings.InitialAddressValidationToken);

        Assert.All(initialTokens, Assert.Empty);
    }
}
