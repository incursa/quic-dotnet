// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0399">A client SHOULD include an applicable, unused token in an Initial packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0399")]
public sealed class REQ_QUIC_RFC9000_0399
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ApplicableUnusedNewToken_IsEncodedInClientInitialPackets()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor();
        QuicClientConnectionSettings settings = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(token);

        Assert.False(settings.InitialAddressValidationToken.IsEmpty);
        byte[][] initialTokens = QuicS8P1P3TokenLifecycleTestSupport.BootstrapAndReadInitialTokens(
            settings.InitialAddressValidationToken);

        Assert.All(initialTokens, encodedToken =>
            Assert.True(encodedToken.AsSpan().SequenceEqual(QuicS8P1P3TokenLifecycleTestSupport.NewToken)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingApplicableToken_LeavesClientInitialTokenFieldEmpty()
    {
        byte[][] initialTokens = QuicS8P1P3TokenLifecycleTestSupport.BootstrapAndReadInitialTokens(
            ReadOnlyMemory<byte>.Empty);

        Assert.All(initialTokens, encodedToken => Assert.Empty(encodedToken));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PreviouslyConsumedNewToken_IsNotIncludedAgain()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor();

        QuicClientConnectionSettings firstAttempt = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(token);
        QuicClientConnectionSettings secondAttempt = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(token);

        Assert.False(firstAttempt.InitialAddressValidationToken.IsEmpty);
        Assert.True(secondAttempt.InitialAddressValidationToken.IsEmpty);
    }
}
