// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-1-3-P6-S4-R01">A client MUST NOT include a token that is not applicable to the server being contacted unless the client has knowledge that the server that issued the token and the contacted server are jointly managing the token space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-1-3-P6-S4-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MatchingServerToken_IsEligibleForInitialInclusion()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor();
        QuicClientConnectionSettings settings = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(
            token,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint);

        Assert.False(settings.InitialAddressValidationToken.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TokenForAnotherServer_IsNotIncludedInClientInitialPackets()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor(
            QuicS8P1P3TokenLifecycleTestSupport.OtherEndPoint);
        QuicClientConnectionSettings settings = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(
            token,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint);

        Assert.True(settings.InitialAddressValidationToken.IsEmpty);
        byte[][] initialTokens = QuicS8P1P3TokenLifecycleTestSupport.BootstrapAndReadInitialTokens(
            settings.InitialAddressValidationToken);

        Assert.All(initialTokens, encodedToken => Assert.Empty(encodedToken));
    }
}
