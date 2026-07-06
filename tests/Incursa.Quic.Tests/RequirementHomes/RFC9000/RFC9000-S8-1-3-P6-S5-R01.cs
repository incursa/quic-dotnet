// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-1-3-P6-S5-R01">A client MAY use a token from any previous connection to that server.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-1-3-P6-S5-R01")]
public sealed class REQ_QUIC_RFC9000_0401
{
    [Fact]
    [Requirement("RFC9000-S8-1-3-P6-S5-R01")]
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
    [Requirement("RFC9000-S8-1-3-P6-S5-R01")]
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

    [Fact]
    [Requirement("RFC9000-S8-1-3-P6-S5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreviousConnectionTokenIsIncludedOnlyForTheSameServerEndpoint()
    {
        QuicClientAddressValidationToken tokenForApplicableServer =
            QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor(QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint);
        QuicClientConnectionSettings mismatchedFirstAttempt = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(
            tokenForApplicableServer,
            QuicS8P1P3TokenLifecycleTestSupport.OtherEndPoint);
        AssertInitialPacketsCarryToken(mismatchedFirstAttempt.InitialAddressValidationToken, expectedToken: []);

        QuicClientConnectionSettings matchingSecondAttempt = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(
            tokenForApplicableServer,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint);
        AssertInitialPacketsCarryToken(
            matchingSecondAttempt.InitialAddressValidationToken,
            QuicS8P1P3TokenLifecycleTestSupport.NewToken);

        foreach (IPEndPoint serverEndPoint in new[]
        {
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicS8P1P3TokenLifecycleTestSupport.OtherEndPoint,
        })
        {
            QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor(serverEndPoint);
            QuicClientConnectionSettings matchingAttempt = QuicS8P1P3TokenLifecycleTestSupport.CaptureSettingsWith(
                token,
                serverEndPoint);

            AssertInitialPacketsCarryToken(
                matchingAttempt.InitialAddressValidationToken,
                QuicS8P1P3TokenLifecycleTestSupport.NewToken);
        }
    }

    private static void AssertInitialPacketsCarryToken(ReadOnlyMemory<byte> token, ReadOnlySpan<byte> expectedToken)
    {
        byte[][] initialTokens = QuicS8P1P3TokenLifecycleTestSupport.BootstrapAndReadInitialTokens(token);
        byte[] expected = expectedToken.ToArray();

        Assert.All(initialTokens, encodedToken => Assert.True(encodedToken.AsSpan().SequenceEqual(expected)));
    }
}
