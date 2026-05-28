// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0013">A client SHOULD NOT reuse a NEW_TOKEN token for different connection attempts.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0013")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewToken_CanBeConsumedForItsFirstMatchingConnectionAttempt()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor();

        Assert.True(token.TryConsume(
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicVersionNegotiation.Version1,
            out ReadOnlyMemory<byte> consumedToken));
        Assert.True(consumedToken.Span.SequenceEqual(QuicS8P1P3TokenLifecycleTestSupport.NewToken));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewToken_CannotBeReusedForASecondConnectionAttempt()
    {
        QuicClientAddressValidationToken token = QuicS8P1P3TokenLifecycleTestSupport.CreateNewTokenFor();

        Assert.True(token.TryConsume(
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicVersionNegotiation.Version1,
            out _));
        Assert.False(token.TryConsume(
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicVersionNegotiation.Version1,
            out ReadOnlyMemory<byte> reusedToken));
        Assert.True(reusedToken.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EmptyNewToken_IsNotRetainedForAnyConnectionAttempt()
    {
        Assert.False(QuicClientAddressValidationToken.TryCreate(
            ReadOnlySpan<byte>.Empty,
            QuicS8P1P3TokenLifecycleTestSupport.ApplicableEndPoint,
            QuicVersionNegotiation.Version1,
            QuicAddressValidationTokenSource.NewToken,
            out QuicClientAddressValidationToken? token));
        Assert.Null(token);
    }
}
