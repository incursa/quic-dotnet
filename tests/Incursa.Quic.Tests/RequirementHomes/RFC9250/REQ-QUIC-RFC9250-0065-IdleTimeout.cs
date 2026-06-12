// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Quic;
using System.Net.Security;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9250_0065_IdleTimeout
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0065")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqClientOptionsAdvertiseDefaultIdleTimeoutWhenUnset()
    {
        QuicClientConnectionOptions options = CreateClientOptions();

        DoqDefaults.EnsureIdleTimeout(options);

        Assert.Equal(DoqDefaults.SuggestedIdleTimeout, options.IdleTimeout);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0065")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqClientOptionsDoNotLeaveIdleTimeoutDisabled()
    {
        QuicClientConnectionOptions options = CreateClientOptions();
        options.IdleTimeout = Timeout.InfiniteTimeSpan;

        DoqDefaults.EnsureIdleTimeout(options);

        Assert.NotEqual(TimeSpan.Zero, options.IdleTimeout);
        Assert.NotEqual(Timeout.InfiniteTimeSpan, options.IdleTimeout);
        Assert.Equal(DoqDefaults.SuggestedIdleTimeout, options.IdleTimeout);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0066")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EffectiveIdleTimeoutUsesMinimumAdvertisedValue()
    {
        Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: 30_000_000,
            peerMaxIdleTimeoutMicros: 15_000_000,
            currentProbeTimeoutMicros: 1_000,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(15_000_000UL, effectiveIdleTimeoutMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0066")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EffectiveIdleTimeoutDoesNotUseLargerAdvertisedValue()
    {
        Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: 30_000_000,
            peerMaxIdleTimeoutMicros: 15_000_000,
            currentProbeTimeoutMicros: 1_000,
            out ulong effectiveIdleTimeoutMicros));

        Assert.NotEqual(30_000_000UL, effectiveIdleTimeoutMicros);
    }

    private static QuicClientConnectionOptions CreateClientOptions()
    {
        return new QuicClientConnectionOptions
        {
            ClientAuthenticationOptions = new SslClientAuthenticationOptions(),
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
        };
    }
}
