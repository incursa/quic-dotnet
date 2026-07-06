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
    [Requirement("REQ-QUIC-RFC9250-0065")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DoqClientOptionsNormalizeUnsetAndDisabledIdleTimeouts()
    {
        foreach ((TimeSpan initialTimeout, TimeSpan expectedTimeout) in new[]
        {
            (TimeSpan.Zero, DoqDefaults.SuggestedIdleTimeout),
            (Timeout.InfiniteTimeSpan, DoqDefaults.SuggestedIdleTimeout),
            (TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1)),
            (TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30)),
            (TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5)),
        })
        {
            QuicClientConnectionOptions options = CreateClientOptions();
            options.IdleTimeout = initialTimeout;

            DoqDefaults.EnsureIdleTimeout(options);

            Assert.Equal(expectedTimeout, options.IdleTimeout);
        }
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0066")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EffectiveIdleTimeoutUsesMinimumAdvertisedValueAndProbeFloor()
    {
        foreach ((ulong? local, ulong? peer, ulong pto, ulong expected) in new (ulong? Local, ulong? Peer, ulong Pto, ulong Expected)[]
        {
            (30_000_000UL, 15_000_000UL, 1_000UL, 15_000_000UL),
            (15_000_000UL, 30_000_000UL, 1_000UL, 15_000_000UL),
            (null, 20_000_000UL, 1_000UL, 20_000_000UL),
            (20_000_000UL, null, 1_000UL, 20_000_000UL),
            (1_000UL, 2_000UL, 1_000UL, 3_000UL),
            (0UL, 9_000UL, 4_000UL, 12_000UL),
        })
        {
            Assert.True(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
                local,
                peer,
                pto,
                out ulong effectiveIdleTimeoutMicros));

            Assert.Equal(expected, effectiveIdleTimeoutMicros);
        }

        Assert.False(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: 0,
            currentProbeTimeoutMicros: 1_000,
            out _));
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
