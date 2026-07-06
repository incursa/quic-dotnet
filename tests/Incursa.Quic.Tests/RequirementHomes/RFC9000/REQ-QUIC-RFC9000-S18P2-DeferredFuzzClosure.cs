// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S18P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerOnlyTransportParametersRespectSenderRoleAcrossOpaqueValues()
    {
        foreach (byte[] originalDestinationConnectionId in OpaqueConnectionIdCases())
        {
            QuicTransportParameters parameters = new()
            {
                OriginalDestinationConnectionId = originalDestinationConnectionId,
            };

            byte[] encoded = FormatTransportParameters(parameters, QuicTransportParameterRole.Server);
            Assert.Equal(
                QuicTransportParameterTestData.BuildTransportParameterTuple(0x00, originalDestinationConnectionId),
                encoded);
            Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Client,
                new byte[64],
                out int bytesWritten));
            Assert.Equal(0, bytesWritten);
            Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
                encoded,
                QuicTransportParameterRole.Server,
                out _));
        }

        foreach (byte[] statelessResetToken in StatelessResetTokenCases())
        {
            QuicTransportParameters parameters = new()
            {
                StatelessResetToken = statelessResetToken,
            };

            byte[] encoded = FormatTransportParameters(parameters, QuicTransportParameterRole.Server);
            Assert.Equal(
                QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, statelessResetToken),
                encoded);
            Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Client,
                new byte[64],
                out int bytesWritten));
            Assert.Equal(0, bytesWritten);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MaxIdleTimeoutConvertsBetweenRuntimeClockAndWireMilliseconds()
    {
        foreach ((TimeSpan idleTimeout, ulong expectedMilliseconds) in new[]
        {
            (TimeSpan.Zero, 0UL),
            (TimeSpan.FromTicks(1), 1UL),
            (TimeSpan.FromMicroseconds(999), 1UL),
            (TimeSpan.FromMilliseconds(1), 1UL),
            (TimeSpan.FromMilliseconds(25), 25UL),
            (TimeSpan.FromMilliseconds(1_500), 1_500UL),
        })
        {
            ulong wireMilliseconds = QuicTransportParameterTimeUnits.IdleTimeoutToMaxIdleTimeoutMilliseconds(idleTimeout);
            Assert.Equal(expectedMilliseconds, wireMilliseconds);
            Assert.Equal(expectedMilliseconds * 1_000UL, QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(wireMilliseconds));

            QuicTransportParameters parsed = RoundTripClientParameterBlock(new QuicTransportParameters
            {
                MaxIdleTimeout = wireMilliseconds,
            });
            Assert.Equal(wireMilliseconds, parsed.MaxIdleTimeout);
        }

        Assert.Null(QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(null));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StatelessResetOnlyMatchesAdvertisedConnectionIdTokens()
    {
        foreach (byte seed in new byte[] { 0x10, 0x30, 0x50 })
        {
            byte[] advertisedToken = CreateSequentialBytes(16, seed);
            byte[] alternateToken = CreateSequentialBytes(16, (byte)(seed + 1));
            byte[] datagram = [..CreateSequentialBytes(24, 0xA0), ..advertisedToken];

            Assert.True(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, advertisedToken));
            Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, alternateToken));
            Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, []));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialStreamLimitsRoundTripAndGateLocalStreamCreation()
    {
        foreach (ulong limit in new[] { 0UL, 1UL, 2UL, 3UL, 63UL, 64UL, QuicS18P2InitialStreamLimitTestSupport.MaximumInitialStreamLimit })
        {
            QuicTransportParameters bidi = QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
                QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsBidiId,
                limit);
            Assert.Equal(limit, bidi.InitialMaxStreamsBidi);
            Assert.Null(bidi.InitialMaxStreamsUni);
            AssertLocalStreamLimitIsApplied(limit, bidirectional: true);

            QuicTransportParameters uni = QuicS18P2InitialStreamLimitTestSupport.ParseInitialStreamLimitParameter(
                QuicS18P2InitialStreamLimitTestSupport.InitialMaxStreamsUniId,
                limit);
            Assert.Equal(limit, uni.InitialMaxStreamsUni);
            Assert.Null(uni.InitialMaxStreamsBidi);
            AssertLocalStreamLimitIsApplied(limit, bidirectional: false);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0017")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DisableActiveMigrationAllowsPreferredAddressMigrationButRejectsNonPreferredLocalMigration()
    {
        foreach (QuicTransportParameters peerParameters in new[]
        {
            QuicS18P2DisableActiveMigrationTestSupport.CreateDisableActiveMigrationPeerTransportParameters(),
            QuicS18P2DisableActiveMigrationTestSupport.CreatePreferredAddressPeerTransportParameters(),
            QuicS18P2DisableActiveMigrationTestSupport.CreatePortOnlyPreferredAddressPeerTransportParameters(),
        })
        {
            byte[] encoded = QuicS18P2DisableActiveMigrationTestSupport.FormatTransportParameters(
                peerParameters,
                QuicTransportParameterRole.Server);
            Assert.Contains(QuicS18P2DisableActiveMigrationTestSupport.DisableActiveMigrationId, encoded.Select(static value => (ulong)value));

            QuicTransportParameters parsed = QuicS18P2DisableActiveMigrationTestSupport.ParsePeerTransportParameters(peerParameters);
            Assert.True(parsed.DisableActiveMigration);

            using QuicConnectionRuntime runtime =
                QuicS18P2DisableActiveMigrationTestSupport.CreateRuntimeWithCommittedPeerTransportParameters(parsed);
            Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));

            if (parsed.PreferredAddress is null)
            {
                AssertValidatedPathDoesNotPromote(runtime, QuicS18P2DisableActiveMigrationTestSupport.CreateNewLocalAddressPath());
                AssertValidatedPathPromotes(runtime, QuicS18P2DisableActiveMigrationTestSupport.CreatePeerRebindingPath());
            }
            else
            {
                AssertValidatedPathPromotes(
                    runtime,
                    QuicS18P2DisableActiveMigrationTestSupport.CreatePreferredPath(parsed.PreferredAddress));
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0026")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0028")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0029")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0030")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0031")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreferredAddressLayoutAndParsingRoundTrip()
    {
        foreach (byte[] preferredConnectionId in PreferredConnectionIdCases())
        {
            QuicPreferredAddress preferredAddress = CreatePreferredAddressForConnectionId(preferredConnectionId);

            byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);
            AssertPreferredAddressValueMatches(preferredAddress, value);
            Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(value, out QuicTransportParameters parsed));
            Assert.NotNull(parsed.PreferredAddress);
            AssertPreferredAddressRoundTrip(preferredAddress, parsed.PreferredAddress!);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0024")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0033")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreferredAddressConnectionIdsCountAgainstActiveConnectionIdLimit()
    {
        foreach (byte[] preferredConnectionId in PreferredConnectionIdCases())
        {
            QuicPreferredAddress preferredAddress = CreatePreferredAddressForConnectionId(preferredConnectionId);

            byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);
            Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(value, out QuicTransportParameters parsed));
            Assert.NotNull(parsed.PreferredAddress);

            QuicConnectionPeerConnectionIdState state = new();
            Assert.True(state.TryAcceptPreferredAddressConnectionId(
                parsed.PreferredAddress!,
                activeConnectionIdLimit: 2UL,
                initialDestinationConnectionId: QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId,
                out QuicTransportErrorCode errorCode,
                out bool destinationConnectionIdChanged));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.False(destinationConnectionIdChanged);
            Assert.Equal(2, state.ActiveConnectionIdCount);

            Assert.False(state.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    sequenceNumber: 2,
                    retirePriorTo: 0,
                    connectionId: CreateSequentialBytes(preferredConnectionId.Length, 0x90),
                    statelessResetToken: CreateSequentialBytes(16, 0xA0)),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 2UL,
                initialDestinationConnectionId: QuicPreferredAddressRequirementTestSupport.InitialSourceConnectionId,
                out errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, errorCode);
        }
    }

    private static QuicPreferredAddress CreatePreferredAddressForConnectionId(byte[] preferredConnectionId)
    {
        return QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredConnectionId: preferredConnectionId,
            preferredIpv4Address: [198, 51, 100, (byte)(30 + preferredConnectionId.Length)],
            preferredIpv4Port: (ushort)(9_000 + preferredConnectionId.Length),
            preferredIpv6Address: CreateSequentialBytes(16, (byte)(0x40 + preferredConnectionId.Length)),
            preferredIpv6Port: (ushort)(9_500 + preferredConnectionId.Length),
            statelessResetToken: CreateSequentialBytes(16, (byte)(0x70 + preferredConnectionId.Length)));
    }

    private static QuicTransportParameters RoundTripClientParameterBlock(QuicTransportParameters parameters)
    {
        byte[] encoded = FormatTransportParameters(parameters, QuicTransportParameterRole.Client);
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));
        return parsed;
    }

    private static byte[] FormatTransportParameters(QuicTransportParameters parameters, QuicTransportParameterRole senderRole)
    {
        byte[] destination = new byte[512];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));
        return destination[..bytesWritten];
    }

    private static void AssertLocalStreamLimitIsApplied(ulong limit, bool bidirectional)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? limit : 0,
            peerUnidirectionalStreamLimit: bidirectional ? 0 : limit);

        ulong attempts = Math.Min(limit, 3);
        for (ulong attempt = 0; attempt < attempts; attempt++)
        {
            Assert.True(state.TryOpenLocalStream(
                bidirectional,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal((attempt * 4) + (bidirectional ? 0UL : 2UL), streamId.Value);
            Assert.Equal(default, blockedFrame);
        }

        if (limit <= attempts)
        {
            Assert.False(state.TryOpenLocalStream(
                bidirectional,
                out _,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
            Assert.Equal(limit, blockedFrame.MaximumStreams);
        }
    }

    private static void AssertValidatedPathPromotes(QuicConnectionRuntime runtime, QuicConnectionPathIdentity pathIdentity)
    {
        byte[] datagram = QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram();

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                pathIdentity,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            pathIdentity,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(pathIdentity, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == pathIdentity);
    }

    private static void AssertValidatedPathDoesNotPromote(QuicConnectionRuntime runtime, QuicConnectionPathIdentity pathIdentity)
    {
        byte[] datagram = QuicS18P2DisableActiveMigrationTestSupport.CreateDatagram();

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                pathIdentity,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            pathIdentity,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(QuicS18P2DisableActiveMigrationTestSupport.OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promoteActivePathEffect
            && promoteActivePathEffect.PathIdentity == pathIdentity);
    }

    private static void AssertPreferredAddressValueMatches(QuicPreferredAddress expected, byte[] value)
    {
        Assert.Equal(expected.IPv4Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv4AddressLength).ToArray());
        Assert.Equal((byte)(expected.IPv4Port >> 8), value[QuicPreferredAddressRequirementTestSupport.IPv4PortOffset]);
        Assert.Equal((byte)expected.IPv4Port, value[QuicPreferredAddressRequirementTestSupport.IPv4PortOffset + 1]);
        Assert.Equal(expected.IPv6Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv6AddressLength).ToArray());
        Assert.Equal((byte)(expected.IPv6Port >> 8), value[QuicPreferredAddressRequirementTestSupport.IPv6PortOffset]);
        Assert.Equal((byte)expected.IPv6Port, value[QuicPreferredAddressRequirementTestSupport.IPv6PortOffset + 1]);
        Assert.Equal(expected.ConnectionId.Length, value[QuicPreferredAddressRequirementTestSupport.ConnectionIdLengthOffset]);
        Assert.Equal(expected.ConnectionId, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.ConnectionIdOffset,
            expected.ConnectionId.Length).ToArray());

        int tokenOffset = QuicPreferredAddressRequirementTestSupport.ConnectionIdOffset + expected.ConnectionId.Length;
        Assert.Equal(expected.StatelessResetToken, value.AsSpan(
            tokenOffset,
            QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength).ToArray());
        Assert.Equal(tokenOffset + QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength, value.Length);
    }

    private static void AssertPreferredAddressRoundTrip(QuicPreferredAddress expected, QuicPreferredAddress actual)
    {
        Assert.Equal(expected.IPv4Address, actual.IPv4Address);
        Assert.Equal(expected.IPv4Port, actual.IPv4Port);
        Assert.Equal(expected.IPv6Address, actual.IPv6Address);
        Assert.Equal(expected.IPv6Port, actual.IPv6Port);
        Assert.Equal(expected.ConnectionId, actual.ConnectionId);
        Assert.Equal(expected.StatelessResetToken, actual.StatelessResetToken);
    }

    private static IEnumerable<byte[]> OpaqueConnectionIdCases()
    {
        yield return [];
        yield return [0x01];
        yield return [0x10, 0x11, 0x12, 0x13];
        yield return Enumerable.Range(0, 20).Select(static value => (byte)(0x40 + value)).ToArray();
    }

    private static IEnumerable<byte[]> StatelessResetTokenCases()
    {
        yield return CreateSequentialBytes(16, 0x20);
        yield return CreateSequentialBytes(16, 0x40);
        yield return CreateSequentialBytes(16, 0x60);
    }

    private static IEnumerable<byte[]> PreferredConnectionIdCases()
    {
        yield return [0x20];
        yield return [0x20, 0x21, 0x22, 0x23];
        yield return Enumerable.Range(0, 20).Select(static value => (byte)(0x20 + value)).ToArray();
    }

    private static byte[] CreateSequentialBytes(int length, byte firstValue)
    {
        return Enumerable.Range(0, length).Select(value => (byte)(firstValue + value)).ToArray();
    }
}
