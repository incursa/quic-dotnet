// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S9P6P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P3-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ProbePacketAddressFuzz_InitiatesPathValidationForEachChangedClientAddress()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new($"203.0.113.{70 + iteration}", RemotePort: 443);
            QuicPreferredAddress preferredAddress = CreatePreferredAddress(iteration);
            QuicConnectionPathIdentity changedClientAddress = new(
                new IPAddress(preferredAddress.IPv4Address).ToString(),
                RemotePort: preferredAddress.IPv4Port);
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
                activePath,
                new QuicTransportParameters
                {
                    InitialSourceConnectionId = [0x10, 0x11, 0x12, (byte)(0x20 + iteration)],
                    PreferredAddress = preferredAddress,
                });

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    changedClientAddress,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20 + iteration);

            Assert.True(result.StateChanged);
            Assert.True(runtime.CandidatePaths.TryGetValue(changedClientAddress, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.False(candidatePath.Validation.IsAbandoned);
            Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
            Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
            QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
                result,
                changedClientAddress,
                runtime: runtime);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P3-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PreferredAddressConnectionIdFuzz_RemainsUsableIndependentOfAdvertisedAddress()
    {
        Span<byte> destination = stackalloc byte[256];

        for (int iteration = 0; iteration < 8; iteration++)
        {
            byte[] expectedConnectionId = [0x30, 0x31, 0x32, (byte)(0x40 + iteration)];
            QuicPreferredAddress source = CreatePreferredAddress(
                iteration,
                preferredConnectionId: expectedConnectionId);

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                new QuicTransportParameters
                {
                    PreferredAddress = source,
                },
                QuicTransportParameterRole.Server,
                destination,
                out int bytesWritten));

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                destination[..bytesWritten],
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsed));

            Assert.NotNull(parsed.PreferredAddress);
            Assert.Equal(expectedConnectionId, parsed.PreferredAddress!.ConnectionId);
            Assert.Equal(source.IPv4Address, parsed.PreferredAddress.IPv4Address);
            Assert.Equal(source.IPv4Port, parsed.PreferredAddress.IPv4Port);
            Assert.Equal(source.IPv6Address, parsed.PreferredAddress.IPv6Address);
            Assert.Equal(source.IPv6Port, parsed.PreferredAddress.IPv6Port);

            QuicConnectionPathIdentity unrelatedPath = new($"203.0.113.{120 + iteration}", RemotePort: (ushort)(5000 + iteration));
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithOneRttKeysAndCommittedPeerTransportParameters(
                unrelatedPath,
                new QuicTransportParameters { PreferredAddress = parsed.PreferredAddress });

            Assert.Equal(expectedConnectionId, runtime.TlsState.PeerTransportParameters!.PreferredAddress!.ConnectionId);
            Assert.Equal(unrelatedPath, runtime.ActivePath!.Value.Identity);
        }
    }

    private static QuicPreferredAddress CreatePreferredAddress(
        int iteration,
        byte[]? preferredConnectionId = null)
    {
        byte lowByte = (byte)(80 + iteration);
        return new QuicPreferredAddress
        {
            IPv4Address = [198, 51, 100, lowByte],
            IPv4Port = (ushort)(9400 + iteration),
            IPv6Address =
            [
                0x20, 0x01, 0x0D, 0xB8,
                0x00, 0x01, 0x00, 0x02,
                0x00, 0x03, 0x00, 0x04,
                0x00, 0x05, 0x00, lowByte,
            ],
            IPv6Port = (ushort)(9500 + iteration),
            ConnectionId = preferredConnectionId ?? [0x20, 0x21, 0x22, (byte)(0x30 + iteration)],
            StatelessResetToken = Enumerable
                .Range(0, QuicPreferredAddressRequirementTestSupport.StatelessResetTokenLength)
                .Select(value => (byte)(0x60 + iteration + value))
                .ToArray(),
        };
    }
}
