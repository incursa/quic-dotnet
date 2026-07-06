// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-4-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0410
{
    [Fact]
    [Requirement("RFC9000-S8-1-4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidateNewToken_AcceptsUnchangedClientIpAddress()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(token, "203.0.113.10", issuedAt.AddSeconds(1)));
    }

    [Fact]
    [Requirement("RFC9000-S8-1-4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidateNewToken_RejectsChangedClientIpAddress()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", issuedAt);

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.IntegrityFailure,
            protector.ValidateNewToken(token, "203.0.113.11", issuedAt.AddSeconds(1)));
    }

    [Fact]
    [Requirement("RFC9000-S8-1-4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewTokenEmissionOnValidatedPath_ProducesATokenBoundToTheValidatedRemoteAddress()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        QuicConnectionRuntime runtime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission(protector);
        QuicConnectionPathIdentity validatedPath = QuicS9P3TokenEmissionTestSupport.ValidatedPath;
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                validatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            validatedPath,
            observedAtTicks: 30);
        QuicConnectionSendDatagramEffect sendEffect = QuicS13AckPiggybackTestSupport.FindNewTokenSendEffect(
            runtime,
            validationResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> tokenPayload = payloadBytes;
        if (QuicFrameCodec.TryParseAckFrame(tokenPayload, out _, out int ackBytesConsumed))
        {
            tokenPayload = QuicS13AckPiggybackTestSupport.SkipPadding(tokenPayload[ackBytesConsumed..]);
        }

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(
            tokenPayload,
            out QuicNewTokenFrame newTokenFrame,
            out int tokenBytesConsumed));

        Assert.True(QuicS13AckPiggybackTestSupport.SkipPadding(tokenPayload[tokenBytesConsumed..]).IsEmpty);
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(newTokenFrame.Token, validatedPath.RemoteAddress, DateTimeOffset.UtcNow));
        Assert.Equal(
            QuicAddressValidationTokenValidationResult.IntegrityFailure,
            protector.ValidateNewToken(newTokenFrame.Token, "203.0.113.99", DateTimeOffset.UtcNow));
    }

    [Fact]
    [Requirement("RFC9000-S8-1-4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewTokenValidationRequiresTheIssuingClientAddressContext()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        (string ClientAddress, int? ClientPort, string ChangedAddress, int? ChangedPort)[] contexts =
        [
            ("203.0.113.10", null, "203.0.113.11", null),
            ("198.51.100.20", 443, "198.51.100.21", 443),
            ("2001:db8::10", null, "2001:db8::11", null),
            ("2001:db8::20", 8443, "2001:db8::21", 8443),
        ];

        foreach ((string clientAddress, int? clientPort, string changedAddress, int? changedPort) in contexts)
        {
            byte[] token = IssueNewToken(protector, clientAddress, clientPort, issuedAt);

            Assert.Equal(
                QuicAddressValidationTokenValidationResult.Valid,
                ValidateNewToken(protector, token, clientAddress, clientPort, issuedAt.AddSeconds(1)));
            Assert.Equal(
                QuicAddressValidationTokenValidationResult.IntegrityFailure,
                ValidateNewToken(protector, token, changedAddress, changedPort, issuedAt.AddSeconds(1)));

            if (clientPort.HasValue)
            {
                Assert.Equal(
                    QuicAddressValidationTokenValidationResult.IntegrityFailure,
                    ValidateNewToken(protector, token, clientAddress, clientPort.Value + 1, issuedAt.AddSeconds(1)));
            }
        }
    }

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(5));
    }

    private static byte[] IssueNewToken(
        QuicAddressValidationTokenProtector protector,
        string clientAddress,
        int? clientPort,
        DateTimeOffset issuedAt)
    {
        return clientPort.HasValue
            ? protector.IssueNewToken(clientAddress, clientPort.Value, issuedAt)
            : protector.IssueNewToken(clientAddress, issuedAt);
    }

    private static QuicAddressValidationTokenValidationResult ValidateNewToken(
        QuicAddressValidationTokenProtector protector,
        ReadOnlySpan<byte> token,
        string clientAddress,
        int? clientPort,
        DateTimeOffset now)
    {
        return clientPort.HasValue
            ? protector.ValidateNewToken(token, clientAddress, clientPort.Value, now)
            : protector.ValidateNewToken(token, clientAddress, now);
    }

    private static byte[] CreateSecret()
    {
        byte[] secret = new byte[QuicAddressValidationTokenProtector.SecretLength];
        for (int index = 0; index < secret.Length; index++)
        {
            secret[index] = unchecked((byte)(0x50 + index));
        }

        return secret;
    }
}
