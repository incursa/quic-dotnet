namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P1P4-0004")]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0004")]
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
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0004")]
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
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0004")]
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
        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
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

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(5));
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
