namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0005")]
public sealed class REQ_QUIC_RFC9000_S9P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildOutboundNewTokenPayload_WritesANewTokenFrame()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        byte[] token =
        [
            0x10, 0x20, 0x30, 0x40,
        ];

        Assert.True(runtime.TryBuildOutboundNewTokenPayload(token, out byte[] payload));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(payload, out QuicNewTokenFrame frame, out int bytesConsumed));
        Assert.Equal(6, bytesConsumed);
        Assert.Equal(0x07, payload[0]);
        Assert.True(frame.Token.SequenceEqual(token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerValidationOfANewClientAddressEmitsANewTokenForTheValidatedPath()
    {
        QuicConnectionRuntime runtime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission();
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

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(validatedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(validatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == validatedPath
            && !promote.RestoreSavedState);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == validatedPath);
    }
}
