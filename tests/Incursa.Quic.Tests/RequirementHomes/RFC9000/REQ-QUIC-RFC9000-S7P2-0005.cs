namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P2-0005")]
public sealed class REQ_QUIC_RFC9000_S7P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientHostUsesAnInitialDestinationConnectionIdAtLeastEightBytesLong()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId =
            QuicS7P2FirstFlightConnectionIdTestSupport.GetPrivateField<byte[]>(host, "initialDestinationConnectionId");

        Assert.True(initialDestinationConnectionId.Length >= 8);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientHostDoesNotUseAZeroLengthFirstInitialDestinationConnectionId()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId =
            QuicS7P2FirstFlightConnectionIdTestSupport.GetPrivateField<byte[]>(host, "initialDestinationConnectionId");

        Assert.NotEmpty(initialDestinationConnectionId);
        Assert.False(initialDestinationConnectionId.Length < 8);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ClientHostUsesTheEightByteMinimumForTheFirstInitialDestinationConnectionId()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId =
            QuicS7P2FirstFlightConnectionIdTestSupport.GetPrivateField<byte[]>(host, "initialDestinationConnectionId");

        Assert.Equal(8, initialDestinationConnectionId.Length);
    }
}
