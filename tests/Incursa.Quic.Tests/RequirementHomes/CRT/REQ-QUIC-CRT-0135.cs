using System.Net;
using System.Net.Security;
using System.Linq;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0135")]
public sealed class REQ_QUIC_CRT_0135
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HostRuntimeSetupResolvesTheNullDiagnosticsSinkOncePerConnection()
    {
        QuicClientConnectionSettings clientSettings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint()),
            "options");

        QuicConnectionRuntime clientRuntime = QuicClientConnectionHost.CreateRuntime(clientSettings);
        Assert.Same(QuicNullDiagnosticsSink.Instance, clientRuntime.DiagnosticsSink);
        Assert.False(clientRuntime.DiagnosticsEnabled);

        QuicServerConnectionOptions serverOptions = new();
        using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [SslApplicationProtocol.Http3],
            static (_, _, _) => new ValueTask<QuicServerConnectionOptions>(new QuicServerConnectionOptions()),
            listenBacklog: 1);

        QuicConnectionRuntime serverRuntime = listenerHost.CreateRuntime(serverOptions);
        Assert.Same(QuicNullDiagnosticsSink.Instance, serverRuntime.DiagnosticsSink);
        Assert.False(serverRuntime.DiagnosticsEnabled);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DisabledRuntimePacketProcessingDoesNotAppendDiagnosticEffects()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "203.0.113.20",
            LocalAddress: "198.51.100.4",
            RemotePort: 443,
            LocalPort: 61235);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                PathIdentity: pathIdentity,
                Datagram: new byte[] { 0xC0 }),
            nowTicks: 1);

        Assert.Same(QuicNullDiagnosticsSink.Instance, runtime.DiagnosticsSink);
        Assert.False(runtime.DiagnosticsEnabled);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionEmitDiagnosticEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DisabledRetryReplayDoesNotAppendDiagnosticEffects()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        Assert.True(retryResult.StateChanged);
        Assert.DoesNotContain(retryResult.Effects, effect => effect is QuicConnectionEmitDiagnosticEffect);
    }

}
