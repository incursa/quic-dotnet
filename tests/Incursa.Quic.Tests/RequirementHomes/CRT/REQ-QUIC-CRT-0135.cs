using System.Linq;
using System.Reflection;

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

        QuicConnectionRuntime clientRuntime = InvokeCreateRuntime(typeof(QuicClientConnectionHost), clientSettings);
        Assert.Same(QuicNullDiagnosticsSink.Instance, GetPrivateField<IQuicDiagnosticsSink>(clientRuntime, "diagnosticsSink"));
        Assert.False(GetPrivateField<bool>(clientRuntime, "diagnosticsEnabled"));

        QuicServerConnectionOptions serverOptions = new();
        QuicConnectionRuntime serverRuntime = InvokeCreateRuntime(typeof(QuicListenerHost), serverOptions);
        Assert.Same(QuicNullDiagnosticsSink.Instance, GetPrivateField<IQuicDiagnosticsSink>(serverRuntime, "diagnosticsSink"));
        Assert.False(GetPrivateField<bool>(serverRuntime, "diagnosticsEnabled"));
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

        Assert.Same(QuicNullDiagnosticsSink.Instance, GetPrivateField<IQuicDiagnosticsSink>(runtime, "diagnosticsSink"));
        Assert.False(GetPrivateField<bool>(runtime, "diagnosticsEnabled"));
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionEmitDiagnosticEffect);
    }

    private static QuicConnectionRuntime InvokeCreateRuntime(Type hostType, object settings)
    {
        MethodInfo createRuntimeMethod = hostType
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(method => method.Name == "CreateRuntime" && method.GetParameters().Length == 1);

        object? runtime = createRuntimeMethod.Invoke(null, [settings]);
        return Assert.IsType<QuicConnectionRuntime>(runtime);
    }

    private static T GetPrivateField<T>(object target, string fieldName)
    {
        FieldInfo? field = target.GetType().GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return Assert.IsAssignableFrom<T>(field!.GetValue(target));
    }
}
