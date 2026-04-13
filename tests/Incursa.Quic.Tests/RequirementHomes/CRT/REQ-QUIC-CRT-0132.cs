using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0132")]
public sealed class REQ_QUIC_CRT_0132
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DormantDetachedCarrierDrivesAResumptionCapableClientHelloAttemptWithBinderAndClosedEarlyData()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();

        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;
        Assert.True(clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters()),
            nowTicks).StateChanged);

        byte[] clientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime);
        QuicResumptionClientHelloTestSupport.ParsedClientHello parsedClientHello =
            QuicResumptionClientHelloTestSupport.ParseClientHello(clientHelloBytes);

        Assert.True(parsedClientHello.HasPskKeyExchangeModes);
        Assert.True(parsedClientHello.HasPreSharedKey);
        Assert.True(parsedClientHello.PreSharedKeyIsLastExtension);
        Assert.False(parsedClientHello.HasEarlyData);
        Assert.Equal(detachedResumptionTicketSnapshot.TicketBytes.ToArray(), parsedClientHello.TicketIdentity);
        Assert.Equal(
            QuicResumptionClientHelloTestSupport.ComputeObfuscatedTicketAge(detachedResumptionTicketSnapshot, nowTicks),
            parsedClientHello.ObfuscatedTicketAge);
        Assert.Equal(
            unchecked((uint)1000 + detachedResumptionTicketSnapshot.TicketAgeAdd),
            parsedClientHello.ObfuscatedTicketAge);
        Assert.True(QuicResumptionClientHelloTestSupport.VerifyBinder(clientHelloBytes, detachedResumptionTicketSnapshot));
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
        Assert.Equal(QuicConnectionPhase.Establishing, clientRuntime.Phase);
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted);
        Assert.False(clientRuntime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.False(clientRuntime.TlsState.OneRttKeysAvailable);
        Assert.False(clientRuntime.HasOwnedResumptionTicket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BootstrapWithoutDormantCarrierStaysOnTheNonResumptionPath()
    {
        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client);

        long nowTicks = Stopwatch.Frequency;
        Assert.True(clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters()),
            nowTicks).StateChanged);

        QuicResumptionClientHelloTestSupport.ParsedClientHello parsedClientHello =
            QuicResumptionClientHelloTestSupport.ParseClientHello(
                QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime));

        Assert.False(parsedClientHello.HasPskKeyExchangeModes);
        Assert.False(parsedClientHello.HasPreSharedKey);
        Assert.False(parsedClientHello.HasEarlyData);
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
        Assert.Equal(QuicConnectionPhase.Establishing, clientRuntime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientHelloAttemptDoesNotClaimResumedHandshakeSuccess()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();

        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;
        Assert.True(clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters()),
            nowTicks).StateChanged);

        Assert.Equal(QuicConnectionPhase.Establishing, clientRuntime.Phase);
        Assert.False(clientRuntime.PeerHandshakeTranscriptCompleted);
        Assert.False(clientRuntime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.False(clientRuntime.TlsState.OneRttKeysAvailable);
        Assert.False(clientRuntime.HasOwnedResumptionTicket);
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDoesNotParticipateInThePSKAttemptPath()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();

        Assert.Throws<ArgumentException>(() => new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeResumptionOrEarlyDataPromises()
    {
        string[] forbiddenFragments = ["Resum", "EarlyData", "Psk", "Binder"];

        string[] publicMembers = typeof(QuicConnection).Assembly
            .GetExportedTypes()
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(member => $"{type.FullName}.{member.Name}"))
            .Concat(
                typeof(QuicConnection).Assembly.GetExportedTypes()
                    .Select(type => type.FullName ?? type.Name))
            .ToArray();

        Assert.DoesNotContain(publicMembers, member =>
            forbiddenFragments.Any(fragment => member.Contains(fragment, StringComparison.OrdinalIgnoreCase)));
    }
}
