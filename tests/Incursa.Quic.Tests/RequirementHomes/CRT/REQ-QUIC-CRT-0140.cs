using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0140")]
public sealed class REQ_QUIC_CRT_0140
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RichDetachedCarrierMarksLaterManagedClientSetupAsReadyForA0RttAttemptWithoutOpeningAdmission()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4096);

        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.True(clientRuntime.HasDormantEarlyDataAttemptReadiness);
        Assert.False(clientRuntime.HasOwnedResumptionTicket);
        Assert.NotNull(clientRuntime.DormantDetachedResumptionTicketSnapshot);
        Assert.True(clientRuntime.DormantDetachedResumptionTicketSnapshot!.HasResumptionCredentialMaterial);
        Assert.True(clientRuntime.DormantDetachedResumptionTicketSnapshot.HasEarlyDataPrerequisiteMaterial);
        Assert.Equal(4096u, clientRuntime.DormantDetachedResumptionTicketSnapshot.TicketMaxEarlyDataSize);
        Assert.NotNull(clientRuntime.DormantDetachedResumptionTicketSnapshot.PeerTransportParameters);
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
        Assert.Equal(QuicConnectionPhase.Establishing, clientRuntime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void WithoutTheEarlyDataPrerequisiteMaterialTheReadinessBoundaryStaysClosed()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();

        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(clientRuntime.HasDormantEarlyDataAttemptReadiness);
        Assert.NotNull(clientRuntime.DormantDetachedResumptionTicketSnapshot);
        Assert.True(clientRuntime.DormantDetachedResumptionTicketSnapshot!.HasResumptionCredentialMaterial);
        Assert.False(clientRuntime.DormantDetachedResumptionTicketSnapshot.HasEarlyDataPrerequisiteMaterial);
        Assert.Null(clientRuntime.DormantDetachedResumptionTicketSnapshot.TicketMaxEarlyDataSize);
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeBroad0RttAntiReplayOrKeyUpdatePromises()
    {
        string[] forbiddenFragments = ["0Rtt", "EarlyData", "Resum", "Binder", "AntiReplay", "KeyUpdate"];

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
