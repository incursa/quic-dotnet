using System.Linq;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0149")]
public sealed class REQ_QUIC_CRT_0149
{
    private static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRuntimeKeepsEarlyDataAdmissionClosed()
    {
        using QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.Equal(QuicTlsRole.Server, serverRuntime.TlsState.Role);
        Assert.False(serverRuntime.IsEarlyDataAdmissionOpen);
        Assert.False(serverRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(serverRuntime.HasDormantEarlyDataAttemptReadiness);
        Assert.False(serverRuntime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointLeavesUnroutedZeroRttDatagramsOutsideAdmission()
    {
        byte[] zeroRttPacket = BuildZeroRttPacket(
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            [0x21, 0x22, 0x23, 0x24],
            QuicS17P2P3TestSupport.CreatePingPayload());

        Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket longHeader));
        Assert.Equal(QuicVersionNegotiation.Version1, longHeader.Version);
        Assert.Equal(QuicLongPacketTypeBits.ZeroRtt, longHeader.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(zeroRttPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);

        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(zeroRttPacket, BootstrapPath);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzUnroutedZeroRttDatagramsRemainOutsideServerAdmission()
    {
        Random random = new(0x0149);
        using QuicConnectionRuntimeEndpoint endpoint = new(1);

        for (int iteration = 0; iteration < 96; iteration++)
        {
            byte[] destinationConnectionId = CreateConnectionId(random, random.Next(1, 21));
            byte[] sourceConnectionId = CreateConnectionId(random, random.Next(1, 21));
            byte[] payload = CreatePayload(random, random.Next(1, 64));
            byte[] zeroRttPacket = BuildZeroRttPacket(
                destinationConnectionId,
                sourceConnectionId,
                payload);

            Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket longHeader));
            Assert.Equal(QuicLongPacketTypeBits.ZeroRtt, longHeader.LongPacketTypeBits);

            QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
                zeroRttPacket,
                new QuicConnectionPathIdentity(
                    $"203.0.113.{1 + (iteration % 200)}",
                    "198.51.100.20",
                    443,
                    12000 + iteration));

            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
            Assert.Null(result.Handle);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeServerEarlyDataAdmissionOrAntiReplayPromises()
    {
        string[] forbiddenFragments = ["ZeroRtt", "0Rtt", "EarlyData", "AntiReplay"];

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

    private static byte[] BuildZeroRttPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        byte[] payload)
    {
        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TrySetInitialDestinationConnectionId(destinationConnectionId));
        Assert.True(coordinator.TrySetSourceConnectionId(sourceConnectionId));

        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            payload,
            zeroRttMaterial,
            out byte[] zeroRttPacket));

        return zeroRttPacket;
    }

    private static byte[] CreateConnectionId(Random random, int length)
    {
        byte[] connectionId = new byte[length];
        random.NextBytes(connectionId);
        return connectionId;
    }

    private static byte[] CreatePayload(Random random, int length)
    {
        byte[] payload = new byte[length];
        random.NextBytes(payload);
        return payload;
    }
}
