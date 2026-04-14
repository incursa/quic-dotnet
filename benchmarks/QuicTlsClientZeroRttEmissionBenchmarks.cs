using BenchmarkDotNet.Attributes;
using System.Diagnostics;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the client-side 0-RTT emission path.
/// </summary>
[MemoryDiagnoser]
public class QuicTlsClientZeroRttEmissionBenchmarks
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] SourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    private byte[] localHandshakePrivateKey = [];
    private QuicTransportParameters localTransportParameters = default!;
    private QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot = default!;
    private long observedAtTicks;
    private byte[] zeroRttApplicationPayload = [];
    private QuicTlsPacketProtectionMaterial zeroRttPacketProtectionMaterial;

    /// <summary>
    /// Prepares representative client 0-RTT inputs and reusable packet material.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        localHandshakePrivateKey = CreateScalar(0x11);
        localTransportParameters = CreateBootstrapLocalTransportParameters();
        detachedResumptionTicketSnapshot = CreateDetachedResumptionTicketSnapshot();
        observedAtTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;
        zeroRttApplicationPayload = CreateZeroRttApplicationPayload();

        if (!TryDeriveClientZeroRttPacketProtectionMaterial(out zeroRttPacketProtectionMaterial))
        {
            throw new InvalidOperationException("Failed to prepare representative 0-RTT packet-protection material.");
        }
    }

    /// <summary>
    /// Measures the client-side resumption ClientHello attempt plus 0-RTT packet-protection material derivation.
    /// </summary>
    [Benchmark]
    public int DeriveClientZeroRttPacketProtectionMaterial()
    {
        return TryDeriveClientZeroRttPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial material)
            ? material.AeadKey.Length + material.AeadIv.Length + material.HeaderProtectionKey.Length
            : -1;
    }

    /// <summary>
    /// Measures protected client 0-RTT application-packet formatting and packet protection.
    /// </summary>
    [Benchmark]
    public int ProtectClientZeroRttApplicationPacket()
    {
        QuicHandshakeFlowCoordinator packetCoordinator = new();
        if (!packetCoordinator.TrySetInitialDestinationConnectionId(InitialDestinationConnectionId)
            || !packetCoordinator.TrySetSourceConnectionId(SourceConnectionId)
            || !packetCoordinator.TryBuildProtectedZeroRttApplicationPacket(
                zeroRttApplicationPayload,
                zeroRttPacketProtectionMaterial,
                out byte[] protectedPacket))
        {
            return -1;
        }

        return protectedPacket.Length;
    }

    private bool TryDeriveClientZeroRttPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial material)
    {
        QuicTlsKeySchedule schedule = new(QuicTlsRole.Client, localHandshakePrivateKey);
        if (!schedule.TryCreateClientHello(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            observedAtTicks,
            out byte[] clientHelloBytes))
        {
            material = default;
            return false;
        }

        return schedule.TryDeriveClientEarlyTrafficPacketProtectionMaterial(
            detachedResumptionTicketSnapshot,
            clientHelloBytes,
            out material);
    }

    private static QuicDetachedResumptionTicketSnapshot CreateDetachedResumptionTicketSnapshot()
    {
        return new QuicDetachedResumptionTicketSnapshot(
            ticketBytes: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF },
            ticketNonce: new byte[] { 0x01, 0x02, 0x03 },
            ticketLifetimeSeconds: 7_200,
            ticketAgeAdd: 0x0102_0304,
            capturedAtTicks: 1_234,
            resumptionMasterSecret: CreateScalar(0x20),
            ticketMaxEarlyDataSize: 4_096,
            peerTransportParameters: CreatePeerTransportParameters());
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = SourceConnectionId,
        };
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            InitialMaxData = 1,
            InitialMaxStreamDataBidiLocal = 1,
            InitialMaxStreamDataBidiRemote = 1,
            InitialMaxStreamDataUni = 1,
            InitialMaxStreamsBidi = 1,
            InitialMaxStreamsUni = 1,
            ActiveConnectionIdLimit = 2,
            InitialSourceConnectionId = SourceConnectionId,
        };
    }

    private static byte[] CreateZeroRttApplicationPayload()
    {
        byte[] applicationPayload =
            new byte[QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength];
        if (!QuicFrameCodec.TryFormatPingFrame(applicationPayload, out int bytesWritten) || bytesWritten <= 0)
        {
            throw new InvalidOperationException("Failed to prepare representative 0-RTT application payload.");
        }

        return applicationPayload;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}
