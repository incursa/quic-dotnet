using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Tests;

internal static class QuicRfc9001KeyPhaseTestSupport
{
    private const int TrafficSecretLength = 32;
    private const int AeadKeyLength = 16;
    private const int AeadIvLength = 12;
    private const int HkdfLengthFieldLength = sizeof(ushort);
    private const int HkdfLabelLengthFieldLength = 1;
    private const int HkdfContextLengthFieldLength = 1;
    private const int HkdfExpandCounterLength = 1;
    private const byte HkdfExpandCounterValue = 1;

    private static readonly byte[] KeyPhaseDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] HkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");
    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicKeyUpdateLabel = Encoding.ASCII.GetBytes("quic ku");

    internal static readonly QuicConnectionPathIdentity PacketPathIdentity =
        new("203.0.113.10", RemotePort: 443);

    internal static void ConfigureKeyPhaseDestinationConnectionId(QuicConnectionRuntime runtime)
    {
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(KeyPhaseDestinationConnectionId));
    }

    internal static QuicHandshakeFlowCoordinator CreatePacketCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new(KeyPhaseDestinationConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(KeyPhaseDestinationConnectionId));
        return coordinator;
    }

    internal static QuicConnectionRuntime CreateEstablishingClientRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client);
    }

    internal static bool TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
        QuicConnectionRuntime runtime,
        out QuicTlsPacketProtectionMaterial openMaterial,
        out QuicTlsPacketProtectionMaterial protectMaterial)
    {
        FieldInfo runtimeBridgeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsTransportBridgeDriver runtimeBridgeDriver =
            (QuicTlsTransportBridgeDriver)runtimeBridgeDriverField.GetValue(runtime)!;

        MethodInfo deriveMethod = typeof(QuicTlsTransportBridgeDriver).GetMethod(
            "TryDeriveOneRttSuccessorPacketProtectionMaterial",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        object?[] arguments =
        [
            default(QuicTlsPacketProtectionMaterial),
            default(QuicTlsPacketProtectionMaterial),
        ];

        if (!(bool)deriveMethod.Invoke(runtimeBridgeDriver, arguments)!)
        {
            openMaterial = default;
            protectMaterial = default;
            return false;
        }

        openMaterial = (QuicTlsPacketProtectionMaterial)arguments[0]!;
        protectMaterial = (QuicTlsPacketProtectionMaterial)arguments[1]!;
        return true;
    }

    internal static bool TryInstallRuntimeOneRttKeyUpdate(QuicConnectionRuntime runtime)
    {
        FieldInfo runtimeBridgeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsTransportBridgeDriver runtimeBridgeDriver =
            (QuicTlsTransportBridgeDriver)runtimeBridgeDriverField.GetValue(runtime)!;

        MethodInfo installMethod = typeof(QuicTlsTransportBridgeDriver).GetMethod(
            "TryInstallOneRttKeyUpdate",
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            Type.EmptyTypes,
            modifiers: null)!;

        return (bool)installMethod.Invoke(runtimeBridgeDriver, [])!;
    }

    internal static bool TryInstallRuntimeRepeatedOneRttKeyUpdate(
        QuicConnectionRuntime runtime,
        ulong nowMicros)
    {
        FieldInfo runtimeBridgeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsTransportBridgeDriver runtimeBridgeDriver =
            (QuicTlsTransportBridgeDriver)runtimeBridgeDriverField.GetValue(runtime)!;

        MethodInfo installMethod = typeof(QuicTlsTransportBridgeDriver).GetMethod(
            "TryInstallRepeatedOneRttKeyUpdate",
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            [typeof(ulong)],
            modifiers: null)!;

        return (bool)installMethod.Invoke(runtimeBridgeDriver, [nowMicros])!;
    }

    internal static bool TryGetRuntimeApplicationTrafficSecrets(
        QuicConnectionRuntime runtime,
        out byte[] clientApplicationTrafficSecret,
        out byte[] serverApplicationTrafficSecret)
    {
        clientApplicationTrafficSecret = [];
        serverApplicationTrafficSecret = [];

        FieldInfo runtimeBridgeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsTransportBridgeDriver runtimeBridgeDriver =
            (QuicTlsTransportBridgeDriver)runtimeBridgeDriverField.GetValue(runtime)!;

        FieldInfo keyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        QuicTlsKeySchedule keySchedule = (QuicTlsKeySchedule)keyScheduleField.GetValue(runtimeBridgeDriver)!;

        FieldInfo clientSecretField = typeof(QuicTlsKeySchedule).GetField(
            "clientApplicationTrafficSecret",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        FieldInfo serverSecretField = typeof(QuicTlsKeySchedule).GetField(
            "serverApplicationTrafficSecret",
            BindingFlags.NonPublic | BindingFlags.Instance)!;

        byte[]? clientSecret = (byte[]?)clientSecretField.GetValue(keySchedule);
        byte[]? serverSecret = (byte[]?)serverSecretField.GetValue(keySchedule);
        if (clientSecret is null || serverSecret is null)
        {
            return false;
        }

        clientApplicationTrafficSecret = clientSecret.ToArray();
        serverApplicationTrafficSecret = serverSecret.ToArray();
        return true;
    }

    internal static byte[] DeriveQuicKeyUpdateTrafficSecret(ReadOnlySpan<byte> currentTrafficSecret)
    {
        return HkdfExpandLabel(currentTrafficSecret, QuicKeyUpdateLabel, [], TrafficSecretLength);
    }

    internal static byte[] DeriveTrafficSecretWithLabel(
        ReadOnlySpan<byte> currentTrafficSecret,
        ReadOnlySpan<byte> label)
    {
        return HkdfExpandLabel(currentTrafficSecret, label, [], TrafficSecretLength);
    }

    internal static bool TryCreateOneRttPacketProtectionMaterialFromTrafficSecret(
        ReadOnlySpan<byte> trafficSecret,
        ReadOnlySpan<byte> retainedHeaderProtectionKey,
        out QuicTlsPacketProtectionMaterial material)
    {
        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], AeadKeyLength);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], AeadIvLength);

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            retainedHeaderProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out material);
    }

    internal static byte[] CreateSuccessorPhaseOneApplicationPacket(QuicTlsPacketProtectionMaterial openMaterial)
    {
        return BuildProtectedApplicationPacket(
            openMaterial,
            keyPhase: true,
            CreatePingPayload());
    }

    internal static byte[] BuildProtectedApplicationPacket(
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        byte[] payload)
    {
        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            keyPhase,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    internal static byte[] CreateTamperedSuccessorPhaseOneApplicationPacket(QuicTlsPacketProtectionMaterial openMaterial)
    {
        byte[] protectedPacket = CreateSuccessorPhaseOneApplicationPacket(openMaterial);

        protectedPacket[^1] ^= 0x80;
        return protectedPacket;
    }

    internal static byte[] CreatePingPayload()
    {
        byte[] payload = new byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }

    private static byte[] HkdfExpandLabel(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        int length)
    {
        int hkdfLabelLength = HkdfLengthFieldLength
            + HkdfLabelLengthFieldLength
            + HkdfLabelPrefix.Length
            + label.Length
            + HkdfContextLengthFieldLength
            + context.Length;

        byte[] hkdfLabel = new byte[hkdfLabelLength];
        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel.AsSpan(0, HkdfLengthFieldLength), checked((ushort)length));
        hkdfLabel[HkdfLengthFieldLength] = checked((byte)(HkdfLabelPrefix.Length + label.Length));

        int index = HkdfLengthFieldLength + HkdfLabelLengthFieldLength;
        HkdfLabelPrefix.CopyTo(hkdfLabel.AsSpan(index));
        index += HkdfLabelPrefix.Length;

        label.CopyTo(hkdfLabel.AsSpan(index));
        index += label.Length;

        hkdfLabel[index++] = checked((byte)context.Length);
        if (!context.IsEmpty)
        {
            context.CopyTo(hkdfLabel.AsSpan(index));
        }

        byte[] expandInput = new byte[hkdfLabel.Length + HkdfExpandCounterLength];
        hkdfLabel.CopyTo(expandInput);
        expandInput[^1] = HkdfExpandCounterValue;

        using HMACSHA256 hmac = new(secret.ToArray());
        byte[] output = hmac.ComputeHash(expandInput);
        if (output.Length == length)
        {
            return output;
        }

        byte[] truncated = new byte[length];
        output.AsSpan(..length).CopyTo(truncated);
        return truncated;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
