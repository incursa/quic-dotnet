using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic;

/// <summary>
/// Owns the narrow managed TLS 1.3 key schedule slice for the client role.
/// </summary>
internal sealed class QuicTlsKeySchedule
{
    private const int HandshakeHeaderLength = 4;
    private const int HkdfLengthFieldLength = sizeof(ushort);
    private const int HkdfLabelLengthFieldLength = 1;
    private const int HkdfContextLengthFieldLength = 1;
    private const int HkdfExpandCounterLength = 1;
    private const byte HkdfExpandCounterValue = 1;
    private const int HashLength = 32;
    private const int Secp256r1CoordinateLength = 32;
    private const int UncompressedPointLength = 1 + (Secp256r1CoordinateLength * 2);
    private const byte UncompressedPointFormat = 0x04;
    private const ushort HandshakeTranscriptVerificationFailureAlertDescription = 0x0033;
    private const ushort HandshakeTranscriptParseFailureAlertDescription = 0x0032;

    private static readonly byte[] HkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");
    private static readonly byte[] DerivedLabel = Encoding.ASCII.GetBytes("derived");
    private static readonly byte[] ClientHandshakeTrafficLabel = Encoding.ASCII.GetBytes("c hs traffic");
    private static readonly byte[] ServerHandshakeTrafficLabel = Encoding.ASCII.GetBytes("s hs traffic");
    private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("finished");
    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = Encoding.ASCII.GetBytes("quic hp");
    private static readonly byte[] EmptyTranscriptHash = SHA256.HashData(Array.Empty<byte>());
    private static readonly QuicAeadUsageLimits HandshakeUsageLimits = new(64, 128);

    private readonly ECDiffieHellman localKeyPair;
    private readonly QuicTlsCipherSuiteProfile profile;
    private readonly ArrayBufferWriter<byte> transcriptBytes = new();
    private readonly byte[] localKeyShare;

    private byte[]? serverHandshakeTrafficSecret;
    private bool handshakeSecretsDerived;
    private bool peerFinishedVerified;
    private bool isTerminal;

    /// <summary>
    /// Creates the client-role TLS key schedule, optionally seeded with a deterministic local private key for tests.
    /// </summary>
    /// <param name="localPrivateKey">An optional P-256 private scalar to import for deterministic tests.</param>
    internal QuicTlsKeySchedule(ReadOnlyMemory<byte> localPrivateKey = default)
    {
        if (!QuicTlsCipherSuiteProfile.TryGet(QuicTlsCipherSuite.TlsAes128GcmSha256, out profile))
        {
            throw new InvalidOperationException("The supported TLS 1.3 profile is unavailable.");
        }

        localKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        if (!localPrivateKey.IsEmpty)
        {
            try
            {
                localKeyPair.ImportParameters(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = localPrivateKey.ToArray(),
                });
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException("The local private key must be a valid P-256 scalar.", nameof(localPrivateKey), ex);
            }
        }

        localKeyShare = ExportUncompressedPoint(localKeyPair.ExportParameters(true));
    }

    /// <summary>
    /// Gets the public local ephemeral key share associated with the current client key pair.
    /// </summary>
    public ReadOnlyMemory<byte> LocalKeyShare => localKeyShare;

    /// <summary>
    /// Gets whether the key schedule has already published handshake traffic secrets.
    /// </summary>
    public bool HandshakeSecretsDerived => handshakeSecretsDerived;

    /// <summary>
    /// Gets whether the peer Finished has been verified with the managed key schedule.
    /// </summary>
    public bool PeerFinishedVerified => peerFinishedVerified;

    /// <summary>
    /// Gets the peer Finished verify data for the current handshake transcript, if the handshake secret has been derived.
    /// </summary>
    internal bool TryGetExpectedPeerFinishedVerifyData(out byte[] verifyData)
    {
        verifyData = Array.Empty<byte>();

        if (serverHandshakeTrafficSecret is null)
        {
            return false;
        }

        verifyData = DeriveFinishedVerifyData(serverHandshakeTrafficSecret, HashTranscript());
        return true;
    }

    /// <summary>
    /// Processes one handshake transcript step and returns any bridge-visible updates produced by the key schedule.
    /// </summary>
    internal IReadOnlyList<QuicTlsStateUpdate> ProcessTranscriptStep(QuicTlsTranscriptStep step)
    {
        if (isTerminal || step.HandshakeMessageType is null || step.HandshakeMessageBytes.IsEmpty)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        return step.HandshakeMessageType.Value switch
        {
            QuicTlsHandshakeMessageType.ServerHello => ProcessServerHello(step),
            QuicTlsHandshakeMessageType.EncryptedExtensions
            or QuicTlsHandshakeMessageType.Certificate
            or QuicTlsHandshakeMessageType.CertificateVerify => AppendTranscriptMessage(step.HandshakeMessageBytes.Span),
            QuicTlsHandshakeMessageType.Finished => ProcessFinished(step),
            _ => AppendTranscriptMessage(step.HandshakeMessageBytes.Span),
        };
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessServerHello(QuicTlsTranscriptStep step)
    {
        if (handshakeSecretsDerived)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (step.SelectedCipherSuite != profile.CipherSuite
            || step.TranscriptHashAlgorithm != profile.TranscriptHashAlgorithm
            || step.NamedGroup != profile.NamedGroup
            || step.KeyShare.IsEmpty)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);
        ReadOnlySpan<byte> transcriptHash = HashTranscript();

        if (!TryDeriveHandshakeTrafficSecrets(step.KeyShare.Span, transcriptHash, out IReadOnlyList<QuicTlsStateUpdate> updates))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        handshakeSecretsDerived = true;
        return updates;
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessFinished(QuicTlsTranscriptStep step)
    {
        if (!handshakeSecretsDerived
            || serverHandshakeTrafficSecret is null
            || step.HandshakeMessageBytes.Length != HandshakeHeaderLength + HashLength)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        ReadOnlySpan<byte> expectedFinished = step.HandshakeMessageBytes.Span.Slice(HandshakeHeaderLength, HashLength);
        ReadOnlySpan<byte> transcriptHash = HashTranscript();
        byte[] expectedVerifyData = DeriveFinishedVerifyData(serverHandshakeTrafficSecret, transcriptHash);
        if (!expectedFinished.SequenceEqual(expectedVerifyData))
        {
            return BuildFatalAlert(HandshakeTranscriptVerificationFailureAlertDescription);
        }

        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);
        peerFinishedVerified = true;
        return [new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)];
    }

    private bool TryDeriveHandshakeTrafficSecrets(
        ReadOnlySpan<byte> peerKeyShareBytes,
        ReadOnlySpan<byte> transcriptHash,
        out IReadOnlyList<QuicTlsStateUpdate> updates)
    {
        updates = Array.Empty<QuicTlsStateUpdate>();

        if (peerKeyShareBytes.Length != UncompressedPointLength || peerKeyShareBytes[0] != UncompressedPointFormat)
        {
            return false;
        }

        byte[] sharedSecret;
        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            peer.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = peerKeyShareBytes.Slice(1, Secp256r1CoordinateLength).ToArray(),
                    Y = peerKeyShareBytes.Slice(1 + Secp256r1CoordinateLength, Secp256r1CoordinateLength).ToArray(),
                },
            });

            sharedSecret = localKeyPair.DeriveKeyMaterial(peer.PublicKey);
        }
        catch (CryptographicException)
        {
            return false;
        }

        byte[] earlySecret = HkdfExtract(new byte[HashLength], []);
        byte[] derivedSecret = HkdfExpandLabel(earlySecret, DerivedLabel, EmptyTranscriptHash, HashLength);
        byte[] handshakeSecret = HkdfExtract(derivedSecret, sharedSecret);
        serverHandshakeTrafficSecret = HkdfExpandLabel(handshakeSecret, ServerHandshakeTrafficLabel, transcriptHash, HashLength);

        if (!TryCreateHandshakePacketProtectionMaterial(
            HkdfExpandLabel(handshakeSecret, ClientHandshakeTrafficLabel, transcriptHash, HashLength),
            out QuicTlsPacketProtectionMaterial protectMaterial)
            || !TryCreateHandshakePacketProtectionMaterial(
                serverHandshakeTrafficSecret,
                out QuicTlsPacketProtectionMaterial openMaterial))
        {
            return false;
        }

        updates =
        [
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: openMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: protectMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.KeysAvailable,
                QuicTlsEncryptionLevel.Handshake),
        ];
        return true;
    }

    private static bool TryCreateHandshakePacketProtectionMaterial(
        ReadOnlySpan<byte> trafficSecret,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], 16);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], 12);
        byte[] headerProtectionKey = HkdfExpandLabel(trafficSecret, QuicHpLabel, [], 16);

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            HandshakeUsageLimits,
            out material);
    }

    private IReadOnlyList<QuicTlsStateUpdate> AppendTranscriptMessage(ReadOnlySpan<byte> handshakeMessageBytes)
    {
        if (handshakeMessageBytes.IsEmpty)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        Span<byte> destination = transcriptBytes.GetSpan(handshakeMessageBytes.Length);
        handshakeMessageBytes.CopyTo(destination);
        transcriptBytes.Advance(handshakeMessageBytes.Length);
        return Array.Empty<QuicTlsStateUpdate>();
    }

    private ReadOnlySpan<byte> HashTranscript()
    {
        return SHA256.HashData(transcriptBytes.WrittenSpan);
    }

    private static byte[] DeriveFinishedVerifyData(ReadOnlySpan<byte> trafficSecret, ReadOnlySpan<byte> transcriptHash)
    {
        byte[] finishedKey = HkdfExpandLabel(trafficSecret, FinishedLabel, [], HashLength);
        using HMACSHA256 hmac = new(finishedKey);
        return hmac.ComputeHash(transcriptHash.ToArray());
    }

    private static byte[] HkdfExtract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        using HMACSHA256 hmac = new(salt.ToArray());
        return hmac.ComputeHash(inputKeyMaterial.ToArray());
    }

    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int length)
    {
        int hkdfLabelLength = HkdfLengthFieldLength
            + HkdfLabelLengthFieldLength
            + HkdfLabelPrefix.Length
            + label.Length
            + HkdfContextLengthFieldLength
            + context.Length;

        Span<byte> hkdfLabel = stackalloc byte[hkdfLabelLength];
        int index = 0;

        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel, checked((ushort)length));
        index += HkdfLengthFieldLength;

        hkdfLabel[index++] = checked((byte)(HkdfLabelPrefix.Length + label.Length));
        HkdfLabelPrefix.CopyTo(hkdfLabel[index..]);
        index += HkdfLabelPrefix.Length;

        label.CopyTo(hkdfLabel[index..]);
        index += label.Length;

        hkdfLabel[index++] = checked((byte)context.Length);
        if (!context.IsEmpty)
        {
            context.CopyTo(hkdfLabel[index..]);
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

    private IReadOnlyList<QuicTlsStateUpdate> BuildFatalAlert(ushort alertDescription)
    {
        isTerminal = true;
        return [new QuicTlsStateUpdate(QuicTlsUpdateKind.FatalAlert, AlertDescription: alertDescription)];
    }

    private static byte[] ExportUncompressedPoint(ECParameters parameters)
    {
        if (parameters.Q.X is null || parameters.Q.Y is null)
        {
            throw new InvalidOperationException("The local key pair does not have an exportable public point.");
        }

        byte[] keyShare = new byte[UncompressedPointLength];
        keyShare[0] = UncompressedPointFormat;
        parameters.Q.X.CopyTo(keyShare, 1);
        parameters.Q.Y.CopyTo(keyShare, 1 + Secp256r1CoordinateLength);
        return keyShare;
    }
}
