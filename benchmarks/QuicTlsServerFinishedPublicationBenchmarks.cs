using BenchmarkDotNet.Attributes;
using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the server Finished publication path that derives and surfaces the first application packet-protection material.
/// </summary>
[MemoryDiagnoser]
public class QuicTlsServerFinishedPublicationBenchmarks
{
    private byte[] localHandshakePrivateKey = [];
    private byte[] localSigningPrivateKey = [];
    private byte[] localLeafCertificateDer = [];
    private QuicTransportParameters localTransportParameters = default!;
    private QuicTransportParameters peerTransportParameters = default!;
    private byte[] clientHelloTranscript = [];
    private byte[] finishedTranscript = [];
    private QuicTlsTransportBridgeDriver driver = default!;

    /// <summary>
    /// Prepares a representative server-role handshake boundary and the Finished transcript used by the benchmark.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        localHandshakePrivateKey = CreateScalar(0x22);
        localSigningPrivateKey = CreateScalar(0x44);
        localLeafCertificateDer = CreateLocalLeafCertificateDer(localSigningPrivateKey);
        localTransportParameters = CreateBootstrapLocalTransportParameters();
        peerTransportParameters = CreateClientTransportParameters();
        clientHelloTranscript = CreateServerRoleClientHello(peerTransportParameters);
        finishedTranscript = PrepareFinishedTranscript();
    }

    /// <summary>
    /// Rebuilds the deterministic server-handshake state to the boundary immediately before peer Finished is processed.
    /// </summary>
    [IterationSetup]
    public void IterationSetup()
    {
        driver = new QuicTlsTransportBridgeDriver(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        _ = driver.StartHandshake(localTransportParameters);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, clientHelloTranscript);
    }

    /// <summary>
    /// Measures the server Finished publication step that surfaces the explicit 1-RTT open/protect material.
    /// </summary>
    [Benchmark]
    public int PublishServerFinishedMaterial()
    {
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        return updates.Count;
    }

    private byte[] PrepareFinishedTranscript()
    {
        QuicTlsTransportBridgeDriver tempDriver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        _ = tempDriver.StartHandshake(localTransportParameters);
        _ = tempDriver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, clientHelloTranscript);

        FieldInfo keyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule keySchedule = (QuicTlsKeySchedule)keyScheduleField.GetValue(tempDriver)!;
        if (!keySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] finishedVerifyData))
        {
            throw new InvalidOperationException("Failed to prepare the representative server Finished transcript.");
        }

        return CreateFinishedTranscript(finishedVerifyData);
    }

    private static byte[] CreateLocalLeafCertificateDer(byte[] localSigningPrivateKey)
    {
        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        CertificateRequest request = new(
            "CN=Incursa.Quic CertificateVerify Benchmark",
            localCertificateKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        return certificate.Export(X509ContentType.Cert);
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreateClientTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };
    }

    private static byte[] CreateServerRoleClientHello(QuicTransportParameters peerTransportParameters)
    {
        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension();
        byte[] keyShareExtension = CreateClientKeyShareExtension();
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            peerTransportParameters,
            QuicTransportParameterRole.Client);

        int extensionsLength = supportedVersionsExtension.Length
            + keyShareExtension.Length
            + transportParametersExtension.Length;
        byte[] body = new byte[43 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        CreateSequentialBytes(0x10, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;

        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;

        body[index++] = 1;
        body[index++] = 0x00;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;
        supportedVersionsExtension.CopyTo(body.AsSpan(index));
        index += supportedVersionsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateClientSupportedVersionsExtension()
    {
        byte[] extension = new byte[7];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x002b);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), 3);
        index += 2;
        extension[index++] = 2;
        WriteUInt16(extension.AsSpan(index, 2), 0x0304);
        return extension;
    }

    private static byte[] CreateClientKeyShareExtension()
    {
        byte[] keyShare = CreateClientKeyShare();
        byte[] extension = new byte[2 + 2 + 2 + 2 + 2 + keyShare.Length];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)(2 + 2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)keyShare.Length);
        index += 2;
        keyShare.CopyTo(extension.AsSpan(index, keyShare.Length));
        return extension;
    }

    private static byte[] CreateClientKeyShare()
    {
        using ECDiffieHellman clientKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        clientKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(1),
        });

        ECParameters parameters = clientKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * 32)];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] CreateTransportParametersExtension(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] encodedTransportParameters = new byte[256];
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int transportParametersBytesWritten))
        {
            throw new InvalidOperationException("Failed to format the representative transport parameters.");
        }

        byte[] extension = new byte[4 + transportParametersBytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)transportParametersBytesWritten);
        encodedTransportParameters.AsSpan(0, transportParametersBytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static byte[] CreateFinishedTranscript(ReadOnlySpan<byte> verifyData)
    {
        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Finished, verifyData);
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private static void WriteUInt16(Span<byte> destination, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}
