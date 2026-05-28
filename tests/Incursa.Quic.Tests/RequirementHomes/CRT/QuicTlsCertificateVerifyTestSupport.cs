// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Incursa.Quic.Tests;

internal static class QuicTlsCertificateVerifyTestSupport
{
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = 2;
    private const int UInt24Length = 3;
    private const int CertificateVerifySignedDataPrefixLength = 64;
    private const DSASignatureFormat CertificateVerifySignatureFormat = DSASignatureFormat.Rfc3279DerSequence;

    private static readonly byte[] ServerCertificateVerifyContext =
        Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify");
    private static readonly byte[] ClientCertificateVerifyContext =
        Encoding.ASCII.GetBytes("TLS 1.3, client CertificateVerify");

    internal static byte[] CreateLeafCertificateDer(ECDsa leafKey)
    {
        ArgumentNullException.ThrowIfNull(leafKey);

        CertificateRequest request = new(
            "CN=Incursa.Quic CertificateVerify Test",
            leafKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        return certificate.Export(X509ContentType.Cert);
    }

    internal static byte[] CreateCertificateTranscript(ReadOnlySpan<byte> leafCertificateDer)
    {
        if (leafCertificateDer.IsEmpty)
        {
            throw new ArgumentException("The leaf certificate must not be empty.", nameof(leafCertificateDer));
        }

        int certificateEntryLength = checked(UInt24Length + leafCertificateDer.Length + UInt16Length);
        byte[] body = new byte[1 + UInt24Length + certificateEntryLength];
        int index = 0;

        body[index++] = 0x00;
        WriteUInt24(body.AsSpan(index, UInt24Length), certificateEntryLength);
        index += UInt24Length;

        WriteUInt24(body.AsSpan(index, UInt24Length), leafCertificateDer.Length);
        index += UInt24Length;
        leafCertificateDer.CopyTo(body.AsSpan(index, leafCertificateDer.Length));
        index += leafCertificateDer.Length;

        WriteUInt16(body.AsSpan(index, UInt16Length), 0);

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Certificate, body);
    }

    internal static byte[] CreateCertificateChainTranscript(params byte[][] certificateChainDer)
    {
        ArgumentNullException.ThrowIfNull(certificateChainDer);
        if (certificateChainDer.Length == 0)
        {
            throw new ArgumentException("The certificate chain must contain at least one entry.", nameof(certificateChainDer));
        }

        int certificateListLength = 0;
        for (int i = 0; i < certificateChainDer.Length; i++)
        {
            byte[] certificateDer = certificateChainDer[i];
            if (certificateDer is null || certificateDer.Length == 0)
            {
                throw new ArgumentException("Certificate chain entries must not be empty.", nameof(certificateChainDer));
            }

            certificateListLength = checked(certificateListLength + UInt24Length + certificateDer.Length + UInt16Length);
        }

        byte[] body = new byte[1 + UInt24Length + certificateListLength];
        int index = 0;

        body[index++] = 0x00;
        WriteUInt24(body.AsSpan(index, UInt24Length), certificateListLength);
        index += UInt24Length;

        for (int i = 0; i < certificateChainDer.Length; i++)
        {
            byte[] certificateDer = certificateChainDer[i];
            WriteUInt24(body.AsSpan(index, UInt24Length), certificateDer.Length);
            index += UInt24Length;
            certificateDer.CopyTo(body.AsSpan(index, certificateDer.Length));
            index += certificateDer.Length;
            WriteUInt16(body.AsSpan(index, UInt16Length), 0);
            index += UInt16Length;
        }

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Certificate, body);
    }

    internal static byte[] CreateCertificateRequestTranscript()
    {
        Span<byte> body = stackalloc byte[11];
        int index = 0;

        body[index++] = 0x00;
        WriteUInt16(body.Slice(index, UInt16Length), 8);
        index += UInt16Length;
        WriteUInt16(body.Slice(index, UInt16Length), 0x000D);
        index += UInt16Length;
        WriteUInt16(body.Slice(index, UInt16Length), 4);
        index += UInt16Length;
        WriteUInt16(body.Slice(index, UInt16Length), 2);
        index += UInt16Length;
        WriteUInt16(body.Slice(index, UInt16Length), (ushort)QuicTlsSignatureScheme.EcdsaSecp256r1Sha256);

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.CertificateRequest, body);
    }

    internal static byte[] CreateCertificateVerifyTranscript(
        ECDsa leafKey,
        ReadOnlySpan<byte> transcriptHash,
        QuicTlsSignatureScheme signatureScheme = QuicTlsSignatureScheme.EcdsaSecp256r1Sha256,
        DSASignatureFormat signatureFormat = CertificateVerifySignatureFormat)
    {
        return CreateCertificateVerifyTranscript(
            leafKey,
            transcriptHash,
            useClientContext: false,
            signatureScheme: signatureScheme,
            signatureFormat: signatureFormat);
    }

    internal static byte[] CreateCertificateVerifyTranscript(
        ECDsa leafKey,
        ReadOnlySpan<byte> transcriptHash,
        bool useClientContext,
        QuicTlsSignatureScheme signatureScheme = QuicTlsSignatureScheme.EcdsaSecp256r1Sha256,
        DSASignatureFormat signatureFormat = CertificateVerifySignatureFormat)
    {
        byte[] signature = CreateCertificateVerifySignature(
            leafKey,
            transcriptHash,
            useClientContext,
            signatureFormat);
        byte[] body = new byte[UInt16Length + UInt16Length + signature.Length];
        int index = 0;

        WriteUInt16(body.AsSpan(index, UInt16Length), (ushort)signatureScheme);
        index += UInt16Length;
        WriteUInt16(body.AsSpan(index, UInt16Length), (ushort)signature.Length);
        index += UInt16Length;
        signature.CopyTo(body.AsSpan(index, signature.Length));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.CertificateVerify, body);
    }

    internal static byte[] CreateCertificateVerifySignature(
        ECDsa leafKey,
        ReadOnlySpan<byte> transcriptHash,
        bool useClientContext = false,
        DSASignatureFormat signatureFormat = CertificateVerifySignatureFormat)
    {
        ArgumentNullException.ThrowIfNull(leafKey);

        ReadOnlySpan<byte> certificateVerifyContext = useClientContext
            ? ClientCertificateVerifyContext
            : ServerCertificateVerifyContext;

        Span<byte> signedData = stackalloc byte[CertificateVerifySignedDataPrefixLength
            + certificateVerifyContext.Length
            + 1
            + transcriptHash.Length];
        signedData[..CertificateVerifySignedDataPrefixLength].Fill(0x20);
        certificateVerifyContext.CopyTo(signedData.Slice(CertificateVerifySignedDataPrefixLength));
        signedData[CertificateVerifySignedDataPrefixLength + certificateVerifyContext.Length] = 0x00;
        transcriptHash.CopyTo(
            signedData.Slice(CertificateVerifySignedDataPrefixLength + certificateVerifyContext.Length + 1));

        return leafKey.SignData(signedData, HashAlgorithmName.SHA256, signatureFormat);
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[HandshakeHeaderLength + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, UInt24Length), body.Length);
        body.CopyTo(transcript.AsSpan(HandshakeHeaderLength));
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
