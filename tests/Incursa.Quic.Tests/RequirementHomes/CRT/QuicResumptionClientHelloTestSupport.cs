using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using Xunit;

namespace Incursa.Quic.Tests;

internal static class QuicResumptionClientHelloTestSupport
{
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = sizeof(ushort);
    private const int UInt32Length = sizeof(uint);
    private const ushort EarlyDataExtensionType = 0x002a;
    private const ushort PreSharedKeyExtensionType = 0x0029;
    private const ushort PskKeyExchangeModesExtensionType = 0x002d;
    private const int HashLength = 32;
    private const byte PskDheKeMode = 0x01;

    private static readonly byte[] HkdfLabelPrefix = System.Text.Encoding.ASCII.GetBytes("tls13 ");
    private static readonly byte[] FinishedLabel = System.Text.Encoding.ASCII.GetBytes("finished");
    private static readonly byte[] ResumptionLabel = System.Text.Encoding.ASCII.GetBytes("resumption");
    private static readonly byte[] ResumptionBinderLabel = System.Text.Encoding.ASCII.GetBytes("res binder");
    private static readonly byte[] EmptyTranscriptHash = SHA256.HashData(Array.Empty<byte>());

    internal static QuicDetachedResumptionTicketSnapshot CreateDetachedResumptionTicketSnapshot()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] ticketBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] ticketNonce = [0x01, 0x02, 0x03];
        const uint ticketLifetimeSeconds = 7200;
        const uint ticketAgeAdd = 0x01020304;
        const long capturedAtTicks = 1234;
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            ticketBytes,
            ticketNonce,
            ticketLifetimeSeconds,
            ticketAgeAdd);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);
        Assert.Single(ticketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(capturedAtTicks, ticketUpdates[0]),
            nowTicks: capturedAtTicks).StateChanged);

        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);
        return detachedResumptionTicketSnapshot!;
    }

    internal static ParsedClientHello ParseClientHello(byte[] clientHelloBytes)
    {
        Assert.NotNull(clientHelloBytes);
        Assert.True(clientHelloBytes.Length > HandshakeHeaderLength);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.ClientHello, clientHelloBytes[0]);

        ReadOnlySpan<byte> body = clientHelloBytes.AsSpan(HandshakeHeaderLength);
        int index = 0;

        index += UInt16Length;
        index += 32;

        int sessionIdLength = body[index++];
        index += sessionIdLength;

        ushort cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(index, UInt16Length));
        index += UInt16Length + cipherSuitesLength;

        int compressionMethodsLength = body[index++];
        index += compressionMethodsLength;

        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(index, UInt16Length));
        index += UInt16Length;
        int extensionsStart = index;
        int extensionsEnd = extensionsStart + extensionsLength;

        bool hasPskModes = false;
        bool hasPreSharedKey = false;
        bool preSharedKeyIsLast = false;
        bool hasEarlyData = false;
        byte[] ticketIdentity = Array.Empty<byte>();
        uint obfuscatedTicketAge = 0;
        byte[] binder = Array.Empty<byte>();
        int truncatedLength = 0;

        while (index < extensionsEnd)
        {
            ushort extensionType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(index, UInt16Length));
            index += UInt16Length;
            ushort extensionValueLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(index, UInt16Length));
            index += UInt16Length;
            int extensionValueStart = index;
            int extensionValueEnd = extensionValueStart + extensionValueLength;
            ReadOnlySpan<byte> extensionValue = body.Slice(extensionValueStart, extensionValueLength);
            index = extensionValueEnd;

            if (extensionType == PskKeyExchangeModesExtensionType)
            {
                hasPskModes = true;
                Assert.Equal(2, extensionValue.Length);
                Assert.Equal(1, extensionValue[0]);
                Assert.Equal(PskDheKeMode, extensionValue[1]);
            }
            else if (extensionType == PreSharedKeyExtensionType)
            {
                hasPreSharedKey = true;
                preSharedKeyIsLast = index == extensionsEnd;

                int extensionIndex = 0;
                ushort identitiesLength = BinaryPrimitives.ReadUInt16BigEndian(extensionValue.Slice(extensionIndex, UInt16Length));
                extensionIndex += UInt16Length;
                int identitiesEnd = extensionIndex + identitiesLength;

                ushort identityLength = BinaryPrimitives.ReadUInt16BigEndian(extensionValue.Slice(extensionIndex, UInt16Length));
                extensionIndex += UInt16Length;
                ticketIdentity = extensionValue.Slice(extensionIndex, identityLength).ToArray();
                extensionIndex += identityLength;
                obfuscatedTicketAge = BinaryPrimitives.ReadUInt32BigEndian(extensionValue.Slice(extensionIndex, UInt32Length));
                extensionIndex += UInt32Length;
                Assert.Equal(identitiesEnd, extensionIndex);

                truncatedLength = HandshakeHeaderLength + extensionValueStart + extensionIndex;

                ushort bindersLength = BinaryPrimitives.ReadUInt16BigEndian(extensionValue.Slice(extensionIndex, UInt16Length));
                extensionIndex += UInt16Length;
                Assert.Equal(1 + HashLength, bindersLength);

                int binderLength = extensionValue[extensionIndex++];
                Assert.Equal(HashLength, binderLength);
                binder = extensionValue.Slice(extensionIndex, binderLength).ToArray();
                extensionIndex += binderLength;
                Assert.Equal(extensionValue.Length, extensionIndex);
            }
            else if (extensionType == EarlyDataExtensionType)
            {
                hasEarlyData = true;
            }
        }

        return new ParsedClientHello(
            hasPskModes,
            hasPreSharedKey,
            preSharedKeyIsLast,
            hasEarlyData,
            ticketIdentity,
            obfuscatedTicketAge,
            binder,
            truncatedLength);
    }

    internal static bool VerifyBinder(byte[] clientHelloBytes, QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot)
    {
        ParsedClientHello parsed = ParseClientHello(clientHelloBytes);
        if (!parsed.HasPskKeyExchangeModes
            || !parsed.HasPreSharedKey
            || parsed.Binder.Length != HashLength)
        {
            return false;
        }

        byte[]? resumptionPsk = null;
        byte[]? earlySecret = null;
        byte[]? binderKey = null;

        try
        {
            resumptionPsk = HkdfExpandLabel(
                detachedResumptionTicketSnapshot.ResumptionMasterSecret.Span,
                ResumptionLabel,
                detachedResumptionTicketSnapshot.TicketNonce.Span,
                HashLength);
            earlySecret = HkdfExtract(new byte[HashLength], resumptionPsk);
            binderKey = HkdfExpandLabel(earlySecret, ResumptionBinderLabel, EmptyTranscriptHash, HashLength);
            byte[] partialTranscriptHash = SHA256.HashData(clientHelloBytes.AsSpan(0, parsed.TruncatedLength));
            byte[] expectedBinder = DeriveFinishedVerifyData(binderKey, partialTranscriptHash);
            return expectedBinder.SequenceEqual(parsed.Binder);
        }
        finally
        {
            if (resumptionPsk is not null)
            {
                CryptographicOperations.ZeroMemory(resumptionPsk);
            }

            if (earlySecret is not null)
            {
                CryptographicOperations.ZeroMemory(earlySecret);
            }

            if (binderKey is not null)
            {
                CryptographicOperations.ZeroMemory(binderKey);
            }
        }
    }

    internal static uint ComputeObfuscatedTicketAge(QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot, long nowTicks)
    {
        long elapsedTicks = nowTicks > detachedResumptionTicketSnapshot.CapturedAtTicks
            ? nowTicks - detachedResumptionTicketSnapshot.CapturedAtTicks
            : 0;
        ulong ticketAgeMilliseconds = elapsedTicks <= 0
            ? 0
            : (unchecked((ulong)elapsedTicks) * 1_000UL) / (ulong)Stopwatch.Frequency;
        uint ticketAgeMilliseconds32 = unchecked((uint)ticketAgeMilliseconds);
        return unchecked(ticketAgeMilliseconds32 + detachedResumptionTicketSnapshot.TicketAgeAdd);
    }

    internal static byte[] GetInitialBootstrapClientHelloBytes(QuicConnectionRuntime runtime)
    {
        FieldInfo? field = typeof(QuicConnectionRuntime).GetField("initialBootstrapClientHelloBytes", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        byte[]? bytes = Assert.IsType<byte[]>(field!.GetValue(runtime));
        return bytes;
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
        int hkdfLabelLength = UInt16Length
            + 1
            + HkdfLabelPrefix.Length
            + label.Length
            + 1
            + context.Length;

        Span<byte> hkdfLabel = stackalloc byte[hkdfLabelLength];
        int index = 0;

        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel, checked((ushort)length));
        index += UInt16Length;

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

        byte[] expandInput = new byte[hkdfLabel.Length + 1];
        hkdfLabel.CopyTo(expandInput);
        expandInput[^1] = 0x01;

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

    internal sealed record ParsedClientHello(
        bool HasPskKeyExchangeModes,
        bool HasPreSharedKey,
        bool PreSharedKeyIsLastExtension,
        bool HasEarlyData,
        byte[] TicketIdentity,
        uint ObfuscatedTicketAge,
        byte[] Binder,
        int TruncatedLength);
}
