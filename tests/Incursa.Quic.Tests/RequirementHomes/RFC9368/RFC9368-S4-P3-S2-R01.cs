// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("RFC9368-S4-P3-S2-R01")]
public sealed class RFC9368_S4_P3_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedPeerVersionInformation_ClosesConnectionWithTransportParameterError()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] serverHello = CreateServerHelloTranscript();
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscriptWithMalformedVersionInformation(
            malformedVersionInformationValue: [0x00, 0x00, 0x00, 0x01, 0x02]);

        progress.AppendCryptoBytes(0, serverHello);
        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, progress.Advance(QuicTlsRole.Client).Kind);

        progress.AppendCryptoBytes(progress.IngressCursor, encryptedExtensions);
        QuicTlsTranscriptStep fatalStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, fatalStep.Kind);
        Assert.Equal(
            QuicTlsTranscriptProgress.QuicTransportParameterParseFailureAlertDescription,
            fatalStep.AlertDescription);

        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 42,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.FatalAlert,
                    AlertDescription: fatalStep.AlertDescription)),
            nowTicks: 42);

        Assert.True(closeResult.StateChanged);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(
            QuicTransportErrorCode.TransportParameterError,
            runtime.TerminalState.Value.Close.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TooShortPeerVersionInformation_ClosesConnectionWithTransportParameterError()
    {
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Client);
        byte[] serverHello = CreateServerHelloTranscript();
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscriptWithMalformedVersionInformation(
            malformedVersionInformationValue: [0x01, 0x02, 0x03]);

        progress.AppendCryptoBytes(0, serverHello);
        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, progress.Advance(QuicTlsRole.Client).Kind);

        progress.AppendCryptoBytes(progress.IngressCursor, encryptedExtensions);
        QuicTlsTranscriptStep fatalStep = progress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Fatal, fatalStep.Kind);
        Assert.Equal(
            QuicTlsTranscriptProgress.QuicTransportParameterParseFailureAlertDescription,
            fatalStep.AlertDescription);
    }

    private static byte[] CreateServerHelloTranscript()
    {
        byte[] keyShare = new byte[65];
        keyShare[0] = 0x04;

        int supportedVersionsExtensionLength = 6;
        int keyShareExtensionLength = 2 + 2 + 2 + 2 + keyShare.Length;
        int extensionsLength = supportedVersionsExtensionLength + keyShareExtensionLength;
        byte[] body = new byte[40 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        for (int offset = 0; offset < 32; offset++)
        {
            body[index + offset] = (byte)(0x40 + offset);
        }

        index += 32;
        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;
        body[index++] = 0;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), 0x002B);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), 0x0304);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)keyShare.Length);
        index += 2;
        keyShare.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
    }

    private static byte[] CreateEncryptedExtensionsTranscriptWithMalformedVersionInformation(
        ReadOnlySpan<byte> malformedVersionInformationValue)
    {
        byte[] versionInformationTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x11,
            malformedVersionInformationValue);
        byte[] transportParametersExtension = new byte[4 + versionInformationTuple.Length];
        WriteUInt16(transportParametersExtension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(transportParametersExtension.AsSpan(2, 2), (ushort)versionInformationTuple.Length);
        versionInformationTuple.CopyTo(transportParametersExtension.AsSpan(4));

        byte[] body = new byte[2 + transportParametersExtension.Length];
        WriteUInt16(body.AsSpan(0, 2), (ushort)transportParametersExtension.Length);
        transportParametersExtension.CopyTo(body.AsSpan(2));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.EncryptedExtensions, body);
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), (uint)body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private static void WriteUInt16(Span<byte> destination, ushort value)
        => BinaryPrimitives.WriteUInt16BigEndian(destination, value);

    private static void WriteUInt24(Span<byte> destination, uint value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
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
