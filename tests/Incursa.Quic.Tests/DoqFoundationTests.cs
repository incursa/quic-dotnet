// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;
using System.Net.Security;

namespace Incursa.Quic.Tests;

public sealed class DoqFoundationTests
{
    [Fact]
    [Requirement("RFC9250-S4-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ApplicationProtocolUsesDoqAlpn()
    {
        Assert.Equal("doq", DoqDefaults.AlpnToken);
        Assert.Equal(new SslApplicationProtocol("doq"), DoqDefaults.ApplicationProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientOptionsCarryTlsAuthenticationOptionsForDoqSetup()
    {
        SslClientAuthenticationOptions authenticationOptions = new();
        QuicClientConnectionOptions options = new()
        {
            ClientAuthenticationOptions = authenticationOptions,
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
        };

        DoqDefaults.EnsureClientConnectionOptions(options);

        Assert.Same(authenticationOptions, options.ClientAuthenticationOptions);
        Assert.NotNull(authenticationOptions.ApplicationProtocols);
        Assert.Contains(DoqDefaults.ApplicationProtocol, authenticationOptions.ApplicationProtocols);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientOptionsRejectMissingTlsAuthenticationOptionsForDoqSetup()
    {
        QuicClientConnectionOptions options = new()
        {
            ClientAuthenticationOptions = null!,
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            DoqDefaults.EnsureClientConnectionOptions(options));

        Assert.Contains("DoQ client authentication options are required", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0003")]
    [Requirement("RFC9250-S4-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientAndListenerOptionsNegotiateDoqAlpnAcrossProtocolLists()
    {
        SslApplicationProtocol[][] acceptedProtocols =
        [
            [],
            [DoqDefaults.ApplicationProtocol],
            [SslApplicationProtocol.Http3, DoqDefaults.ApplicationProtocol],
        ];

        foreach (SslApplicationProtocol[] protocols in acceptedProtocols)
        {
            QuicClientConnectionOptions clientOptions = new()
            {
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    ApplicationProtocols = [.. protocols],
                },
                RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
            };
            QuicListenerOptions listenerOptions = new()
            {
                ApplicationProtocols = [.. protocols],
                ListenEndPoint = DoqDefaults.CreateListenEndPoint(IPAddress.Loopback),
                ConnectionOptionsCallback = (_, _, _) => throw new NotSupportedException(),
            };

            DoqDefaults.EnsureClientConnectionOptions(clientOptions);
            DoqDefaults.EnsureListenerOptions(listenerOptions);

            Assert.Contains(DoqDefaults.ApplicationProtocol, clientOptions.ClientAuthenticationOptions.ApplicationProtocols);
            Assert.Contains(DoqDefaults.ApplicationProtocol, listenerOptions.ApplicationProtocols);
        }

        foreach (SslApplicationProtocol[] rejectedProtocols in new[]
        {
            new[] { SslApplicationProtocol.Http3 },
            new[] { new SslApplicationProtocol("doq-h3") },
            new[] { new SslApplicationProtocol("dot"), SslApplicationProtocol.Http3 },
        })
        {
            QuicClientConnectionOptions clientOptions = new()
            {
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    ApplicationProtocols = [.. rejectedProtocols],
                },
                RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
            };
            QuicListenerOptions listenerOptions = new()
            {
                ApplicationProtocols = [.. rejectedProtocols],
                ListenEndPoint = DoqDefaults.CreateListenEndPoint(IPAddress.Loopback),
                ConnectionOptionsCallback = (_, _, _) => throw new NotSupportedException(),
            };

            Assert.Throws<ArgumentException>(() => DoqDefaults.EnsureClientConnectionOptions(clientOptions));
            Assert.Throws<ArgumentException>(() => DoqDefaults.EnsureListenerOptions(listenerOptions));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0126")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AlpnByteSequenceMatchesDoqDefaultsAlpn()
    {
        Assert.True(DoqDefaults.Alpn.SequenceEqual("doq"u8));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0126")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AlpnByteSequenceDoesNotUseHttp3Token()
    {
        Assert.False(DoqDefaults.Alpn.SequenceEqual("h3"u8));
        Assert.NotEqual(new SslApplicationProtocol("h3"), DoqDefaults.ApplicationProtocol);
    }

    [Fact]
    [Requirement("RFC9250-S4-1-1-P1-R01")]
    [Requirement("RFC9250-S4-1-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointHelpersUseDefaultDoqPort()
    {
        DnsEndPoint clientEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example");
        IPEndPoint listenEndPoint = DoqDefaults.CreateListenEndPoint(IPAddress.Loopback);

        Assert.Equal(DoqDefaults.DefaultPort, clientEndPoint.Port);
        Assert.Equal(DoqDefaults.DefaultPort, listenEndPoint.Port);
    }

    [Fact]
    [Requirement("RFC9250-S4-1-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointHelpersAllowDoqPortsOtherThanUdp53()
    {
        const int alternatePort = DoqDefaults.DefaultPort + 1;

        Assert.True(DoqDefaults.IsAllowedPort(DoqDefaults.DefaultPort));
        Assert.True(DoqDefaults.IsAllowedPort(alternatePort));

        DnsEndPoint clientEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example", alternatePort);
        IPEndPoint listenEndPoint = DoqDefaults.CreateListenEndPoint(IPAddress.Loopback, alternatePort);

        Assert.Equal(alternatePort, clientEndPoint.Port);
        Assert.Equal(alternatePort, listenEndPoint.Port);
    }

    [Fact]
    [Requirement("RFC9250-S4-1-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointHelpersRejectUdpPort53()
    {
        Assert.False(DoqDefaults.IsAllowedPort(DoqDefaults.ProhibitedPlainDnsPort));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DoqDefaults.CreateClientEndPoint("resolver.example", DoqDefaults.ProhibitedPlainDnsPort));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DoqDefaults.CreateListenEndPoint(IPAddress.Loopback, DoqDefaults.ProhibitedPlainDnsPort));
    }

    [Fact]
    [Requirement("RFC9250-S4-1-1-P1-R01")]
    [Requirement("RFC9250-S4-1-1-P2-R01")]
    [Requirement("RFC9250-S4-1-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EndpointHelpersApplyDoqPortPolicyAcrossRepresentativePorts()
    {
        foreach (int allowedPort in new[] { DoqDefaults.DefaultPort, 1, 52, 54, 4_853, IPEndPoint.MaxPort })
        {
            Assert.True(DoqDefaults.IsAllowedPort(allowedPort));

            DnsEndPoint clientEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example", allowedPort);
            IPEndPoint listenEndPoint = DoqDefaults.CreateListenEndPoint(IPAddress.Loopback, allowedPort);

            Assert.Equal(allowedPort, clientEndPoint.Port);
            Assert.Equal(allowedPort, listenEndPoint.Port);
        }

        foreach (int rejectedPort in new[] { IPEndPoint.MinPort - 1, DoqDefaults.ProhibitedPlainDnsPort, IPEndPoint.MaxPort + 1 })
        {
            Assert.False(DoqDefaults.IsAllowedPort(rejectedPort));
            Assert.Throws<ArgumentOutOfRangeException>(() => DoqDefaults.CreateClientEndPoint("resolver.example", rejectedPort));
            Assert.Throws<ArgumentOutOfRangeException>(() => DoqDefaults.CreateListenEndPoint(IPAddress.Loopback, rejectedPort));
        }
    }

    [Fact]
    [Requirement("RFC9250-S4-1-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientOptionsAllowExplicitAlternateDoqPort()
    {
        const int alternatePort = DoqDefaults.DefaultPort + 1;
        QuicClientConnectionOptions options = new()
        {
            ClientAuthenticationOptions = new SslClientAuthenticationOptions(),
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example", alternatePort),
        };

        DoqDefaults.EnsureClientConnectionOptions(options);

        DnsEndPoint endPoint = Assert.IsType<DnsEndPoint>(options.RemoteEndPoint);
        Assert.Equal(alternatePort, endPoint.Port);
    }

    [Fact]
    [Requirement("RFC9250-S4-1-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ListenerOptionsAllowExplicitAlternateDoqPort()
    {
        const int alternatePort = DoqDefaults.DefaultPort + 1;
        QuicListenerOptions options = new()
        {
            ListenEndPoint = DoqDefaults.CreateListenEndPoint(IPAddress.Loopback, alternatePort),
            ConnectionOptionsCallback = (_, _, _) => throw new NotSupportedException(),
        };

        DoqDefaults.EnsureListenerOptions(options);

        Assert.Equal(alternatePort, options.ListenEndPoint.Port);
    }

    [Fact]
    [Requirement("RFC9250-S4-1-P1-S1-R01")]
    [Requirement("RFC9250-S4-1-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientOptionsAddDoqAlpnWhenNoProtocolWasSpecified()
    {
        QuicClientConnectionOptions options = new()
        {
            ClientAuthenticationOptions = new SslClientAuthenticationOptions(),
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
        };

        DoqDefaults.EnsureClientConnectionOptions(options);

        Assert.NotNull(options.ClientAuthenticationOptions.ApplicationProtocols);
        Assert.Contains(DoqDefaults.ApplicationProtocol, options.ClientAuthenticationOptions.ApplicationProtocols);
    }

    [Fact]
    [Requirement("RFC9250-S4-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientOptionsRejectExplicitNonDoqAlpn()
    {
        QuicClientConnectionOptions options = new()
        {
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
            },
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
        };

        Assert.Throws<ArgumentException>(() => DoqDefaults.EnsureClientConnectionOptions(options));
    }

    [Fact]
    [Requirement("RFC9250-S4-1-P1-S1-R01")]
    [Requirement("RFC9250-S4-1-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionsAddDoqAlpnWhenNoProtocolWasSpecified()
    {
        QuicListenerOptions options = new()
        {
            ListenEndPoint = DoqDefaults.CreateListenEndPoint(IPAddress.Loopback),
            ConnectionOptionsCallback = (_, _, _) => throw new NotSupportedException(),
        };

        DoqDefaults.EnsureListenerOptions(options);

        Assert.NotNull(options.ApplicationProtocols);
        Assert.Contains(DoqDefaults.ApplicationProtocol, options.ApplicationProtocols);
    }

    [Fact]
    [Requirement("RFC9250-S4-2-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MessageCodecEncodesTwoOctetLengthPrefix()
    {
        byte[] encoded = DoqMessageCodec.Encode([0x01, 0x02, 0x03]);

        Assert.Equal([0x00, 0x03, 0x01, 0x02, 0x03], encoded);
    }

    [Fact]
    [Requirement("RFC9250-S4-2-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MessageCodecDecodesOneMessageAndReportsConsumedBytes()
    {
        byte[] source = [0x00, 0x02, 0xaa, 0xbb, 0xcc];

        Assert.True(DoqMessageCodec.TryDecode(source, out DoqMessage message, out int bytesConsumed));

        Assert.Equal(4, bytesConsumed);
        Assert.Equal([0xaa, 0xbb], message.Payload.ToArray());
    }

    [Theory]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0x00, 0x03, 0x01, 0x02 })]
    [Requirement("RFC9250-S4-2-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MessageCodecReportsPartialFramesAsIncomplete(byte[] source)
    {
        Assert.False(DoqMessageCodec.TryDecode(source, out _, out int bytesConsumed));
        Assert.Equal(0, bytesConsumed);
        Assert.Throws<DoqException>(() => DoqMessageCodec.Decode(source, out _));
    }

    [Fact]
    [Requirement("RFC9250-S4-2-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MessageCodecRejectsPayloadsLargerThanTwoOctetsCanRepresent()
    {
        byte[] oversizedPayload = new byte[DoqMessageCodec.MaxPayloadLength + 1];
        Span<byte> destination = stackalloc byte[DoqMessageCodec.LengthPrefixSize];

        Assert.False(DoqMessageCodec.TryEncode(oversizedPayload, destination, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
        Assert.Throws<ArgumentOutOfRangeException>(() => DoqMessageCodec.Encode(oversizedPayload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MessageCodecAllowsResponsePayloadLargerThanTypicalPathMtu()
    {
        const int typicalUdpSafePayloadSize = 1232;
        byte[] payload = new byte[typicalUdpSafePayloadSize + 1];
        payload[0] = 0xab;
        payload[^1] = 0xcd;

        byte[] encoded = DoqMessageCodec.Encode(payload);

        Assert.Equal(DoqMessageCodec.LengthPrefixSize + payload.Length, encoded.Length);
        Assert.Equal(payload.Length, BinaryPrimitives.ReadUInt16BigEndian(encoded));
        Assert.True(DoqMessageCodec.TryDecode(encoded, out DoqMessage message, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(payload, message.Payload.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0001")]
    [Requirement("RFC9250-S4-2-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MessageCodecRoundTripsRepresentativePayloadSizesBeyondPathMtu()
    {
        foreach (int payloadLength in new[] { 0, 1, 2, 512, 1_232, 1_233, 2_048, 4_096, 16_384, DoqMessageCodec.MaxPayloadLength })
        {
            byte[] payload = CreateDnsFuzzPayload(payloadLength);

            byte[] encoded = DoqMessageCodec.Encode(payload);

            Assert.Equal(DoqMessageCodec.LengthPrefixSize + payloadLength, encoded.Length);
            Assert.Equal(payloadLength, BinaryPrimitives.ReadUInt16BigEndian(encoded));
            Assert.True(DoqMessageCodec.TryDecode(encoded, out DoqMessage decoded, out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(payload, decoded.Payload.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0065")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EnsureIdleTimeout_SetsDefaultWhenNotSpecified()
    {
        QuicClientConnectionOptions options = new()
        {
            ClientAuthenticationOptions = new SslClientAuthenticationOptions(),
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
        };

        DoqDefaults.EnsureIdleTimeout(options);

        Assert.Equal(DoqDefaults.SuggestedIdleTimeout, options.IdleTimeout);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0065")]
    [Requirement("REQ-QUIC-RFC9250-0066")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EnsureIdleTimeout_PreservesExplicitValue()
    {
        TimeSpan explicitTimeout = TimeSpan.FromSeconds(15);
        QuicClientConnectionOptions options = new()
        {
            ClientAuthenticationOptions = new SslClientAuthenticationOptions(),
            RemoteEndPoint = DoqDefaults.CreateClientEndPoint("resolver.example"),
            IdleTimeout = explicitTimeout,
        };

        DoqDefaults.EnsureIdleTimeout(options);

        Assert.Equal(explicitTimeout, options.IdleTimeout);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Encode_Accepts65534BytePayload()
    {
        byte[] payload = new byte[DoqMessageCodec.MaxPayloadLength - 1];
        payload[0] = 0xab;
        payload[^1] = 0xcd;

        byte[] encoded = DoqMessageCodec.Encode(payload);

        Assert.Equal(DoqMessageCodec.LengthPrefixSize + payload.Length, encoded.Length);
        Assert.Equal(payload.Length, BinaryPrimitives.ReadUInt16BigEndian(encoded));
        Assert.Equal(0xab, encoded[DoqMessageCodec.LengthPrefixSize]);
        Assert.Equal(0xcd, encoded[^1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Encode_Accepts65535BytePayload()
    {
        byte[] payload = new byte[DoqMessageCodec.MaxPayloadLength];
        payload[0] = 0x12;
        payload[^1] = 0x34;

        byte[] encoded = DoqMessageCodec.Encode(payload);

        Assert.Equal(DoqMessageCodec.LengthPrefixSize + payload.Length, encoded.Length);
        Assert.Equal(payload.Length, BinaryPrimitives.ReadUInt16BigEndian(encoded));
        Assert.Equal(0x12, encoded[DoqMessageCodec.LengthPrefixSize]);
        Assert.Equal(0x34, encoded[^1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Encode_Rejects65536BytePayload()
    {
        byte[] oversizedPayload = new byte[DoqMessageCodec.MaxPayloadLength + 1];

        Assert.Throws<ArgumentOutOfRangeException>(() => DoqMessageCodec.Encode(oversizedPayload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDecode_Accepts65534BytePayload()
    {
        int payloadLength = DoqMessageCodec.MaxPayloadLength - 1;
        byte[] source = BuildFramedMessage(payloadLength);
        source[DoqMessageCodec.LengthPrefixSize] = 0xab;
        source[^1] = 0xcd;

        Assert.True(DoqMessageCodec.TryDecode(source, out DoqMessage message, out int bytesConsumed));

        Assert.Equal(source.Length, bytesConsumed);
        Assert.Equal(payloadLength, message.Payload.Length);
        Assert.Equal(0xab, message.Payload.Span[0]);
        Assert.Equal(0xcd, message.Payload.Span[^1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDecode_Accepts65535BytePayload()
    {
        int payloadLength = DoqMessageCodec.MaxPayloadLength;
        byte[] source = BuildFramedMessage(payloadLength);
        source[DoqMessageCodec.LengthPrefixSize] = 0xde;
        source[^1] = 0xad;

        Assert.True(DoqMessageCodec.TryDecode(source, out DoqMessage message, out int bytesConsumed));

        Assert.Equal(source.Length, bytesConsumed);
        Assert.Equal(payloadLength, message.Payload.Length);
        Assert.Equal(0xde, message.Payload.Span[0]);
        Assert.Equal(0xad, message.Payload.Span[^1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDecode_AcceptsZeroLengthPayload()
    {
        byte[] source = [0x00, 0x00];

        Assert.True(DoqMessageCodec.TryDecode(source, out DoqMessage message, out int bytesConsumed));

        Assert.Equal(DoqMessageCodec.LengthPrefixSize, bytesConsumed);
        Assert.True(message.Payload.IsEmpty);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDecode_RejectsMalformedLengthPrefixes()
    {
        Assert.False(DoqMessageCodec.TryDecode([], out _, out _));
        Assert.False(DoqMessageCodec.TryDecode([0x00], out _, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(65534)]
    [InlineData(65535)]
    [Requirement("REQ-QUIC-RFC9250-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDecodeAndEncode_RoundTripPreservesPayload(int payloadLength)
    {
        byte[] payload = new byte[payloadLength];
        for (int i = 0; i < payloadLength && i < 256; i++)
        {
            payload[i] = (byte)i;
        }

        byte[] encoded = DoqMessageCodec.Encode(payload);

        Assert.True(DoqMessageCodec.TryDecode(encoded, out DoqMessage message, out int bytesConsumed));

        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(payload.Length, message.Payload.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0084")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDecode_DoesNotConsultEdnsUdpPayloadSizeField()
    {
        byte[] dnsMessageWithEdns = BuildDnsResponseWithEdnsUdpPayloadSize(65536);
        byte[] encoded = DoqMessageCodec.Encode(dnsMessageWithEdns);

        Assert.True(DoqMessageCodec.TryDecode(encoded, out DoqMessage message, out int bytesConsumed));

        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(dnsMessageWithEdns, message.Payload.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0084")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDecode_DoesNotLimitDoqMessageToEdnsUdpPayloadSize()
    {
        byte[] dnsMessageWithSmallEdnsPayloadSize = BuildDnsResponseWithEdnsUdpPayloadSize(16);
        byte[] encoded = DoqMessageCodec.Encode(dnsMessageWithSmallEdnsPayloadSize);

        Assert.True(DoqMessageCodec.TryDecode(encoded, out DoqMessage message, out int bytesConsumed));

        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.True(message.Payload.Length > 16);
        Assert.Equal(dnsMessageWithSmallEdnsPayloadSize, message.Payload.ToArray());
    }

    private static byte[] BuildFramedMessage(int payloadLength)
    {
        byte[] source = new byte[DoqMessageCodec.LengthPrefixSize + payloadLength];
        BinaryPrimitives.WriteUInt16BigEndian(source, checked((ushort)payloadLength));
        return source;
    }

    private static byte[] BuildDnsResponseWithEdnsUdpPayloadSize(int udpPayloadSize)
    {
        int totalLength = 56;
        byte[] dns = new byte[totalLength];
        dns[0] = 0x00; dns[1] = 0x00;
        dns[2] = 0x81; dns[3] = 0x80;
        dns[4] = 0x00; dns[5] = 0x01;
        dns[6] = 0x00; dns[7] = 0x01;
        dns[8] = 0x00; dns[9] = 0x00;
        dns[10] = 0x00; dns[11] = 0x01;

        int offset = 12;
        dns[offset] = 0x07; offset++;
        WriteAscii("example", dns, ref offset);
        dns[offset] = 0x03; offset++;
        WriteAscii("com", dns, ref offset);
        dns[offset] = 0x00; offset++;
        dns[offset] = 0x00; dns[offset + 1] = 0x01;
        dns[offset + 2] = 0x00; dns[offset + 3] = 0x01;
        offset += 4;

        dns[offset] = 0xc0; dns[offset + 1] = 0x0c;
        offset += 2;
        dns[offset] = 0x00; dns[offset + 1] = 0x01;
        dns[offset + 2] = 0x00; dns[offset + 3] = 0x01;
        dns[offset + 4] = 0x00; dns[offset + 5] = 0x00;
        dns[offset + 6] = 0x00; dns[offset + 7] = 0x3c;
        dns[offset + 8] = 0x00; dns[offset + 9] = 0x04;
        dns[offset + 10] = 0x7f; dns[offset + 11] = 0x00;
        dns[offset + 12] = 0x00; dns[offset + 13] = 0x01;
        offset += 14;

        dns[offset] = 0x00; offset++;
        dns[offset] = 0x00; dns[offset + 1] = 0x29;
        dns[offset + 2] = (byte)((udpPayloadSize >> 8) & 0xff);
        dns[offset + 3] = (byte)(udpPayloadSize & 0xff);
        dns[offset + 4] = 0x00; dns[offset + 5] = 0x00;
        dns[offset + 6] = 0x00; dns[offset + 7] = 0x00;
        dns[offset + 8] = 0x00; dns[offset + 9] = 0x00;

        return dns;
    }

    private static void WriteAscii(string text, byte[] destination, ref int offset)
    {
        foreach (char c in text)
        {
            destination[offset++] = (byte)c;
        }
    }

    [Fact]
    [Requirement("RFC9250-S4-2-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NormalizeToDoq_SetsMessageIdToZero()
    {
        byte[] input = [0x12, 0x34, 0x01, 0x02, 0x03];

        byte[] result = DoqMessage.NormalizeToDoq(input);

        Assert.Equal(0, result[0]);
        Assert.Equal(0, result[1]);
        Assert.Equal([0x01, 0x02, 0x03], result[2..].ToArray());
    }

    [Fact]
    [Requirement("RFC9250-S4-2-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NormalizeToDoq_ThrowsOnShortInput()
    {
        Assert.Throws<ArgumentException>(() => DoqMessage.NormalizeToDoq([0x00]));
        Assert.Throws<ArgumentException>(() => DoqMessage.NormalizeToDoq([]));
    }

    [Fact]
    [Requirement("RFC9250-S4-2-1-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void GenerateMessageId_WritesSpecifiedId()
    {
        byte[] input = [0x00, 0x00, 0xaa, 0xbb];

        byte[] result = DoqMessage.GenerateMessageId(input, 0xABCD);

        Assert.Equal(0xAB, result[0]);
        Assert.Equal(0xCD, result[1]);
        Assert.Equal([0xaa, 0xbb], result[2..].ToArray());
    }

    [Fact]
    [Requirement("RFC9250-S4-2-1-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void GenerateMessageId_PreservesOriginalInput()
    {
        byte[] input = [0x00, 0x00, 0x01, 0x02];

        byte[] result = DoqMessage.GenerateMessageId(input, 0x4321);

        Assert.Equal(0x43, result[0]);
        Assert.Equal(0x21, result[1]);
        Assert.Equal(0x00, input[0]);
        Assert.Equal(0x00, input[1]);
    }

    [Fact]
    [Requirement("RFC9250-S4-2-1-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void GenerateMessageId_ThrowsOnShortInput()
    {
        Assert.Throws<ArgumentException>(() => DoqMessage.GenerateMessageId([0x00], 0x1234));
        Assert.Throws<ArgumentException>(() => DoqMessage.GenerateMessageId([], 0x1234));
    }

    [Fact]
    [Requirement("RFC9250-S4-2-1-P3-S1-R01")]
    [Requirement("RFC9250-S4-2-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NormalizeToDoqAndGenerateMessageId_RoundTrip()
    {
        byte[] original = [0x12, 0x34, 0xff, 0xee];

        byte[] forDoq = DoqMessage.NormalizeToDoq(original);
        byte[] forTcp = DoqMessage.GenerateMessageId(forDoq, 0x1234);

        Assert.Equal(0x00, forDoq[0]);
        Assert.Equal(0x00, forDoq[1]);
        Assert.Equal(0x12, forTcp[0]);
        Assert.Equal(0x34, forTcp[1]);
    }

    [Fact]
    [Requirement("RFC9250-S4-5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsReplayableOpcode_QueryIsReplayable()
    {
        Assert.True(DoqDefaults.IsReplayableOpcode(0));
    }

    [Fact]
    [Requirement("RFC9250-S4-5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsReplayableOpcode_NotifyIsReplayable()
    {
        Assert.True(DoqDefaults.IsReplayableOpcode(4));
    }

    [Fact]
    [Requirement("RFC9250-S4-5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IsReplayableOpcode_OtherOpcodesAreNotReplayable()
    {
        Assert.False(DoqDefaults.IsReplayableOpcode(1));
        Assert.False(DoqDefaults.IsReplayableOpcode(2));
        Assert.False(DoqDefaults.IsReplayableOpcode(5));
        Assert.False(DoqDefaults.IsReplayableOpcode(6));
        Assert.False(DoqDefaults.IsReplayableOpcode(7));
        Assert.False(DoqDefaults.IsReplayableOpcode(8));
        Assert.False(DoqDefaults.IsReplayableOpcode(15));
    }

    [Fact]
    [Requirement("RFC9250-S4-5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsReplayableQuery_DetectsQueryOpcodeFromPayload()
    {
        byte[] query = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01];

        Assert.True(DoqDefaults.IsReplayableQuery(query));
    }

    [Fact]
    [Requirement("RFC9250-S4-5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IsReplayableQuery_DetectsNonQueryOpcode()
    {
        byte[] statusQuery = [0x00, 0x00, 0x10, 0x00, 0x00, 0x01];

        Assert.False(DoqDefaults.IsReplayableQuery(statusQuery));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0081")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BuildRefusedWithTooEarlyResponse_ReturnsRefusedResponse()
    {
        byte[] query = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        byte[] response = DoqDefaults.BuildRefusedWithTooEarlyResponse(query);

        Assert.Equal(5, response[3] & 0x0F);
        Assert.Equal(1, (response[2] >> 7));
        Assert.NotEmpty(response);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0081")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerResumptionPolicyDoesNotRequireZeroRttQueueing()
    {
        DoqServerOptions options = new();

        Assert.True(options.ResumptionTicketLifetime > TimeSpan.Zero);
        Assert.True(options.EnableAntiReplay);
        Assert.Equal(0, options.MaxQueuedZeroRttTransactions);
        Assert.Null(options.ZeroRttStreamDetector);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0026")]
    [Requirement("REQ-QUIC-RFC9250-0027")]
    [Requirement("REQ-QUIC-RFC9250-0028")]
    [Requirement("REQ-QUIC-RFC9250-0029")]
    [Requirement("REQ-QUIC-RFC9250-0030")]
    [Requirement("REQ-QUIC-RFC9250-0031")]
    [Requirement("REQ-QUIC-RFC9250-0032")]
    [Requirement("REQ-QUIC-RFC9250-0033")]
    [Requirement("REQ-QUIC-RFC9250-0134")]
    [Requirement("REQ-QUIC-RFC9250-0135")]
    [Requirement("REQ-QUIC-RFC9250-0136")]
    [Requirement("REQ-QUIC-RFC9250-0137")]
    [Requirement("REQ-QUIC-RFC9250-0138")]
    [Requirement("REQ-QUIC-RFC9250-0139")]
    [Requirement("REQ-QUIC-RFC9250-0140")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ErrorCodeValuesMatchRfc9250Registry()
    {
        Assert.Equal(0x0, (long)DoqErrorCode.NoError);
        Assert.Equal(0x1, (long)DoqErrorCode.InternalError);
        Assert.Equal(0x2, (long)DoqErrorCode.ProtocolError);
        Assert.Equal(0x3, (long)DoqErrorCode.RequestCancelled);
        Assert.Equal(0x4, (long)DoqErrorCode.ExcessiveLoad);
        Assert.Equal(0x5, (long)DoqErrorCode.UnspecifiedError);
        Assert.Equal(0xd098ea5e, (long)DoqErrorCode.ErrorReserved);
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResumptionTicketLifetimeDefaultIsSixHours()
    {
        DoqServerOptions options = new();

        Assert.Equal(6, options.ResumptionTicketLifetime.TotalHours);
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResumptionTicketLifetimeRejectsNonPositiveValues()
    {
        DoqServerOptions options = new();

        Assert.Throws<ArgumentOutOfRangeException>(() => options.ResumptionTicketLifetime = TimeSpan.Zero);
        Assert.Throws<ArgumentOutOfRangeException>(() => options.ResumptionTicketLifetime = TimeSpan.FromSeconds(-1));
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P5-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AntiReplayEnabledByDefault()
    {
        DoqServerOptions options = new();

        Assert.True(options.EnableAntiReplay);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0141")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NotifyOpcodeIsReplayable()
    {
        Assert.True(DoqDefaults.IsReplayableOpcode(4));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0141")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NotifyQueryPayloadIsClassifiedAsReplayable()
    {
        byte[] notifyQuery = [0x00, 0x00, 0x20, 0x00, 0x00, 0x01];

        Assert.True(DoqDefaults.IsReplayableQuery(notifyQuery));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0141")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonNotifyStateChangingOpcodeIsNotClassifiedAsReplayable()
    {
        byte[] updateQuery = [0x00, 0x00, 0x28, 0x00, 0x00, 0x01];

        Assert.False(DoqDefaults.IsReplayableOpcode(5));
        Assert.False(DoqDefaults.IsReplayableQuery(updateQuery));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0124")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplayableOpcodesAreStatePreserving()
    {
        Assert.True(DoqDefaults.IsReplayableOpcode(0));
        Assert.True(DoqDefaults.IsReplayableOpcode(4));

        Assert.False(DoqDefaults.IsReplayableOpcode(1));
        Assert.False(DoqDefaults.IsReplayableOpcode(2));
        Assert.False(DoqDefaults.IsReplayableOpcode(5));
        Assert.False(DoqDefaults.IsReplayableOpcode(6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0124")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StateChangingOpcodeIsNotAllowedAsStatePreservingZeroRttTransaction()
    {
        byte[] updateQuery = [0x00, 0x00, 0x28, 0x00, 0x00, 0x01];

        Assert.False(DoqDefaults.IsReplayableOpcode(5));
        Assert.False(DoqDefaults.IsReplayableQuery(updateQuery));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0090")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FallbackCache_RecordsAndChecksBackoff()
    {
        DoqFallbackCache cache = new(TimeSpan.FromMinutes(5));

        Assert.False(cache.IsBackedOff("resolver.example:853"));

        cache.RecordFailure("resolver.example:853");

        Assert.True(cache.IsBackedOff("resolver.example:853"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0090")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FallbackCache_DoesNotBackOffUnfailedEndpoint()
    {
        DoqFallbackCache cache = new(TimeSpan.FromMinutes(5));

        cache.RecordFailure("resolver-a.example:853");

        Assert.True(cache.IsBackedOff("resolver-a.example:853"));
        Assert.False(cache.IsBackedOff("resolver-b.example:853"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0091")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FallbackCache_BackoffExpires()
    {
        DoqFallbackCache cache = new(TimeSpan.FromMilliseconds(1));

        cache.RecordFailure("resolver.example:853");
        Thread.Sleep(10);

        Assert.False(cache.IsBackedOff("resolver.example:853"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0091")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FallbackCache_RejectsNonPositiveBackoffPeriods()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new DoqFallbackCache(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DoqFallbackCache(TimeSpan.FromMilliseconds(-1)));

        DoqFallbackCache cache = new(TimeSpan.FromMinutes(5));

        Assert.Throws<ArgumentOutOfRangeException>(() => cache.BackoffPeriod = TimeSpan.Zero);
        Assert.Throws<ArgumentOutOfRangeException>(() => cache.BackoffPeriod = TimeSpan.FromMilliseconds(-1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0089")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FallbackCache_ClearAllowsRetry()
    {
        DoqFallbackCache cache = new(TimeSpan.FromMinutes(5));

        cache.RecordFailure("resolver.example:853");
        Assert.True(cache.IsBackedOff("resolver.example:853"));

        cache.ClearFailure("resolver.example:853");

        Assert.False(cache.IsBackedOff("resolver.example:853"));
    }

    [Fact]
    [Requirement("RFC9250-S5-1-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StrictProfileDefaultsToNoFallback()
    {
        Assert.Equal(DoqClientProfile.Strict, default(DoqClientProfile));
    }

    [Fact]
    [Requirement("RFC9250-S5-1-P1-S2-R01")]
    [Requirement("RFC9250-S5-2-P1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StrictProfileDoesNotSelectFallbackTransport()
    {
        DoqFallbackTransport transport = DoqFallbackPolicy.SelectTransportAfterDoqFailure(
            DoqClientProfile.Strict,
            dnsOverTlsAvailable: true,
            cleartextDnsAllowed: true);

        Assert.Equal(DoqFallbackTransport.None, transport);
    }

    [Fact]
    [Requirement("RFC9250-S5-2-P1-R01")]
    [Requirement("REQ-QUIC-RFC9250-0092")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OpportunisticFallbackPrefersDnsOverTlsWhenAvailable()
    {
        DoqFallbackTransport transport = DoqFallbackPolicy.SelectTransportAfterDoqFailure(
            DoqClientProfile.Opportunistic,
            dnsOverTlsAvailable: true,
            cleartextDnsAllowed: true);

        Assert.Equal(DoqFallbackTransport.DnsOverTls, transport);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0092")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OpportunisticFallbackRequiresExplicitCleartextPermission()
    {
        DoqFallbackTransport transport = DoqFallbackPolicy.SelectTransportAfterDoqFailure(
            DoqClientProfile.Opportunistic,
            dnsOverTlsAvailable: false,
            cleartextDnsAllowed: false);

        Assert.Equal(DoqFallbackTransport.None, transport);
    }

    [Fact]
    [Requirement("RFC9250-S5-2-P1-R01")]
    [Requirement("REQ-QUIC-RFC9250-0092")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OpportunisticFallbackAllowsCleartextOnlyWhenExplicitlyPermitted()
    {
        DoqFallbackTransport transport = DoqFallbackPolicy.SelectTransportAfterDoqFailure(
            DoqClientProfile.Opportunistic,
            dnsOverTlsAvailable: false,
            cleartextDnsAllowed: true);

        Assert.Equal(DoqFallbackTransport.CleartextDns, transport);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0092")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OpportunisticFallbackDoesNotUseCleartextForKeyPinnedEndpoint()
    {
        DoqFallbackTransport transport = DoqFallbackPolicy.SelectTransportAfterDoqFailure(
            DoqClientProfile.Opportunistic,
            dnsOverTlsAvailable: false,
            cleartextDnsAllowed: true,
            endpointKeyPinned: true);

        Assert.Equal(DoqFallbackTransport.None, transport);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0093")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AmplificationLimitEnforcedByDefault()
    {
        DoqServerOptions options = new();

        Assert.True(options.EnforceAmplificationLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0094")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetryPacketsEnabledByDefault()
    {
        DoqServerOptions options = new();

        Assert.True(options.UseRetryPackets);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0094")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressValidationEnabledByDefault()
    {
        DoqServerOptions options = new();

        Assert.True(options.UseAddressValidationForFutureConnections);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0094")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RetryAndAddressValidationPolicyCanBeExplicitlyDisabled()
    {
        DoqServerOptions options = new()
        {
            UseRetryPackets = false,
            UseAddressValidationForFutureConnections = false,
        };

        Assert.False(options.UseRetryPackets);
        Assert.False(options.UseAddressValidationForFutureConnections);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0095")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PadMessage_PadsToBlockSize()
    {
        byte[] smallQuery = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01];

        byte[] padded = DoqPadding.PadMessage(smallQuery, 32);

        Assert.True(padded.Length % 32 == 0);
        Assert.True(padded.Length > smallQuery.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0095")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PadMessage_DoesNotAddPaddingWhenBlockSizeIsDisabled()
    {
        byte[] query = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        byte[] padded = DoqPadding.PadMessage(query, 1);

        Assert.Equal(query, padded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0096")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PadMessage_BlockSizeZeroDisabled()
    {
        byte[] query = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        byte[] padded = DoqPadding.PadMessage(query, 0);

        Assert.Equal(query.Length, padded.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0096")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PadMessage_LeavesMalformedQuestionNameUnchanged()
    {
        byte[] malformedQuery = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f];

        byte[] padded = DoqPadding.PadMessage(malformedQuery, 32);

        Assert.Equal(malformedQuery, padded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0097")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PadMessage_AlreadyAlignedWithPadding()
    {
        byte[] query = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01];

        byte[] padded = DoqPadding.PadMessage(query, 16);

        Assert.True(padded.Length > query.Length);
        Assert.True(padded.Length % 16 == 0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0125")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PaddingBlockSizeConfiguredInDefaults()
    {
        Assert.Equal(0, DoqDefaults.PaddingBlockSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0097")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PadMessage_RespectsMaxPayloadLength()
    {
        byte[] nearMaxQuery = new byte[DoqMessageCodec.MaxPayloadLength - 10];
        nearMaxQuery[0] = 0; nearMaxQuery[1] = 0;
        nearMaxQuery[2] = 0; nearMaxQuery[3] = 0;
        nearMaxQuery[4] = 0; nearMaxQuery[5] = 1;
        nearMaxQuery[10] = 0; nearMaxQuery[11] = 0;

        byte[] padded = DoqPadding.PadMessage(nearMaxQuery, 128);

        Assert.True(padded.Length <= DoqMessageCodec.MaxPayloadLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0097")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PadMessage_ReturnsOriginalWhenPaddingCannotFit()
    {
        byte[] maxLengthQuery = new byte[DoqMessageCodec.MaxPayloadLength];
        maxLengthQuery[0] = 0x00;
        maxLengthQuery[1] = 0x00;

        byte[] padded = DoqPadding.PadMessage(maxLengthQuery, 2);

        Assert.Equal(maxLengthQuery.Length, padded.Length);
        Assert.Equal(maxLengthQuery, padded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0097")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PadMessage_RepresentativeLengthsStayWithinDoqMessageLimit()
    {
        int[] lengths = [0, 1, 11, 12, 13, 29, 30, 127, 128, 129, 511, 512, 1024, 4096, 65480, 65520, 65535];
        int[] blockSizes = [0, 1, 2, 16, 32, 128, 255];

        foreach (int length in lengths)
        {
            byte[] message = CreateDnsFuzzPayload(length);
            foreach (int blockSize in blockSizes)
            {
                byte[] padded = DoqPadding.PadMessage(message, blockSize);

                Assert.True(padded.Length <= DoqMessageCodec.MaxPayloadLength);
                if (blockSize <= 1 || length < 12)
                {
                    Assert.Equal(message, padded);
                }

                if (padded.Length > message.Length && padded.Length + DoqMessageCodec.LengthPrefixSize <= ushort.MaxValue + DoqMessageCodec.LengthPrefixSize)
                {
                    byte[] framed = DoqMessageCodec.Encode(padded);
                    Assert.True(DoqMessageCodec.TryDecode(framed, out DoqMessage decoded, out int bytesConsumed));
                    Assert.Equal(framed.Length, bytesConsumed);
                    Assert.Equal(padded, decoded.Payload.ToArray());
                }
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0096")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PadMessage_AddsPaddingOptionWithCorrectCode()
    {
        byte[] query = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        byte[] padded = DoqPadding.PadMessage(query, 32);

        Assert.True(padded.Length > query.Length);
        Assert.True(padded.Length % 32 == 0);
        Assert.Equal(1, padded[11]);
    }

    private static byte[] CreateDnsFuzzPayload(int length)
    {
        byte[] message = new byte[length];
        if (length >= 12)
        {
            message[0] = 0x00;
            message[1] = 0x00;
            message[2] = 0x01;
            message[3] = 0x00;
        }

        return message;
    }
}
