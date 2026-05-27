using System.Net;
using System.Net.Security;

namespace Incursa.Quic.Tests;

public sealed class DoqFoundationTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ApplicationProtocolUsesDoqAlpn()
    {
        Assert.Equal("doq", DoqDefaults.AlpnToken);
        Assert.Equal(new SslApplicationProtocol("doq"), DoqDefaults.ApplicationProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0005")]
    [Requirement("REQ-QUIC-RFC9250-0006")]
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
    [Requirement("REQ-QUIC-RFC9250-0007")]
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
    [Requirement("REQ-QUIC-RFC9250-0004")]
    [Requirement("REQ-QUIC-RFC9250-0006")]
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
    [Requirement("REQ-QUIC-RFC9250-0004")]
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
    [Requirement("REQ-QUIC-RFC9250-0004")]
    [Requirement("REQ-QUIC-RFC9250-0005")]
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
    [Requirement("REQ-QUIC-RFC9250-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MessageCodecEncodesTwoOctetLengthPrefix()
    {
        byte[] encoded = DoqMessageCodec.Encode([0x01, 0x02, 0x03]);

        Assert.Equal([0x00, 0x03, 0x01, 0x02, 0x03], encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0010")]
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
    [Requirement("REQ-QUIC-RFC9250-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MessageCodecReportsPartialFramesAsIncomplete(byte[] source)
    {
        Assert.False(DoqMessageCodec.TryDecode(source, out _, out int bytesConsumed));
        Assert.Equal(0, bytesConsumed);
        Assert.Throws<DoqException>(() => DoqMessageCodec.Decode(source, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0010")]
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
}
