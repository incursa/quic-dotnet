// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Authentication;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0897")]
public sealed class REQ_QUIC_RFC9000_0897
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientOptionsRejectNonTls13ForVersion1Handshake()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint);
        options.ClientAuthenticationOptions.EnabledSslProtocols = SslProtocols.Tls12;

        NotSupportedException exception = Assert.Throws<NotSupportedException>(() =>
            QuicClientConnectionOptionsValidator.Capture(options, nameof(options)));

        Assert.Contains("Only TLS 1.3 is supported", exception.Message, StringComparison.Ordinal);
    }
}
