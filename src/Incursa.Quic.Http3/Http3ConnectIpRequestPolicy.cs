// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 CONNECT-IP request initiation, protection, routing, and rejection policy helpers.
/// </summary>
public static class Http3ConnectIpRequestPolicy
{
    private const int MinimumSuccessfulStatusCode = 200;
    private const int MaximumSuccessfulStatusCode = 299;

    /// <summary>
    /// Returns true when a request can initiate a CONNECT-IP tunnel associated with one HTTP stream.
    /// </summary>
    public static bool CanInitiateIpTunnel(string protocolToken, bool associatedWithSingleHttpStream)
    {
        ArgumentException.ThrowIfNullOrEmpty(protocolToken);
        return associatedWithSingleHttpStream
            && string.Equals(protocolToken, Http3ConnectIpFoundationPolicy.ProtocolToken, StringComparison.Ordinal);
    }

    /// <summary>
    /// Expands the CONNECT-IP URI Template to request target components.
    /// </summary>
    public static Http3ConnectIpRequestTarget ExpandRequestTarget(
        Http3ConnectIpUriTemplate template,
        string? target = null,
        string? ipproto = null,
        IReadOnlyDictionary<string, string>? additionalVariables = null)
    {
        ArgumentNullException.ThrowIfNull(template);
        return template.Expand(target, ipproto, additionalVariables);
    }

    /// <summary>
    /// Returns true when HTTP CONNECT-IP is protected by TLS, QUIC encryption, or an equivalent protocol.
    /// </summary>
    public static bool IsProtectedByRequiredEncryption(bool tlsProtected, bool quicProtected, bool equivalentEncryptionProtocol)
    {
        return tlsProtected || quicProtected || equivalentEncryptionProtocol;
    }

    /// <summary>
    /// Selects whether the recipient forwards the request or acts as the IP proxy.
    /// </summary>
    public static Http3ConnectIpRecipientAction SelectRecipientAction(bool configuredToUseAnotherHttpServer)
    {
        return configuredToUseAnotherHttpServer
            ? Http3ConnectIpRecipientAction.ForwardToConfiguredHttpServer
            : Http3ConnectIpRecipientAction.ActAsIpProxy;
    }

    /// <summary>
    /// Indicates that an IP proxy is allowed to reject an IP proxying request.
    /// </summary>
    public const bool IpProxyMayRejectRequest = true;

    /// <summary>
    /// Returns true when a client must abort after receiving a non-successful IP proxying response.
    /// </summary>
    public static bool ShouldAbortRequestOnResponse(int statusCode)
    {
        return statusCode is < MinimumSuccessfulStatusCode or > MaximumSuccessfulStatusCode;
    }
}
