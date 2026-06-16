// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 CONNECT-UDP tunnel setup policy helpers.
/// </summary>
public static class Http3ConnectUdpTunnelSetupPolicy
{
    private const int MinimumSuccessfulStatusCode = 200;
    private const int MaximumSuccessfulStatusCode = 299;
    private const int SetupErrorStatusCode = 502;

    /// <summary>
    /// Extracts the CONNECT-UDP target from request headers reconstructed through a URI Template.
    /// </summary>
    public static Http3ConnectUdpTarget ExtractTarget(
        IReadOnlyList<QPackFieldLine> requestHeaders,
        Http3ConnectUdpUriTemplate template)
    {
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentNullException.ThrowIfNull(template);

        Http3HeaderValidationResult request = Http3ConnectUdp.ValidateHttp3RequestHeaders(requestHeaders);
        if (!string.Equals(request.Scheme, template.AbsoluteUri.Scheme, StringComparison.Ordinal)
            || !string.Equals(request.Authority, template.ProxyAuthority, StringComparison.Ordinal))
        {
            throw Malformed("CONNECT-UDP request headers do not match the configured URI Template authority.");
        }

        Match match = Regex.Match(
            request.Path ?? "",
            CreateTargetExtractionPattern(template),
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));

        if (!match.Success)
        {
            throw Malformed("CONNECT-UDP request path does not match the configured URI Template.");
        }

        string host = Uri.UnescapeDataString(match.Groups["host"].Value);
        string portText = Uri.UnescapeDataString(match.Groups["port"].Value);
        if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out int port))
        {
            throw Malformed("CONNECT-UDP target_port is not a decimal UDP port.");
        }

        try
        {
            return new Http3ConnectUdpTarget(host, port);
        }
        catch (ArgumentException)
        {
            throw Malformed("CONNECT-UDP request target is invalid.");
        }
    }

    /// <summary>
    /// Returns true when the target host is a DNS name that must be resolved before replying.
    /// </summary>
    public static bool RequiresDnsResolutionBeforeResponse(Http3ConnectUdpTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return !IPAddress.TryParse(target.Host, out _);
    }

    /// <summary>
    /// Creates the endpoint that a proxy should open for the UDP socket.
    /// </summary>
    public static IPEndPoint CreateUdpSocketEndpoint(
        Http3ConnectUdpTarget target,
        IPAddress? resolvedAddress = null,
        IReadOnlyCollection<IPAddress>? proxyLocalAddresses = null)
    {
        ArgumentNullException.ThrowIfNull(target);

        IPAddress address = IPAddress.TryParse(target.Host, out IPAddress? literalAddress)
            ? literalAddress
            : resolvedAddress ?? throw Malformed("CONNECT-UDP DNS targets require a resolved address before opening a UDP socket.");

        if (Http3ConnectUdpTargetPolicy.IsVulnerableTarget(address, proxyLocalAddresses))
        {
            throw Malformed("CONNECT-UDP target address is prohibited.");
        }

        return new IPEndPoint(address, target.Port);
    }

    /// <summary>
    /// Returns true when the proxy has enough setup state to send a success response.
    /// </summary>
    public static bool CanSendSuccessfulResponse(
        Http3ConnectUdpTarget target,
        bool dnsResolutionCompleted,
        bool udpSocketOpened,
        bool receivedPacketFromTarget)
    {
        ArgumentNullException.ThrowIfNull(target);
        _ = receivedPacketFromTarget;

        if (RequiresDnsResolutionBeforeResponse(target) && !dnsResolutionCompleted)
        {
            return false;
        }

        return udpSocketOpened;
    }

    /// <summary>
    /// Returns true when tunnel setup errors require rejecting the request.
    /// </summary>
    public static bool ShouldRejectSetup(bool dnsResolutionFailed, bool udpSocketOpenFailed)
    {
        return dnsResolutionFailed || udpSocketOpenFailed;
    }

    /// <summary>
    /// Creates a Proxy-Status field carrying setup failure details.
    /// </summary>
    public static QPackFieldLine CreateSetupErrorProxyStatusHeader(string errorType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(errorType);
        return new QPackFieldLine("proxy-status", $"error={errorType}");
    }

    /// <summary>
    /// Builds minimal response headers for a failed setup attempt.
    /// </summary>
    public static IReadOnlyList<QPackFieldLine> BuildSetupErrorResponseHeaders(string errorType)
    {
        return
        [
            new QPackFieldLine(":status", SetupErrorStatusCode.ToString(CultureInfo.InvariantCulture)),
            CreateSetupErrorProxyStatusHeader(errorType),
        ];
    }

    /// <summary>
    /// Returns true when a client must abort a CONNECT-UDP request after a response status.
    /// </summary>
    public static bool ShouldAbortRequestOnResponse(int statusCode)
    {
        return statusCode is < MinimumSuccessfulStatusCode or > MaximumSuccessfulStatusCode;
    }

    private static string CreateTargetExtractionPattern(Http3ConnectUdpUriTemplate template)
    {
        string escaped = Regex.Escape(GetTemplatePathAndQuery(template.Template));
        escaped = escaped.Replace(Regex.Escape("{target_host}"), "(?<host>[^/?#&]+)", StringComparison.Ordinal);
        escaped = escaped.Replace(Regex.Escape("{target_port}"), "(?<port>[0-9]{1,5})", StringComparison.Ordinal);
        return $"^{escaped}$";
    }

    private static string GetTemplatePathAndQuery(string template)
    {
        int schemeSeparator = template.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 0)
        {
            return "";
        }

        int authorityStart = schemeSeparator + "://".Length;
        int pathStart = template.IndexOf('/', authorityStart);
        return pathStart < 0 ? "" : template[pathStart..];
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
