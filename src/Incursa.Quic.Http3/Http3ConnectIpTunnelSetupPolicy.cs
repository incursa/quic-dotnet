// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 CONNECT-IP tunnel setup and lifetime policy helpers.
/// </summary>
public static class Http3ConnectIpTunnelSetupPolicy
{
    private const int SetupErrorStatusCode = 502;

    /// <summary>
    /// Extracts and validates decoded CONNECT-IP tunnel variables.
    /// </summary>
    public static Http3ConnectIpTunnelVariables ValidateTunnelVariables(string? decodedTarget, string? decodedIpproto)
    {
        if (!Http3ConnectIpTargetScope.TryParse(decodedTarget, out Http3ConnectIpTargetScope? target))
        {
            throw Malformed("CONNECT-IP target variable is malformed.");
        }

        if (!Http3ConnectIpProtocolScope.TryParse(decodedIpproto, out Http3ConnectIpProtocolScope? ipproto))
        {
            throw Malformed("CONNECT-IP ipproto variable is malformed.");
        }

        return new Http3ConnectIpTunnelVariables(target, ipproto);
    }

    /// <summary>
    /// Returns true when target DNS resolution is required before replying to the request.
    /// </summary>
    public static bool RequiresDnsResolutionBeforeResponse(Http3ConnectIpTunnelVariables variables)
    {
        ArgumentNullException.ThrowIfNull(variables);
        return variables.Target.RequiresDnsResolution;
    }

    /// <summary>
    /// Returns true when tunnel setup errors require rejecting the request.
    /// </summary>
    public static bool ShouldRejectSetup(bool variableValidationFailed, bool dnsResolutionFailed, bool tunnelEstablishmentFailed)
    {
        return variableValidationFailed || dnsResolutionFailed || tunnelEstablishmentFailed;
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
    /// Builds minimal response headers for a failed CONNECT-IP setup attempt.
    /// </summary>
    public static IReadOnlyList<QPackFieldLine> BuildSetupErrorResponseHeaders(string errorType)
    {
        return
        [
            new QPackFieldLine(":status", SetupErrorStatusCode.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            CreateSetupErrorProxyStatusHeader(errorType),
        ];
    }

    /// <summary>
    /// Returns true when the tunnel and its assignments remain active.
    /// </summary>
    public static bool ShouldMaintainAssignments(bool requestStreamOpen, bool tunnelEstablished, bool inactivityTimeoutElapsed)
    {
        return requestStreamOpen && tunnelEstablished && !inactivityTimeoutElapsed;
    }

    /// <summary>
    /// Returns true when the tunnel can be torn down due to inactivity.
    /// </summary>
    public static bool CanTearDownTunnelAfterInactivity(bool inactivityTimeoutElapsed)
    {
        return inactivityTimeoutElapsed;
    }

    /// <summary>
    /// Returns true when tearing down the tunnel requires closing the request stream.
    /// </summary>
    public static bool ShouldCloseRequestStreamWhenTearingDown(bool tearingDownTunnel)
    {
        return tearingDownTunnel;
    }

    private static Http3Exception Malformed(string message)
    {
        return new Http3Exception(Http3ErrorCode.MessageError, message);
    }
}
