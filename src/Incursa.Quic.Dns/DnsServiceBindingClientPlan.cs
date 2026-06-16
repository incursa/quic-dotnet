// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Client-side RFC 9461 DNS service binding behavior for a selected endpoint.
/// </summary>
public sealed class DnsServiceBindingClientPlan
{
    internal DnsServiceBindingClientPlan(
        DnsServiceBindingEndpoint endpoint,
        bool svcbResolutionSucceeded,
        bool endpointSentInvalidResponse,
        bool endpointKnownSafeForClientAuthentication,
        bool dependentSpecificationAllowsCleartextFallback)
    {
        Endpoint = endpoint;
        SvcbResolutionSucceeded = svcbResolutionSucceeded;
        EndpointSentInvalidResponse = endpointSentInvalidResponse;
        EndpointKnownSafeForClientAuthentication = endpointKnownSafeForClientAuthentication;
        DependentSpecificationAllowsCleartextFallback = dependentSpecificationAllowsCleartextFallback;
    }

    /// <summary>
    /// Gets the selected RFC 9461 endpoint.
    /// </summary>
    public DnsServiceBindingEndpoint Endpoint { get; }

    /// <summary>
    /// Gets a value indicating whether SVCB resolution succeeded.
    /// </summary>
    public bool SvcbResolutionSucceeded { get; }

    /// <summary>
    /// Gets a value indicating whether the endpoint has returned an invalid DNS response.
    /// </summary>
    public bool EndpointSentInvalidResponse { get; }

    /// <summary>
    /// Gets a value indicating whether the endpoint is specifically known safe for DNS-query client authentication.
    /// </summary>
    public bool EndpointKnownSafeForClientAuthentication { get; }

    /// <summary>
    /// Gets a value indicating whether a dependent specification adjusted the default cleartext-fallback policy.
    /// </summary>
    public bool DependentSpecificationAllowsCleartextFallback { get; }

    /// <summary>
    /// Gets the authentication name that secure transport establishment must authenticate.
    /// </summary>
    public string ServerAuthenticationName => Endpoint.AuthenticationName;

    /// <summary>
    /// Gets a value indicating whether secure transport establishment authenticates to the SVCB authentication name.
    /// </summary>
    public bool AuthenticatesServerToAuthenticationName => true;

    /// <summary>
    /// Gets a value indicating whether the client should query HTTPS RRs for this endpoint.
    /// </summary>
    public bool ShouldQueryHttpsRecords => Endpoint.DohPathTemplate is null;

    /// <summary>
    /// Gets a value indicating whether DNS queries may identify or authenticate the client.
    /// </summary>
    public bool AllowsClientIdentityDuringDnsQuery => EndpointKnownSafeForClientAuthentication;

    /// <summary>
    /// Gets a value indicating whether more queries should be sent to this endpoint.
    /// </summary>
    public bool ShouldSendMoreQueriesToEndpoint => !EndpointSentInvalidResponse;

    /// <summary>
    /// Gets a value indicating whether an invalid response may be logged.
    /// </summary>
    public bool MayLogInvalidResponse => EndpointSentInvalidResponse;

    /// <summary>
    /// Gets a value indicating whether the client should use SVCB-reliant behavior.
    /// </summary>
    public bool UsesSvcbReliantBehavior => SvcbResolutionSucceeded;

    /// <summary>
    /// Gets a value indicating whether cleartext fallback is allowed by the active policy.
    /// </summary>
    public bool AllowsCleartextFallback => DependentSpecificationAllowsCleartextFallback;
}
