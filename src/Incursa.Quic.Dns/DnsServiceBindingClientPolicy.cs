// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Pure RFC 9461 client policy for DNS service binding endpoint use.
/// </summary>
public static class DnsServiceBindingClientPolicy
{
    /// <summary>
    /// Creates a client behavior plan for a selected RFC 9461 endpoint.
    /// </summary>
    public static DnsServiceBindingClientPlan CreatePlan(
        DnsServiceBindingEndpoint endpoint,
        bool svcbResolutionSucceeded = false,
        bool endpointSentInvalidResponse = false,
        bool endpointKnownSafeForClientAuthentication = false,
        bool dependentSpecificationAllowsCleartextFallback = false)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return new DnsServiceBindingClientPlan(
            endpoint,
            svcbResolutionSucceeded,
            endpointSentInvalidResponse,
            endpointKnownSafeForClientAuthentication,
            dependentSpecificationAllowsCleartextFallback);
    }
}
