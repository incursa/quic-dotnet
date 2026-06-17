// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Deterministic encrypted DNS session target produced before opening a network connection.
/// </summary>
public sealed class EncryptedDnsSessionAttempt
{
    internal EncryptedDnsSessionAttempt(
        EncryptedDnsSessionAttemptSource source,
        DnsServiceBindingProtocol protocol,
        IPAddress? address,
        string authenticationName,
        int port,
        ushort servicePriority,
        bool canTryCleartextResolverAfterEncryptedFailure,
        string? dohPathTemplate,
        IReadOnlyList<string> serviceParameterKeys,
        IReadOnlyDictionary<string, string> httpsServiceParameters)
    {
        if (port is < IPEndPoint.MinPort + 1 or > IPEndPoint.MaxPort)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "The encrypted DNS session port must be a valid non-zero port.");
        }

        if (port == DnsServiceBindingDefaults.CleartextDnsDefaultPort)
        {
            throw new ArgumentException("Encrypted DNS session attempts must not target the classic cleartext DNS port.", nameof(port));
        }

        Source = source;
        Protocol = protocol;
        Address = address;
        AuthenticationName = authenticationName;
        Port = port;
        ServicePriority = servicePriority;
        CanTryCleartextResolverAfterEncryptedFailure = canTryCleartextResolverAfterEncryptedFailure;
        DohPathTemplate = dohPathTemplate;
        ServiceParameterKeys = new ReadOnlyCollection<string>([.. serviceParameterKeys]);
        HttpsServiceParameters = new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(httpsServiceParameters, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Gets the planning surface that produced this attempt.
    /// </summary>
    public EncryptedDnsSessionAttemptSource Source { get; }

    /// <summary>
    /// Gets the encrypted DNS protocol to establish.
    /// </summary>
    public DnsServiceBindingProtocol Protocol { get; }

    /// <summary>
    /// Gets the literal resolver address when discovery or provisioning supplied one.
    /// </summary>
    public IPAddress? Address { get; }

    /// <summary>
    /// Gets the authentication name to validate during secure transport establishment.
    /// </summary>
    public string AuthenticationName { get; }

    /// <summary>
    /// Gets the effective encrypted DNS service port.
    /// </summary>
    public int Port { get; }

    /// <summary>
    /// Gets the service priority for ordered resolver attempts.
    /// </summary>
    public ushort ServicePriority { get; }

    /// <summary>
    /// Gets a value indicating whether a cleartext resolver can be tried after encrypted establishment fails.
    /// </summary>
    public bool CanTryCleartextResolverAfterEncryptedFailure { get; }

    /// <summary>
    /// Gets the DoH path template when the attempt targets DNS-over-HTTPS.
    /// </summary>
    public string? DohPathTemplate { get; }

    /// <summary>
    /// Gets normalized service parameter keys preserved from discovery or provisioning input.
    /// </summary>
    public IReadOnlyList<string> ServiceParameterKeys { get; }

    /// <summary>
    /// Gets HTTPS service parameter values carried by RFC 9461 endpoint selection.
    /// </summary>
    public IReadOnlyDictionary<string, string> HttpsServiceParameters { get; }
}
