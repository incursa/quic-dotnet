using System.Net;
using System.Net.Security;

namespace Incursa.Quic.Dns;

/// <summary>
/// DNS over QUIC protocol defaults and option validation helpers.
/// </summary>
public static class DoqDefaults
{
    /// <summary>
    /// The ALPN token used to negotiate DNS over QUIC.
    /// </summary>
    public const string AlpnToken = "doq";

    /// <summary>
    /// The dedicated UDP port assigned to DNS over QUIC.
    /// </summary>
    public const int DefaultPort = 853;

    /// <summary>
    /// The UDP port that DNS over QUIC connections must not use.
    /// </summary>
    public const int ProhibitedPlainDnsPort = 53;

    /// <summary>
    /// Gets the DNS over QUIC ALPN protocol value.
    /// </summary>
    public static SslApplicationProtocol ApplicationProtocol { get; } = new(AlpnToken);

    /// <summary>
    /// Creates a DNS endpoint using the default DoQ port unless an explicit port is supplied.
    /// </summary>
    public static DnsEndPoint CreateClientEndPoint(string host, int port = DefaultPort)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentException("A DNS over QUIC host name is required.", nameof(host));
        }

        ValidatePort(port, nameof(port));
        return new DnsEndPoint(host, port);
    }

    /// <summary>
    /// Creates a listen endpoint using the default DoQ port unless an explicit port is supplied.
    /// </summary>
    public static IPEndPoint CreateListenEndPoint(IPAddress address, int port = DefaultPort)
    {
        ArgumentNullException.ThrowIfNull(address);
        ValidatePort(port, nameof(port));
        return new IPEndPoint(address, port);
    }

    /// <summary>
    /// Ensures client options advertise DoQ and do not target the prohibited DNS port.
    /// </summary>
    public static void EnsureClientConnectionOptions(QuicClientConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        SslClientAuthenticationOptions authenticationOptions = options.ClientAuthenticationOptions
            ?? throw new ArgumentException("DoQ client authentication options are required.", nameof(options));

        authenticationOptions.ApplicationProtocols ??= [];
        EnsureApplicationProtocol(authenticationOptions.ApplicationProtocols, nameof(options));
        ValidateEndPointPort(options.RemoteEndPoint, nameof(options));
    }

    /// <summary>
    /// Ensures listener options advertise DoQ and do not bind the prohibited DNS port.
    /// </summary>
    public static void EnsureListenerOptions(QuicListenerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.ApplicationProtocols ??= [];
        EnsureApplicationProtocol(options.ApplicationProtocols, nameof(options));
        ValidateEndPointPort(options.ListenEndPoint, nameof(options));
    }

    /// <summary>
    /// Returns a value indicating whether the port is permitted for DoQ use.
    /// </summary>
    public static bool IsAllowedPort(int port)
        => port is >= IPEndPoint.MinPort and <= IPEndPoint.MaxPort and not ProhibitedPlainDnsPort;

    private static void EnsureApplicationProtocol(IList<SslApplicationProtocol> protocols, string argumentName)
    {
        if (protocols.Count == 0)
        {
            protocols.Add(ApplicationProtocol);
            return;
        }

        foreach (SslApplicationProtocol protocol in protocols)
        {
            if (protocol.Equals(ApplicationProtocol))
            {
                return;
            }
        }

        throw new ArgumentException("DNS over QUIC requires ALPN doq.", argumentName);
    }

    private static void ValidateEndPointPort(EndPoint? endpoint, string argumentName)
    {
        if (endpoint is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        int? port = endpoint switch
        {
            IPEndPoint ipEndPoint => ipEndPoint.Port,
            DnsEndPoint dnsEndPoint => dnsEndPoint.Port,
            _ => null,
        };

        if (port.HasValue)
        {
            ValidatePort(port.Value, argumentName);
        }
    }

    private static void ValidatePort(int port, string argumentName)
    {
        if (!IsAllowedPort(port))
        {
            throw new ArgumentOutOfRangeException(argumentName, port, "DNS over QUIC must use a UDP port other than 53.");
        }
    }
}
