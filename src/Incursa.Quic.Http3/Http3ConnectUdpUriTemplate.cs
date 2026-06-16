// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Validates and expands RFC 9298 CONNECT-UDP URI Templates.
/// </summary>
public sealed class Http3ConnectUdpUriTemplate
{
    private const char MinimumPrintableAscii = '!';
    private const char MaximumPrintableAscii = '~';
    private const string TargetHostVariable = "{target_host}";
    private const string TargetPortVariable = "{target_port}";
    private const string DefaultTemplatePath = "/.well-known/masque/udp/{target_host}/{target_port}/";

    private static readonly string[] ForbiddenOperators = ["{.", "{#", "{+", "{;", "{/"];

    private Http3ConnectUdpUriTemplate(Uri absoluteUri, string template)
    {
        AbsoluteUri = absoluteUri;
        Template = template;
    }

    /// <summary>
    /// Gets the default CONNECT-UDP template path.
    /// </summary>
    public const string DefaultPathTemplate = DefaultTemplatePath;

    /// <summary>
    /// Gets the original absolute URI Template string.
    /// </summary>
    public string Template { get; }

    /// <summary>
    /// Gets the parsed absolute URI Template.
    /// </summary>
    public Uri AbsoluteUri { get; }

    /// <summary>
    /// Gets the UDP proxy authority from the URI Template.
    /// </summary>
    public string ProxyAuthority => AbsoluteUri.IsDefaultPort ? AbsoluteUri.Host : AbsoluteUri.Authority;

    /// <summary>
    /// Validates and creates a CONNECT-UDP URI Template.
    /// </summary>
    public static Http3ConnectUdpUriTemplate Create(string template)
    {
        ArgumentException.ThrowIfNullOrEmpty(template);
        ValidatePrintableAscii(template);
        ValidateForbiddenOperators(template);

        string parseCandidate = CreateUriParseCandidate(template);
        if (!Uri.TryCreate(parseCandidate, UriKind.Absolute, out Uri? uri)
            || string.IsNullOrEmpty(uri.Scheme)
            || string.IsNullOrEmpty(uri.Authority)
            || string.IsNullOrEmpty(uri.AbsolutePath)
            || uri.AbsolutePath[0] != '/')
        {
            throw new ArgumentException("CONNECT-UDP URI Template must be absolute and include non-empty scheme, authority, and slash-prefixed path.", nameof(template));
        }

        string pathAndQuery = GetOriginalPathAndQuery(template);
        if (!pathAndQuery.Contains(TargetHostVariable, StringComparison.Ordinal)
            || !pathAndQuery.Contains(TargetPortVariable, StringComparison.Ordinal))
        {
            throw new ArgumentException("CONNECT-UDP URI Template must contain target_host and target_port variables in the path or query.", nameof(template));
        }

        string beforePathAndQuery = template[..template.IndexOf(pathAndQuery, StringComparison.Ordinal)];
        if (beforePathAndQuery.Contains('{', StringComparison.Ordinal) || beforePathAndQuery.Contains('}', StringComparison.Ordinal))
        {
            throw new ArgumentException("CONNECT-UDP URI Template variables must be in the path or query.", nameof(template));
        }

        return new Http3ConnectUdpUriTemplate(uri, template);
    }

    /// <summary>
    /// Creates the default CONNECT-UDP URI Template for a proxy authority.
    /// </summary>
    public static Http3ConnectUdpUriTemplate CreateDefault(string proxyAuthority, string scheme = "https")
    {
        ArgumentException.ThrowIfNullOrEmpty(proxyAuthority);
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        return Create($"{scheme}://{proxyAuthority}{DefaultPathTemplate}");
    }

    /// <summary>
    /// Expands the template to an HTTP/3 scheme, authority, path, and query request target.
    /// </summary>
    public Http3ConnectUdpRequestTarget Expand(Http3ConnectUdpTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);

        string expanded = Template
            .Replace(TargetHostVariable, target.EncodedHost, StringComparison.Ordinal)
            .Replace(TargetPortVariable, target.Port.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal);

        Uri expandedUri = new(expanded, UriKind.Absolute);
        return new Http3ConnectUdpRequestTarget(expandedUri.Scheme, ProxyAuthority, expandedUri.PathAndQuery);
    }

    private static void ValidatePrintableAscii(string template)
    {
        for (int index = 0; index < template.Length; index++)
        {
            char character = template[index];
            if (character is < MinimumPrintableAscii or > MaximumPrintableAscii)
            {
                throw new ArgumentException("CONNECT-UDP URI Template must contain only printable ASCII characters.", nameof(template));
            }
        }
    }

    private static void ValidateForbiddenOperators(string template)
    {
        foreach (string forbidden in ForbiddenOperators)
        {
            if (template.Contains(forbidden, StringComparison.Ordinal))
            {
                throw new ArgumentException("CONNECT-UDP URI Template uses a forbidden level 4 expansion operator.", nameof(template));
            }
        }
    }

    private static string GetOriginalPathAndQuery(string template)
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

    private static string CreateUriParseCandidate(string template)
    {
        System.Text.StringBuilder builder = new(template.Length);
        int index = 0;
        while (index < template.Length)
        {
            if (template[index] == '{')
            {
                int end = template.IndexOf('}', index);
                if (end > index)
                {
                    builder.Append('x');
                    index = end + 1;
                    continue;
                }
            }

            builder.Append(template[index]);
            index++;
        }

        return builder.ToString();
    }
}
