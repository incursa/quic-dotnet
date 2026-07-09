// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Serves GET requests from an in-memory route table.
/// </summary>
public sealed class Http3InMemoryRouteHandler : IHttp3RequestHandler, IHttp3HeadersOnlyRequestHandler
{
    private const int StatusOk = 200;
    private const int StatusNotFound = 404;
    private const int StatusMethodNotAllowed = 405;

    private readonly Dictionary<string, Http3ServerResponse> routes = new(StringComparer.Ordinal);

    /// <summary>
    /// Adds or replaces a GET route.
    /// </summary>
    public Http3InMemoryRouteHandler MapGet(string path, ReadOnlyMemory<byte> body, string contentType = "application/octet-stream")
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(contentType);
        if (path[0] != '/')
        {
            throw new ArgumentException("HTTP/3 route paths must begin with '/'.", nameof(path));
        }

        byte[] routeBody = body.ToArray();
        QPackFieldLine[] routeHeaders =
        [
            new QPackFieldLine("content-type", contentType),
            new QPackFieldLine("content-length", routeBody.Length.ToString()),
        ];

        routes[path] = Http3ServerResponse.CreateFromImmutableBodyAndHeaders(
            StatusOk,
            routeBody,
            routeHeaders);
        return this;
    }

    /// <summary>
    /// Adds or replaces a UTF-8 text GET route.
    /// </summary>
    public Http3InMemoryRouteHandler MapGetText(string path, string body, string contentType = "text/plain; charset=utf-8")
    {
        ArgumentNullException.ThrowIfNull(body);
        return MapGet(path, Encoding.UTF8.GetBytes(body), contentType);
    }

    /// <inheritdoc />
    public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Handle(request.Method, request.Path));
    }

    /// <inheritdoc />
    public ValueTask<Http3ServerResponse> HandleHeadersOnlyAsync(
        Http3HeadersOnlyRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(Handle(request.Method, request.Path));
    }

    private Http3ServerResponse Handle(string method, string path)
    {
        if (method != "GET")
        {
            return new Http3ServerResponse(StatusMethodNotAllowed, ReadOnlyMemory<byte>.Empty);
        }

        string routePath = path;
        int queryStart = routePath.IndexOf('?', StringComparison.Ordinal);
        if (queryStart >= 0)
        {
            routePath = routePath[..queryStart];
        }

        if (routes.TryGetValue(routePath, out Http3ServerResponse? response))
        {
            return response;
        }

        return new Http3ServerResponse(
            StatusNotFound,
            Encoding.UTF8.GetBytes("Not Found"),
            [
                new QPackFieldLine("content-type", "text/plain; charset=utf-8"),
                new QPackFieldLine("content-length", "9"),
            ]);
    }
}
