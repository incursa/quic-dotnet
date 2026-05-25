using System.Text;
using Incursa.Qpack;

namespace Incursa.Quic.Http3;

/// <summary>
/// Serves GET requests from an in-memory route table.
/// </summary>
public sealed class Http3InMemoryRouteHandler : IHttp3RequestHandler
{
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

        routes[path] = new Http3ServerResponse(
            200,
            body,
            [
                new QPackFieldLine("content-type", contentType),
                new QPackFieldLine("content-length", body.Length.ToString()),
            ]);
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

        if (request.Method != "GET")
        {
            return ValueTask.FromResult(new Http3ServerResponse(405, ReadOnlyMemory<byte>.Empty));
        }

        string routePath = request.Path;
        int queryStart = routePath.IndexOf('?', StringComparison.Ordinal);
        if (queryStart >= 0)
        {
            routePath = routePath[..queryStart];
        }

        if (routes.TryGetValue(routePath, out Http3ServerResponse? response))
        {
            return ValueTask.FromResult(response);
        }

        return ValueTask.FromResult(new Http3ServerResponse(
            404,
            Encoding.UTF8.GetBytes("Not Found"),
            [
                new QPackFieldLine("content-type", "text/plain; charset=utf-8"),
                new QPackFieldLine("content-length", "9"),
            ]));
    }
}
