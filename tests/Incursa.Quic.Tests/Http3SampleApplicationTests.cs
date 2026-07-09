// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Cryptography;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Incursa.Http3.Samples.ObjectStore;
using Incursa.Http3.Samples.TechEmpower;

namespace Incursa.Quic.Tests;

public sealed class Http3SampleApplicationTests
{
    [Fact]
    public async Task ObjectStoreRoutes_ReturnStaticAssetWithContentLength()
    {
        ObjectStoreHandler handler = new(new InMemoryUploadStore(), new ObjectStoreMetrics());
        Http3ServerResponse response = await handler.HandleAsync(CreateRequest("GET", "/assets/app.css"));

        Assert.Equal(200, response.StatusCode);
        Assert.Contains(response.Headers, header => header.Name == "content-type" && header.Value.StartsWith("text/css", StringComparison.Ordinal));
        Assert.Contains(response.Headers, header => header.Name == "content-length");
        Assert.Contains("body", Encoding.UTF8.GetString(response.Body.Span), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ObjectStoreRoutes_ReturnEmbeddedIncursaLogo()
    {
        ObjectStoreHandler handler = new(new InMemoryUploadStore(), new ObjectStoreMetrics());
        Http3ServerResponse response = await handler.HandleAsync(CreateRequest("GET", "/assets/incursa.svg"));

        Assert.Equal(200, response.StatusCode);
        Assert.Contains(response.Headers, header => header.Name == "content-type" && header.Value == "image/svg+xml");
        Assert.Contains(response.Headers, header => header.Name == "content-length");
        Assert.Contains("<svg", Encoding.UTF8.GetString(response.Body.Span), StringComparison.Ordinal);
        Assert.Contains("viewBox=\"0 0 498 82\"", Encoding.UTF8.GetString(response.Body.Span), StringComparison.Ordinal);
    }

    [Fact]
    public void ObjectStoreRouteMatching_SplitsPathAndQueryString()
    {
        RequestTarget target = ObjectStoreHandler.MatchTarget("/api/headers?x=1&y=two");

        Assert.Equal("/api/headers", target.Path);
        Assert.Equal("x=1&y=two", target.QueryString);
    }

    [Fact]
    public async Task ObjectStoreStatusPayload_ReportsIncursaHttp3Shape()
    {
        ObjectStoreMetrics metrics = new();
        metrics.Emit(new Http3DiagnosticEvent(Http3DiagnosticKind.ConnectionStarted));
        ObjectStoreHandler handler = new(new InMemoryUploadStore(), metrics);

        Http3ServerResponse response = await handler.HandleAsync(CreateRequest("GET", "/api/status"));
        using JsonDocument document = JsonDocument.Parse(response.Body);

        Assert.Equal("Incursa.Http3", document.RootElement.GetProperty("server").GetString());
        Assert.Equal("h3", document.RootElement.GetProperty("protocol").GetString());
        Assert.Equal(Environment.ProcessId, document.RootElement.GetProperty("processId").GetInt32());
        Assert.Equal(1, document.RootElement.GetProperty("activeConnections").GetInt32());
    }

    [Fact]
    public async Task ObjectStoreHeadersPayload_IncludesMethodPathQueryAndHeaders()
    {
        Http3Request request = CreateRequest(
            "GET",
            "/api/headers?debug=true",
            [new QPackFieldLine("x-sample", "present")]);
        ObjectStoreHandler handler = new(new InMemoryUploadStore(), new ObjectStoreMetrics());

        Http3ServerResponse response = await handler.HandleAsync(request);
        using JsonDocument document = JsonDocument.Parse(response.Body);

        Assert.Equal("GET", document.RootElement.GetProperty("method").GetString());
        Assert.Equal("/api/headers", document.RootElement.GetProperty("path").GetString());
        Assert.Equal("debug=true", document.RootElement.GetProperty("queryString").GetString());
        Assert.Equal("present", document.RootElement.GetProperty("headers").GetProperty("x-sample")[0].GetString());
    }

    [Fact]
    public async Task ObjectStoreUpload_StoresContentHashAndReturnsFileById()
    {
        byte[] content = "uploaded over h3"u8.ToArray();
        InMemoryUploadStore uploads = new();
        ObjectStoreHandler handler = new(uploads, new ObjectStoreMetrics());
        Http3Request uploadRequest = CreateRequest(
            "POST",
            "/api/files",
            [new QPackFieldLine("content-type", "text/plain")],
            content);

        Http3ServerResponse uploadResponse = await handler.HandleAsync(uploadRequest);
        using JsonDocument upload = JsonDocument.Parse(uploadResponse.Body);
        string id = upload.RootElement.GetProperty("id").GetString()!;

        Assert.Equal(content.Length, upload.RootElement.GetProperty("byteCount").GetInt32());
        Assert.Equal(Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(), upload.RootElement.GetProperty("sha256").GetString());

        Http3ServerResponse downloadResponse = await handler.HandleAsync(CreateRequest("GET", "/api/files/" + id));
        Assert.Equal(200, downloadResponse.StatusCode);
        Assert.Equal(content, downloadResponse.Body.ToArray());
    }

    [Fact]
    public async Task ObjectStoreUpload_RejectsOverLimitBody()
    {
        ObjectStoreHandler handler = new(new InMemoryUploadStore(), new ObjectStoreMetrics(), maxUploadBytes: 3);

        Http3ServerResponse response = await handler.HandleAsync(CreateRequest("POST", "/api/files", [], "four"u8.ToArray()));

        Assert.Equal(413, response.StatusCode);
    }

    [Fact]
    public void ObjectStoreStartupInstructions_PrintBrowserQuicLaunchCommands()
    {
        string instructions = BrowserLaunchInstructions.Create(4433, "sample-spki");

        Assert.Contains("HTTP/3 over QUIC/UDP only", instructions, StringComparison.Ordinal);
        Assert.Contains("--origin-to-force-quic-on=localhost:4433", instructions, StringComparison.Ordinal);
        Assert.Contains("--ignore-certificate-errors-spki-list=sample-spki", instructions, StringComparison.Ordinal);
        Assert.Contains("Microsoft\\Edge\\Application\\msedge.exe", instructions, StringComparison.Ordinal);
        Assert.Contains("Google\\Chrome\\Application\\chrome.exe", instructions, StringComparison.Ordinal);
        Assert.Contains("Mozilla Firefox\\firefox.exe", instructions, StringComparison.Ordinal);
        Assert.Contains("Firefox does not provide a Chromium-style", instructions, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TechEmpowerPlaintextAndJson_UseExactPayloads()
    {
        TechEmpowerHandler handler = new();

        Http3ServerResponse plaintext = await handler.HandleAsync(CreateRequest("GET", "/plaintext"));
        Http3ServerResponse json = await handler.HandleAsync(CreateRequest("GET", "/json"));

        Assert.Equal("Hello, World!", Encoding.UTF8.GetString(plaintext.Body.Span));
        Assert.Equal("""{"message":"Hello, World!"}""", Encoding.UTF8.GetString(json.Body.Span));
        Assert.Contains(plaintext.Headers, header => header.Name == "server" && header.Value == "Incursa.Http3");
        Assert.Contains(json.Headers, header => header.Name == "content-type" && header.Value == "application/json");
    }

    [Fact]
    public async Task TechEmpowerPlaintext_HeadersOnlyFastPathUsesExactPayload()
    {
        TechEmpowerHandler handler = new();
        Http3HeadersOnlyRequest request = CreateHeadersOnlyRequest("GET", "/plaintext");

        Http3ServerResponse response = await handler.HandleHeadersOnlyAsync(request);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("Hello, World!", Encoding.UTF8.GetString(response.Body.Span));
        Assert.Contains(response.Headers, header => header.Name == "server" && header.Value == "Incursa.Http3");
        Assert.True(response.CacheEncodedHeaders);
    }

    [Theory]
    [InlineData("/bytes/1024", 1024)]
    [InlineData("/bytes/65536", 64 * 1024)]
    [InlineData("/bytes/1048576", 1024 * 1024)]
    public async Task TechEmpowerBytesRoutes_ReturnDeterministicPayloads(string path, int expectedLength)
    {
        TechEmpowerHandler handler = new();

        Http3ServerResponse response = await handler.HandleAsync(CreateRequest("GET", path));

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(expectedLength, response.Body.Length);
        Assert.Contains(response.Headers, header => header.Name == "content-type" && header.Value == "application/octet-stream");
        Assert.Contains(response.Headers, header => header.Name == "content-length" && header.Value == expectedLength.ToString(CultureInfo.InvariantCulture));
        Assert.Equal(CreateDeterministicBytes(expectedLength), response.Body.ToArray());
    }

    [Fact]
    public async Task TechEmpowerPayloadRoutes_BorrowStaticPayloadBodyMemory()
    {
        TechEmpowerHandler handler = new();

        Http3ServerResponse first = await handler.HandleAsync(CreateRequest("GET", "/bytes/1024"));
        Http3ServerResponse second = await handler.HandleAsync(CreateRequest("GET", "/bytes/1024"));

        Assert.True(first.CacheEncodedHeaders);
        Assert.True(second.CacheEncodedHeaders);
        Assert.True(MemoryMarshal.TryGetArray(first.Body, out ArraySegment<byte> firstSegment));
        Assert.True(MemoryMarshal.TryGetArray(second.Body, out ArraySegment<byte> secondSegment));
        Assert.Same(firstSegment.Array, secondSegment.Array);
    }

    [Theory]
    [InlineData("/db")]
    [InlineData("/queries?queries=10")]
    [InlineData("/fortunes")]
    [InlineData("/updates?queries=10")]
    [InlineData("/cached-queries?count=100")]
    public async Task TechEmpowerDatabaseRoutes_AreExplicitPlaceholders(string path)
    {
        TechEmpowerHandler handler = new();

        Http3ServerResponse response = await handler.HandleAsync(CreateRequest("GET", path));

        Assert.Equal(501, response.StatusCode);
        Assert.Contains("intentionally not implemented", Encoding.UTF8.GetString(response.Body.Span), StringComparison.Ordinal);
    }

    private static Http3Request CreateRequest(
        string method,
        string path,
        IReadOnlyList<QPackFieldLine>? extraHeaders = null,
        ReadOnlyMemory<byte> body = default)
    {
        List<QPackFieldLine> headers =
        [
            new QPackFieldLine(":method", method),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
        ];

        if (extraHeaders is not null)
        {
            headers.AddRange(extraHeaders);
        }

        return new Http3Request(method, "https", "localhost", path, headers, body);
    }

    private static Http3HeadersOnlyRequest CreateHeadersOnlyRequest(
        string method,
        string path,
        IReadOnlyList<QPackFieldLine>? extraHeaders = null)
    {
        List<QPackFieldLine> headers =
        [
            new QPackFieldLine(":method", method),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
        ];

        if (extraHeaders is not null)
        {
            headers.AddRange(extraHeaders);
        }

        return new Http3HeadersOnlyRequest(method, "https", "localhost", path, protocol: null, headers);
    }

    private static byte[] CreateDeterministicBytes(int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(index % 251);
        }

        return bytes;
    }
}
