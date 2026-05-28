// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;
using Incursa.Quic.Http3;

namespace Incursa.Quic.InteropHarness;

internal sealed class InteropHttp3FileHandler : IHttp3RequestHandler
{
    private const int StatusOk = 200;
    private const int StatusBadRequest = 400;
    private const int StatusNotFound = 404;
    private const int StatusMethodNotAllowed = 405;

    private readonly TextWriter stdout;
    private readonly int expectedRequestCount;
    private readonly CancellationTokenSource? completionSignal;
    private int servedRequestCount;

    internal InteropHttp3FileHandler(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        int expectedRequestCount = 0,
        CancellationTokenSource? completionSignal = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        this.stdout = stdout ?? throw new ArgumentNullException(nameof(stdout));
        this.expectedRequestCount = Math.Max(0, expectedRequestCount);
        this.completionSignal = completionSignal;
    }

    public async ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!string.Equals(request.Method, "GET", StringComparison.Ordinal))
        {
            return CreateTextResponse(StatusMethodNotAllowed, "Method Not Allowed");
        }

        if (!InteropHarnessPreflightPlanner.TryGetTransferPathsFromRequestTarget(
            request.Path,
            out string? relativePath,
            out string? sourcePath,
            out _,
            out string? errorMessage) ||
            string.IsNullOrWhiteSpace(relativePath) ||
            string.IsNullOrWhiteSpace(sourcePath))
        {
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=server, testcase=http3 rejected request target {request.Path}: {errorMessage}");
            return CreateTextResponse(StatusBadRequest, "Bad Request");
        }

        if (!File.Exists(sourcePath))
        {
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=server, testcase=http3 missing source file {sourcePath} for {request.Path}.");
            return CreateTextResponse(StatusNotFound, "Not Found");
        }

        byte[] body = await File.ReadAllBytesAsync(sourcePath, cancellationToken).ConfigureAwait(false);
        int served = Interlocked.Increment(ref servedRequestCount);
        WriteLineAndFlush(
            stdout,
            $"interop harness: role=server, testcase=http3 served {relativePath}, bytes={body.Length}, request {served}/{FormatExpectedRequestCount()}.");

        if (expectedRequestCount > 0 && served >= expectedRequestCount)
        {
            if (completionSignal is not null)
            {
                await completionSignal.CancelAsync().ConfigureAwait(false);
            }
        }

        return new Http3ServerResponse(
            StatusOk,
            body,
            [
                new QPackFieldLine("content-type", GetContentType(sourcePath)),
                new QPackFieldLine("content-length", body.Length.ToString()),
            ]);
    }

    private string FormatExpectedRequestCount()
    {
        return expectedRequestCount > 0 ? expectedRequestCount.ToString() : "?";
    }

    private static Http3ServerResponse CreateTextResponse(int statusCode, string text)
    {
        byte[] body = System.Text.Encoding.UTF8.GetBytes(text);
        return new Http3ServerResponse(
            statusCode,
            body,
            [
                new QPackFieldLine("content-type", "text/plain; charset=utf-8"),
                new QPackFieldLine("content-length", body.Length.ToString()),
            ]);
    }

    private static string GetContentType(string filePath)
    {
        return Path.GetExtension(filePath).ToLowerInvariant() switch
        {
            ".css" => "text/css",
            ".gif" => "image/gif",
            ".htm" or ".html" => "text/html; charset=utf-8",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".js" => "text/javascript",
            ".json" => "application/json",
            ".png" => "image/png",
            ".txt" => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        };
    }

    private static void WriteLineAndFlush(TextWriter writer, string message)
    {
        writer.WriteLine(message);
        writer.Flush();
    }
}
