using System.Net;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessPreflightPlannerTests
{
    [Theory]
    [InlineData(
        "not-a-url",
        "REQUESTS entry 'not-a-url' is not a valid absolute URL.")]
    [InlineData(
        "http://localhost:443/handshake",
        "REQUESTS entry 'http://localhost:443/handshake' must use https for testcase dispatch.")]
    public void TryGetDispatchRequestUriRejectsInvalidOrNonHttpsRequests(string request, string expectedErrorMessage)
    {
        InteropHarnessPreflightPlanner planner = CreatePlanner("client", "handshake", request);

        Assert.False(planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage));
        Assert.Null(requestUri);
        Assert.Equal(expectedErrorMessage, errorMessage);
    }

    [Fact]
    public void TryGetDispatchRequestUriReturnsTheFirstHttpsRequest()
    {
        InteropHarnessPreflightPlanner planner = CreatePlanner(
            "client",
            "handshake",
            "https://127.0.0.1:8443/first https://localhost:9443/second");

        Assert.True(planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage));
        Assert.NotNull(requestUri);
        Assert.Null(errorMessage);
        Assert.Equal("https", requestUri!.Scheme);
        Assert.Equal("127.0.0.1", requestUri.Host);
        Assert.Equal(8443, requestUri.Port);
        Assert.Equal("/first", requestUri.AbsolutePath);
    }

    [Fact]
    public void TryGetDispatchRequestUriAllowsEmptyRequestsOnlyWhenRequested()
    {
        InteropHarnessPreflightPlanner planner = CreatePlanner("server", "transfer");

        Assert.False(planner.TryGetDispatchRequestUri(out Uri? requestUri, out string? errorMessage));
        Assert.Null(requestUri);
        Assert.Equal("REQUESTS must contain at least one URL for testcase dispatch.", errorMessage);

        Assert.True(planner.TryGetDispatchRequestUri(out requestUri, out errorMessage, allowEmptyRequests: true));
        Assert.Null(requestUri);
        Assert.Null(errorMessage);
    }

    [Fact]
    public async Task TryGetTransferPathsInfersTheFirstMountedFileWhenRequestsAreEmpty()
    {
        string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
        string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
        Directory.CreateDirectory(sourceRoot);

        string? sourceDirectory = null;
        string? sourcePath = null;
        string expectedRelativePath;
        string expectedSourcePath;
        string expectedDestinationPath;

        string[] existingSourceFiles = Directory.EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (existingSourceFiles.Length > 0)
        {
            expectedSourcePath = Path.GetFullPath(existingSourceFiles[0]);
            expectedRelativePath = Path.GetRelativePath(sourceRoot, expectedSourcePath);
            expectedDestinationPath = Path.GetFullPath(Path.Combine(destinationRoot, expectedRelativePath));
        }
        else
        {
            string relativeDirectory = $"~~~~interop-harness-preflight-{Guid.NewGuid():N}";
            string fileName = "payload.txt";
            expectedRelativePath = Path.Combine(relativeDirectory, fileName);
            sourceDirectory = Path.Combine(sourceRoot, relativeDirectory);
            sourcePath = Path.Combine(sourceDirectory, fileName);
            expectedSourcePath = Path.GetFullPath(Path.Combine(sourceRoot, expectedRelativePath));
            expectedDestinationPath = Path.GetFullPath(Path.Combine(destinationRoot, expectedRelativePath));

            Directory.CreateDirectory(sourceDirectory);
            File.WriteAllText(sourcePath, $"preflight transfer payload {Guid.NewGuid():N}");
        }

        try
        {
            DateTime deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            string? lastObservedRelativePath = null;
            string? lastObservedErrorMessage = null;

            while (DateTime.UtcNow < deadline)
            {
                if (InteropHarnessPreflightPlanner.TryGetTransferPaths(
                    null,
                    out string? observedRelativePath,
                    out string? observedSourcePath,
                    out string? observedDestinationPath,
                    out string? errorMessage))
                {
                    if (string.Equals(observedRelativePath, expectedRelativePath, StringComparison.Ordinal))
                    {
                        Assert.Equal(expectedSourcePath, observedSourcePath);
                        Assert.Equal(expectedDestinationPath, observedDestinationPath);
                        Assert.Null(errorMessage);
                        return;
                    }

                    lastObservedRelativePath = observedRelativePath;
                    lastObservedErrorMessage = $"Observed '{observedRelativePath}' while waiting for '{expectedRelativePath}'.";
                }
                else
                {
                    lastObservedErrorMessage = errorMessage;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(50));
            }

            throw new TimeoutException(
                $"The preflight planner did not infer '{expectedRelativePath}' within the timeout. " +
                $"Last observed path: '{lastObservedRelativePath ?? "(none)"}'. " +
                $"Last error: '{lastObservedErrorMessage ?? "(none)"}'.");
        }
        finally
        {
            if (sourcePath is not null)
            {
                TryDeleteFile(sourcePath);
            }

            if (sourceDirectory is not null)
            {
                TryDeleteDirectory(sourceDirectory);
            }
        }
    }

    [Fact]
    public void TryGetTransferPathsRejectsEscapingRequestPaths()
    {
        Uri requestUri = new("https://localhost:443/foo/..%2fescape.txt");

        Assert.False(InteropHarnessPreflightPlanner.TryGetTransferPaths(
            requestUri,
            out string? relativePath,
            out string? sourcePath,
            out string? destinationPath,
            out string? errorMessage));
        Assert.Null(relativePath);
        Assert.Null(sourcePath);
        Assert.Null(destinationPath);
        Assert.NotNull(errorMessage);
        Assert.Contains("must not escape the transfer mount roots", errorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ResolveHandshakeEndpointsUseIpLiteralsWithoutDns()
    {
        Uri ipv4Request = new("https://127.0.0.1:8443/dispatch");
        IPEndPoint ipv4RemoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(ipv4Request);
        IPEndPoint ipv4ListenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(ipv4Request);

        Assert.Equal(IPAddress.Loopback, ipv4RemoteEndPoint.Address);
        Assert.Equal(8443, ipv4RemoteEndPoint.Port);
        Assert.Equal(IPAddress.Loopback, ipv4ListenEndPoint.Address);
        Assert.Equal(8443, ipv4ListenEndPoint.Port);

        Uri ipv6Request = new("https://[::1]:9443/dispatch");
        IPEndPoint ipv6RemoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(ipv6Request);
        IPEndPoint ipv6ListenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(ipv6Request);

        Assert.Equal(IPAddress.IPv6Loopback, ipv6RemoteEndPoint.Address);
        Assert.Equal(9443, ipv6RemoteEndPoint.Port);
        Assert.Equal(IPAddress.IPv6Loopback, ipv6ListenEndPoint.Address);
        Assert.Equal(9443, ipv6ListenEndPoint.Port);
    }

    private static InteropHarnessPreflightPlanner CreatePlanner(
        string role,
        string testcase,
        string? requests = null)
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(role, testcase, requests),
            out InteropHarnessEnvironment? settings,
            out string? errorMessage));
        Assert.NotNull(settings);
        Assert.Null(errorMessage);

        return new InteropHarnessPreflightPlanner(settings!, TextWriter.Null);
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: false);
            }
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }
}
