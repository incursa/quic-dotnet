using System.Net;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0002")]
public sealed class REQ_QUIC_INT_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientDispatchParsesTheFirstHttpsRequestUri()
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "client",
                testcase: "handshake",
                requests: "https://127.0.0.1:12345/handshake"),
            out InteropHarnessEnvironment? environment,
            out string? errorMessage));

        Assert.NotNull(environment);
        Assert.Null(errorMessage);

        Assert.True(InteropHarnessRunner.TryGetDispatchRequestUri(environment, out Uri? requestUri, out errorMessage));
        Assert.NotNull(requestUri);
        Assert.Null(errorMessage);
        Assert.Equal("https", requestUri!.Scheme);
        Assert.Equal("127.0.0.1", requestUri.Host);
        Assert.Equal(12345, requestUri.Port);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerDispatchCanOmitRequestsAndUsesTheFixedListenerPort()
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "server",
                testcase: "handshake"),
            out InteropHarnessEnvironment? environment,
            out string? errorMessage));

        Assert.NotNull(environment);
        Assert.Null(errorMessage);
        Assert.True(InteropHarnessRunner.TryGetDispatchRequestUri(
            environment,
            out Uri? requestUri,
            out errorMessage,
            allowEmptyRequests: true));

        Assert.Null(requestUri);
        Assert.Null(errorMessage);

        IPEndPoint listenEndPoint = await InteropHarnessRunner.ResolveHandshakeListenEndPointAsync(requestUri);
        Assert.Equal(IPAddress.Any, listenEndPoint.Address);
        Assert.Equal(443, listenEndPoint.Port);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDispatchStillRejectsEmptyRequestsWithoutTheServerFallback()
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "client",
                testcase: "handshake"),
            out InteropHarnessEnvironment? environment,
            out string? errorMessage));

        Assert.NotNull(environment);
        Assert.Null(errorMessage);
        Assert.False(InteropHarnessRunner.TryGetDispatchRequestUri(environment, out Uri? requestUri, out errorMessage));
        Assert.Null(requestUri);
        Assert.Equal("REQUESTS must contain at least one URL for testcase dispatch.", errorMessage);
    }
}
