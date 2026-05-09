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
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerResumptionDispatchAllowsEmptyRunnerRequestsAndExpectsPeerDrivenRequests()
    {
        InteropHarnessRunner.ServerTransferDispatchPlan dispatchPlan = new(
            new IPEndPoint(IPAddress.Any, 443),
            ExpectedRequestCount: 0,
            ConfiguredRequestCount: 0);

        Assert.True(InteropHarnessRunner.TryCreateServerResumptionDispatchCounts(
            dispatchPlan,
            out InteropHarnessRunner.ServerResumptionDispatchCounts? counts,
            out string? errorMessage));

        Assert.NotNull(counts);
        Assert.Null(errorMessage);
        Assert.Equal(1, counts!.FirstConnectionExpectedRequestCount);
        Assert.Equal(1, counts.ResumedConnectionExpectedRequestCount);
        Assert.Equal(2, counts.ConfiguredRequestCount);
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerResumptionDispatchRejectsExplicitSingleRequestPlan()
    {
        InteropHarnessRunner.ServerTransferDispatchPlan dispatchPlan = new(
            new IPEndPoint(IPAddress.Any, 443),
            ExpectedRequestCount: 1,
            ConfiguredRequestCount: 1);

        Assert.False(InteropHarnessRunner.TryCreateServerResumptionDispatchCounts(
            dispatchPlan,
            out InteropHarnessRunner.ServerResumptionDispatchCounts? counts,
            out string? errorMessage));

        Assert.Null(counts);
        Assert.Equal(
            "interop harness: role=server, testcase=resumption requires at least 2 REQUESTS URLs when server REQUESTS is explicitly configured.",
            errorMessage);
    }
}
