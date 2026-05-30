// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
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
        Assert.Equal(IPAddress.IPv6Any, listenEndPoint.Address);
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
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttDispatchAllowsOpenEndedSecondConnectionForRunnerRequests()
    {
        InteropHarnessRunner.ServerTransferDispatchPlan dispatchPlan = new(
            new IPEndPoint(IPAddress.Any, 443),
            ExpectedRequestCount: 0,
            ConfiguredRequestCount: 0);

        Assert.True(InteropHarnessRunner.TryCreateServerResumptionDispatchCounts(
            dispatchPlan,
            "zerortt",
            emptySecondConnectionExpectedRequestCount: 0,
            out InteropHarnessRunner.ServerResumptionDispatchCounts? counts,
            out string? errorMessage));

        Assert.NotNull(counts);
        Assert.Null(errorMessage);
        Assert.Equal(1, counts!.FirstConnectionExpectedRequestCount);
        Assert.Equal(0, counts.ResumedConnectionExpectedRequestCount);
        Assert.Equal(0, counts.ConfiguredRequestCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttOpenEndedSecondConnectionUsesAShortRequestGapTimeout()
    {
        Assert.Equal(
            TimeSpan.FromSeconds(2),
            InteropHarnessRunner.GetServerRequestWaitTimeout("zerortt", 0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerZeroRttExplicitRequestCountStillUsesTheDefaultRequestGapTimeout()
    {
        Assert.Equal(
            TimeSpan.FromSeconds(20),
            InteropHarnessRunner.GetServerRequestWaitTimeout("zerortt", 2));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttOptionsEnableResumptionTicketsAndEarlyData()
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "server",
                testcase: "zerortt"),
            out InteropHarnessEnvironment? environment,
            out string? errorMessage));

        Assert.NotNull(environment);
        Assert.Null(errorMessage);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        InteropHarnessPreflightPlanner planner = new(environment!, TextWriter.Null);
        QuicServerConnectionOptions options = planner.CreateSupportedServerOptions(serverCertificate);

        Assert.True(options.EnableResumptionTickets);
        Assert.True(options.EnableEarlyData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionMigrationPreferredAddressFactoryBuildsACompleteTransportParameter()
    {
        QuicPreferredAddress preferredAddress = InteropHarnessPreflightPlanner.CreateConnectionMigrationPreferredAddress(
            IPAddress.Parse("192.0.2.10"),
            IPAddress.Parse("2001:db8::10"),
            443);

        Assert.Equal(new byte[] { 192, 0, 2, 10 }, preferredAddress.IPv4Address);
        Assert.Equal((ushort)443, preferredAddress.IPv4Port);
        Assert.Equal(new byte[] { 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 }, preferredAddress.IPv6Address);
        Assert.Equal((ushort)443, preferredAddress.IPv6Port);
        Assert.Equal(Convert.FromHexString("2021222324252627"), preferredAddress.ConnectionId);
        Assert.Equal(Convert.FromHexString("303132333435363738393A3B3C3D3E3F"), preferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionMigrationPreferredAddressFactoryCanBuildAnIpv4OnlyTransportParameter()
    {
        QuicPreferredAddress preferredAddress = InteropHarnessPreflightPlanner.CreateConnectionMigrationPreferredAddress(
            IPAddress.Parse("192.0.2.10"),
            443);

        Assert.Equal(new byte[] { 192, 0, 2, 10 }, preferredAddress.IPv4Address);
        Assert.Equal((ushort)443, preferredAddress.IPv4Port);
        Assert.Equal(new byte[16], preferredAddress.IPv6Address);
        Assert.Equal((ushort)0, preferredAddress.IPv6Port);
        Assert.Equal(Convert.FromHexString("2021222324252627"), preferredAddress.ConnectionId);
        Assert.Equal(Convert.FromHexString("303132333435363738393A3B3C3D3E3F"), preferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionMigrationServerOptionsAdvertiseTheDualStackPreferredAddress()
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "server",
                testcase: "connectionmigration"),
            out InteropHarnessEnvironment? environment,
            out string? errorMessage));

        Assert.NotNull(environment);
        Assert.Null(errorMessage);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        InteropHarnessPreflightPlanner planner = new(environment!, TextWriter.Null);
        QuicServerConnectionOptions options = planner.CreateSupportedServerOptions(serverCertificate);

        Assert.NotNull(options.PreferredAddress);
        Assert.Equal(new byte[] { 193, 167, 100, 110 }, options.PreferredAddress!.IPv4Address);
        Assert.Equal((ushort)443, options.PreferredAddress.IPv4Port);
        Assert.Equal(IPAddress.Parse("fd00:cafe:cafe:100::110").GetAddressBytes(), options.PreferredAddress.IPv6Address);
        Assert.Equal((ushort)443, options.PreferredAddress.IPv6Port);
        Assert.Equal(Convert.FromHexString("2021222324252627"), options.PreferredAddress.ConnectionId);
        Assert.Equal(Convert.FromHexString("303132333435363738393A3B3C3D3E3F"), options.PreferredAddress.StatelessResetToken);
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerZeroRttDispatchRejectsExplicitSingleRequestPlan()
    {
        InteropHarnessRunner.ServerTransferDispatchPlan dispatchPlan = new(
            new IPEndPoint(IPAddress.Any, 443),
            ExpectedRequestCount: 1,
            ConfiguredRequestCount: 1);

        Assert.False(InteropHarnessRunner.TryCreateServerResumptionDispatchCounts(
            dispatchPlan,
            "zerortt",
            emptySecondConnectionExpectedRequestCount: 0,
            out InteropHarnessRunner.ServerResumptionDispatchCounts? counts,
            out string? errorMessage));

        Assert.Null(counts);
        Assert.Equal(
            "interop harness: role=server, testcase=zerortt requires at least 2 REQUESTS URLs when server REQUESTS is explicitly configured.",
            errorMessage);
    }
}
