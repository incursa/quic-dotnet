// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0017">The public resumption slice exposes an opaque ticket carrier, a resumption outcome, client import through QuicClientConnectionOptions.ResumptionTicket, optional server ticket issuance through QuicServerConnectionOptions.EnableResumptionTickets, and no public early-data switch. The ticket carrier must remain immutable, reusable after source disposal, and secret-free in ToString.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0017")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_API_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnection_ExposesTheApprovedResumptionMembers()
    {
        string[] methodNames = typeof(QuicConnection)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName)
            .Select(method => method.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "AcceptInboundStreamAsync",
            "CloseAsync",
            "ConnectAsync",
            "DisposeAsync",
            "OpenOutboundStreamAsync",
            "ReceiveDatagramAsync",
            "SendDatagramAsync",
            "TryExportResumptionTicket",
        }, methodNames);

        PropertyInfo? resumptionOutcomeProperty = typeof(QuicConnection).GetProperty(nameof(QuicConnection.ResumptionOutcome));
        Assert.NotNull(resumptionOutcomeProperty);
        Assert.Equal(typeof(QuicResumptionOutcome), resumptionOutcomeProperty!.PropertyType);

        MethodInfo? exportMethod = typeof(QuicConnection).GetMethod(
            nameof(QuicConnection.TryExportResumptionTicket),
            BindingFlags.Public | BindingFlags.Instance,
            [typeof(QuicResumptionTicket).MakeByRefType()]);

        Assert.NotNull(exportMethod);
        Assert.Equal(typeof(bool), exportMethod!.ReturnType);

        string[] connectionOptionNames = typeof(QuicClientConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Contains(nameof(QuicClientConnectionOptions.ResumptionTicket), connectionOptionNames);
        Assert.DoesNotContain(connectionOptionNames, name => name.Contains("EarlyData", StringComparison.OrdinalIgnoreCase));

        string[] serverOptionNames = typeof(QuicServerConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Contains(nameof(QuicServerConnectionOptions.EnableResumptionTickets), serverOptionNames);
        Assert.DoesNotContain(serverOptionNames, name => name.Contains("EarlyData", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicResumptionTicket_CopiesBytesAndKeepsToStringNonSecret()
    {
        byte[] expectedTicketBytes = [0x10, 0x20, 0x30, 0x40];
        byte[] sourceTicketBytes = [0x10, 0x20, 0x30, 0x40];
        QuicResumptionTicket ticket = new(sourceTicketBytes);

        sourceTicketBytes[0] = 0xFF;

        Assert.Equal(expectedTicketBytes, ticket.TicketBytes.ToArray());
        Assert.Contains("Length = 4 bytes", ticket.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexString(expectedTicketBytes), ticket.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ExportedTicketSurvivesSourceDisposalAndResumesOnTheSameListener()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);

        QuicConnection? firstServerConnection = null;
        QuicConnection? firstClientConnection = null;
        QuicResumptionTicket? exportedTicket = null;

        try
        {
            Task<QuicConnection> firstAcceptTask = listener.AcceptConnectionAsync().AsTask();
            Task<QuicConnection> firstConnectTask = QuicConnection.ConnectAsync(CreateClientOptions(listenEndPoint, serverCertificate)).AsTask();

            await Task.WhenAll(firstAcceptTask, firstConnectTask).WaitAsync(TimeSpan.FromSeconds(5));

            firstServerConnection = await firstAcceptTask;
            firstClientConnection = await firstConnectTask;

            exportedTicket = await WaitForExportedTicketAsync(firstClientConnection);
            Assert.Equal(QuicResumptionOutcome.NotAttempted, firstClientConnection.ResumptionOutcome);
            Assert.Equal(QuicResumptionOutcome.NotAttempted, firstServerConnection.ResumptionOutcome);
        }
        finally
        {
            if (firstServerConnection is not null)
            {
                await firstServerConnection.DisposeAsync();
            }

            if (firstClientConnection is not null)
            {
                await firstClientConnection.DisposeAsync();
            }
        }

        Assert.NotNull(exportedTicket);
        Assert.False(exportedTicket.TicketBytes.IsEmpty);

        Task<QuicConnection> secondAcceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> secondConnectTask = QuicConnection.ConnectAsync(
            CreateClientOptions(listenEndPoint, serverCertificate, exportedTicket)).AsTask();

        await Task.WhenAll(secondAcceptTask, secondConnectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection secondServerConnection = await secondAcceptTask;
        QuicConnection secondClientConnection = await secondConnectTask;

        try
        {
            Assert.Equal(QuicResumptionOutcome.Resumed, secondClientConnection.ResumptionOutcome);
            Assert.Equal(QuicResumptionOutcome.Resumed, secondServerConnection.ResumptionOutcome);
        }
        finally
        {
            await secondServerConnection.DisposeAsync();
            await secondClientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ExportedTicketRejectedByAFreshListenerReportsRejected()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint firstListenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions firstListenerOptions = new()
        {
            ListenEndPoint = firstListenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateServerOptions(serverCertificate)),
        };

        await using QuicListener firstListener = await QuicListener.ListenAsync(firstListenerOptions);

        QuicResumptionTicket? exportedTicket;
        QuicConnection firstServerConnection;
        QuicConnection firstClientConnection;

        Task<QuicConnection> firstAcceptTask = firstListener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> firstConnectTask = QuicConnection.ConnectAsync(CreateClientOptions(firstListenEndPoint, serverCertificate)).AsTask();

        await Task.WhenAll(firstAcceptTask, firstConnectTask).WaitAsync(TimeSpan.FromSeconds(5));

        firstServerConnection = await firstAcceptTask;
        firstClientConnection = await firstConnectTask;

        try
        {
            exportedTicket = await WaitForExportedTicketAsync(firstClientConnection);
        }
        finally
        {
            await firstServerConnection.DisposeAsync();
            await firstClientConnection.DisposeAsync();
        }

        IPEndPoint secondListenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicListenerOptions secondListenerOptions = new()
        {
            ListenEndPoint = secondListenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateServerOptions(serverCertificate)),
        };

        await using QuicListener secondListener = await QuicListener.ListenAsync(secondListenerOptions);

        Task<QuicConnection> secondAcceptTask = secondListener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> secondConnectTask = QuicConnection.ConnectAsync(
            CreateClientOptions(secondListenEndPoint, serverCertificate, exportedTicket)).AsTask();

        await Task.WhenAll(secondAcceptTask, secondConnectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection secondServerConnection = await secondAcceptTask;
        QuicConnection secondClientConnection = await secondConnectTask;

        try
        {
            Assert.Equal(QuicResumptionOutcome.Rejected, secondClientConnection.ResumptionOutcome);
            Assert.Equal(QuicResumptionOutcome.NotAttempted, secondServerConnection.ResumptionOutcome);
        }
        finally
        {
            await secondServerConnection.DisposeAsync();
            await secondClientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RawTicketReportsInvalidTicketWithoutAPublicEarlyDataSwitch()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);

        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            CreateClientOptions(listenEndPoint, serverCertificate, new QuicResumptionTicket(new byte[] { 0x01, 0x02, 0x03 }))).AsTask();

        await Task.WhenAll(acceptTask, connectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            Assert.Equal(QuicResumptionOutcome.InvalidTicket, clientConnection.ResumptionOutcome);
            Assert.Equal(QuicResumptionOutcome.NotAttempted, serverConnection.ResumptionOutcome);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task NoTicketReportsNotAttemptedAndNoPublicEarlyDataSwitchExists()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateServerOptions(serverCertificate)),
        };

        string[] serverPropertyNames = typeof(QuicServerConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .ToArray();

        string[] clientPropertyNames = typeof(QuicClientConnectionOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(property => property.Name)
            .ToArray();

        Assert.DoesNotContain(serverPropertyNames, name => name.Contains("EarlyData", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(clientPropertyNames, name => name.Contains("EarlyData", StringComparison.OrdinalIgnoreCase));

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(CreateClientOptions(listenEndPoint, serverCertificate)).AsTask();

        await Task.WhenAll(acceptTask, connectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            Assert.Equal(QuicResumptionOutcome.NotAttempted, clientConnection.ResumptionOutcome);
            Assert.Equal(QuicResumptionOutcome.NotAttempted, serverConnection.ResumptionOutcome);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    private static QuicClientConnectionOptions CreateClientOptions(
        IPEndPoint remoteEndPoint,
        X509Certificate2 serverCertificate,
        QuicResumptionTicket? resumptionTicket = null)
    {
        QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            remoteEndPoint,
            trustedServerCertificate: serverCertificate);
        options.ResumptionTicket = resumptionTicket;
        return options;
    }

    private static QuicServerConnectionOptions CreateServerOptions(X509Certificate2 serverCertificate)
    {
        QuicServerConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        options.EnableResumptionTickets = true;
        return options;
    }

    private static async Task<QuicResumptionTicket> WaitForExportedTicketAsync(QuicConnection connection)
    {
        using CancellationTokenSource timeoutSource = new(TimeSpan.FromSeconds(5));
        QuicResumptionTicket? ticket;

        while (!connection.TryExportResumptionTicket(out ticket))
        {
            await Task.Delay(50, timeoutSource.Token).ConfigureAwait(false);
        }

        return ticket!;
    }
}
