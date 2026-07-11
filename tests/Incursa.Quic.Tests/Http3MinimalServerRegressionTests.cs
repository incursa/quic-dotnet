// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Tests;

[Collection(Http3LoopbackTestCollection.Name)]
public sealed class Http3MinimalServerRegressionTests
{
    private const int ResponseSizeBytes = 1_048_576;
    private const int SequentialRequestCount = 154;

    [Fact]
    [Trait("Category", "Regression")]
    [Trait("Category", "Positive")]
    public async Task SequentialLargeResponses_CompleteWithExactBodyAndFin()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(ResponseSizeBytes);
        Http3InMemoryRouteHandler handler = new();
        handler.MapGet("/large", body);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };

        Http3Server server = await Http3Server.ListenAsync(listenerOptions, handler);
        using CancellationTokenSource cancellationSource = new(TimeSpan.FromMinutes(5));
        Task serverTask = server.ServeAsync(cancellationSource.Token);

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);

        Http3Client client = await Http3Client.ConnectAsync(
            clientOptions,
            new Http3ClientOptions(),
            cancellationSource.Token);

        try
        {
            Stopwatch elapsed = Stopwatch.StartNew();
            for (int requestIndex = 0; requestIndex < SequentialRequestCount; requestIndex++)
            {
                TimeSpan requestStartedAt = elapsed.Elapsed;
                using CancellationTokenSource requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationSource.Token);
                requestTimeout.CancelAfter(TimeSpan.FromSeconds(30));
                Http3Response response;
                try
                {
                    response = await client.GetAsync(
                        new Uri($"https://localhost:{listenEndPoint.Port}/large?request={requestIndex}"),
                        requestTimeout.Token);
                }
                catch (OperationCanceledException ex) when (requestTimeout.IsCancellationRequested)
                {
                    throw new TimeoutException(
                        $"Sequential HTTP/3 large-response regression stalled at request {requestIndex} for {elapsed.Elapsed - requestStartedAt}; total elapsed {elapsed.Elapsed}.",
                        ex);
                }

                Assert.Equal(200, response.StatusCode);
                Assert.Equal(ResponseSizeBytes, response.Body.Length);
                Assert.Equal(body, response.Body);
                Assert.True(response.StreamCompleted);
                Assert.Contains(response.Headers, header => header.Name == "content-length" && header.Value == ResponseSizeBytes.ToString());
            }
        }
        finally
        {
            cancellationSource.Cancel();
            try
            {
                await client.DisposeAsync();
            }
            finally
            {
                await server.DisposeAsync();
                await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
            }
        }
    }

    private static byte[] CreateDeterministicBytes(int length)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)index);
        }

        return payload;
    }
}
