// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(Http3LoopbackTestCollection.Name)]
public sealed class Http3MinimalClientTests
{
    [Fact]
    public async Task GetAsync_OverLoopbackQuic_ReturnsResponseHeadersAndBody()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

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

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serverTask = RunMinimalServerAsync(listener, clientCompleted.Task);

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);

        await using Http3Client client = await Http3Client.ConnectAsync(
            clientOptions,
            new Http3ClientOptions { UserAgent = "incursa-http3-test" }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Http3Response response;
        try
        {
            response = await client.GetAsync(
                new Uri($"https://localhost:{listenEndPoint.Port}/resource?q=1")).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            clientCompleted.TrySetResult(null);
        }

        Assert.Equal(200, response.StatusCode);
        Assert.True(response.StreamCompleted);
        Assert.Equal("hello over h3", System.Text.Encoding.ASCII.GetString(response.Body));
        Assert.Contains(response.Headers, header => header.Name == "content-type" && header.Value == "text/plain");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void ConnectAsync_RejectsClientOptionsWithoutH3Alpn()
    {
        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, 443));
        SslClientAuthenticationOptions? authenticationOptions = clientOptions.ClientAuthenticationOptions;
        if (authenticationOptions is null)
        {
            throw new InvalidOperationException("The test client options did not include TLS authentication options.");
        }

        authenticationOptions.ApplicationProtocols ??= [];
        authenticationOptions.ApplicationProtocols.Clear();
        authenticationOptions.ApplicationProtocols.Add(SslApplicationProtocol.Http11);

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => Http3Client.ConnectAsync(clientOptions).AsTask().GetAwaiter().GetResult());

        Assert.Contains("ALPN h3", exception.Message, StringComparison.Ordinal);
    }

    private static async Task RunMinimalServerAsync(QuicListener listener, Task clientCompleted)
    {
        await using QuicConnection connection = await listener.AcceptConnectionAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicStream? requestStream = null;
        List<QuicStream> unidirectionalStreams = [];

        try
        {
            while (requestStream is null || unidirectionalStreams.Count < 3)
            {
                QuicStream stream = await connection.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                if (stream.Type == QuicStreamType.Bidirectional)
                {
                    requestStream = stream;
                }
                else
                {
                    unidirectionalStreams.Add(stream);
                    await ObserveUnidirectionalStreamPreambleAsync(stream);
                }
            }

            Assert.NotNull(requestStream);
            await RespondAsync(requestStream);
            await clientCompleted.WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            if (requestStream is not null)
            {
                await requestStream.DisposeAsync();
            }

            foreach (QuicStream stream in unidirectionalStreams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static async Task ObserveUnidirectionalStreamPreambleAsync(QuicStream stream)
    {
        byte[] buffer = new byte[512];
        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(bytesRead > 0);

        Assert.True(Http3VariableLengthInteger.TryParse(buffer.AsSpan(0, bytesRead), out ulong streamType, out int bytesConsumed));
        Assert.True(
            streamType is (ulong)Http3StreamType.Control
                or (ulong)Http3StreamType.QPackEncoder
                or (ulong)Http3StreamType.QPackDecoder);

        if (streamType != (ulong)Http3StreamType.Control)
        {
            return;
        }

        Http3FrameReader reader = new();
        Http3SettingsFrame? settingsFrame = ReadSettingsFrame(reader.Read(buffer.AsSpan(bytesConsumed, bytesRead - bytesConsumed)));
        while (settingsFrame is null)
        {
            bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(bytesRead > 0);
            settingsFrame = ReadSettingsFrame(reader.Read(buffer.AsSpan(0, bytesRead)));
        }

        Assert.Equal(0UL, settingsFrame.Values.QPackMaxTableCapacity);
        Assert.Equal(0UL, settingsFrame.Values.QPackBlockedStreams);
    }

    private static Http3SettingsFrame? ReadSettingsFrame(IEnumerable<Http3Frame> frames)
    {
        foreach (Http3Frame frame in frames)
        {
            return Assert.IsType<Http3SettingsFrame>(frame);
        }

        return null;
    }

    private static async Task RespondAsync(QuicStream requestStream)
    {
        Http3FrameReader reader = new();
        byte[] buffer = new byte[1024];
        QPackFieldLine[]? requestHeaders = null;

        while (true)
        {
            int bytesRead = await requestStream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            if (bytesRead == 0)
            {
                foreach (Http3Frame frame in reader.Complete())
                {
                    requestHeaders = CaptureRequestHeaders(frame, requestHeaders);
                }

                break;
            }

            foreach (Http3Frame frame in reader.Read(buffer.AsSpan(0, bytesRead)))
            {
                requestHeaders = CaptureRequestHeaders(frame, requestHeaders);
            }
        }

        Assert.NotNull(requestHeaders);
        Assert.Contains(requestHeaders, header => header.Name == ":method" && header.Value == "GET");
        Assert.Contains(requestHeaders, header => header.Name == ":path" && header.Value == "/resource?q=1");
        Assert.Contains(requestHeaders, header => header.Name == ":authority" && header.Value.StartsWith("localhost:", StringComparison.Ordinal));

        byte[] responseHeaders = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("content-type", "text/plain"),
        ]);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(responseHeaders);
        byte[] dataFrame = Http3FrameWriter.WriteData("hello over h3"u8);

        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static QPackFieldLine[]? CaptureRequestHeaders(Http3Frame frame, QPackFieldLine[]? current)
    {
        if (frame is not Http3HeadersFrame headersFrame)
        {
            return current;
        }

        Assert.Null(current);
        return QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection);
    }
}
