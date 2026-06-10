// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Incursa.Quic;

var port = args.Length > 0 && int.TryParse(args[0], out var parsedPort) ? parsedPort : 0;
var listenPort = port > 0 ? port : GetFreePort();
var alpn = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ALPN") ?? "plab-raw-quic";
var certSubject = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_CERT_SUBJECT") ?? "CN=Incursa-RawQuic-Local";
var payloadDirection = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_PAYLOAD_DIRECTION") ?? "bidirectional";
var echoResponses = !string.Equals(payloadDirection, "client-to-server", StringComparison.OrdinalIgnoreCase);

var certificate = GenerateSelfSignedCertificate(certSubject);
var alpnProtocol = new SslApplicationProtocol(alpn);
var debugLogging = string.Equals(Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG"), "1", StringComparison.Ordinal);
var connectionCount = 0;

var listenerOptions = new QuicListenerOptions
{
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, listenPort),
    ApplicationProtocols = [alpnProtocol],
    ConnectionOptionsCallback = (_, _, _) =>
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer accepted handshake proposal for ALPN '{alpn}'");
        }

        return ValueTask.FromResult(new QuicServerConnectionOptions
        {
            DefaultStreamErrorCode = 0,
            DefaultCloseErrorCode = 0,
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ApplicationProtocols = [alpnProtocol],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption
            }
        });
    }
};

var listener = await QuicListener.ListenAsync(listenerOptions);

Console.Error.WriteLine($"IncursaRawQuicServer listening on 127.0.0.1:{listenPort} with ALPN '{alpn}'");
Console.WriteLine($"QUIC_ENDPOINT=127.0.0.1:{listenPort}");
Console.WriteLine($"QUIC_PORT={listenPort}");
Console.WriteLine($"QUIC_ALPN={alpn}");
Console.WriteLine($"QUIC_IMPLEMENTATION=incursa-raw-quic");

try
{
    while (true)
    {
        var connection = await listener.AcceptConnectionAsync(default);
        var connectionIndex = Interlocked.Increment(ref connectionCount);
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer accepted connection #{connectionIndex} for ALPN '{alpn}'");
        }

        _ = HandleConnectionAsync(connection, connectionIndex, default, debugLogging, echoResponses);
    }
}
catch (OperationCanceledException)
{
}
catch (ObjectDisposedException)
{
}
catch (QuicException ex)
{
    if (debugLogging)
    {
        Console.Error.WriteLine($"IncursaRawQuicServer listener stopped with QUIC error: {ex.Message}");
    }
}
finally
{
    await listener.DisposeAsync();
}

static async Task HandleConnectionAsync(QuicConnection connection, int connectionIndex, CancellationToken cancellationToken, bool debugLogging, bool echoResponses)
{
    try
    {
        var streamIndex = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            var stream = await connection.AcceptInboundStreamAsync(cancellationToken);
            var acceptedStreamIndex = Interlocked.Increment(ref streamIndex);
            if (debugLogging)
            {
                Console.Error.WriteLine($"IncursaRawQuicServer accepted inbound stream #{acceptedStreamIndex} on connection #{connectionIndex}");
            }

            _ = HandleStreamAsync(stream, connectionIndex, acceptedStreamIndex, cancellationToken, debugLogging, echoResponses);
        }
    }
    catch (OperationCanceledException)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer connection #{connectionIndex} stopped: cancellation requested");
        }
    }
    catch (QuicException ex)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer connection #{connectionIndex} stopped with QUIC error: {ex.Message}");
        }
    }
    catch (ObjectDisposedException ex)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer connection #{connectionIndex} disposed: {ex.Message}");
        }
    }
    finally
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer closing connection #{connectionIndex}");
        }

        await connection.DisposeAsync();
    }
}

static async Task HandleStreamAsync(QuicStream stream, int connectionIndex, int streamIndex, CancellationToken cancellationToken, bool debugLogging, bool echoResponses)
{
    try
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer handling stream #{streamIndex} on connection #{connectionIndex}");
        }

        var buffer = new byte[65536];

        while (true)
        {
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (bytesRead <= 0)
            {
                if (debugLogging)
                {
                    Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} reached EOF after read loop");
                }
                break;
            }

            if (debugLogging)
            {
                Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} read {bytesRead} byte(s)");
            }

            if (echoResponses && stream.CanWrite)
            {
                await stream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);

                if (debugLogging)
                {
                    Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} echoed {bytesRead} byte(s)");
                }
            }
        }

        if (stream.CanWrite)
        {
            await stream.CompleteWritesAsync(cancellationToken);
            if (debugLogging)
            {
                Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} completed writes");
            }
        }
    }
    catch (OperationCanceledException)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} canceled");
        }
    }
    catch (QuicException ex)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} failed with QUIC error: {ex.Message}");
        }
    }
    finally
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer closing stream #{streamIndex} on connection #{connectionIndex}");
        }

        await stream.DisposeAsync();
    }
}

static X509Certificate2 GenerateSelfSignedCertificate(string subject)
{
    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
    var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    return X509CertificateLoader.LoadPkcs12(
        cert.Export(X509ContentType.Pfx),
        (string?)null,
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
}

static int GetFreePort()
{
    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    return ((IPEndPoint)socket.LocalEndPoint!).Port;
}
