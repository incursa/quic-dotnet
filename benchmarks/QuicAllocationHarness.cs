// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

#pragma warning disable CA1416

using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using IncursaClientConnection = global::Incursa.Quic.QuicConnection;
using IncursaListener = global::Incursa.Quic.QuicListener;
using SystemNetClientConnection = global::System.Net.Quic.QuicConnection;
using SystemNetListener = global::System.Net.Quic.QuicListener;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Non-BDN allocation measurement harness that runs high-N connection iterations
/// and reports managed allocations, working-set, and private-bytes delta per iteration.
/// Runs two passes to distinguish warmup/cache effects from real per-connection retention.
///
/// Usage:
///   dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness [count]
///
/// Example:
///   dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness 5000
/// </summary>
internal static class QuicAllocationHarness
{
    private const int DefaultCount = 2000;
    private const int WarmupCount = 3;
    private const int PassCount = 2;

    internal static int Run(string[] args)
    {
        int count = DefaultCount;
        if (args.Length > 1 && int.TryParse(args[1], out int parsed) && parsed > 0)
        {
            count = parsed;
        }

        Console.WriteLine();
        Console.WriteLine("=== QUIC Allocation Harness ===");
        Console.WriteLine($"Iterations per pass: {count:N0}");
        Console.WriteLine($"Passes: {PassCount}");
        Console.WriteLine();

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);

        try
        {
            if (IncursaClientConnection.IsSupported && IncursaListener.IsSupported)
            {
                for (int pass = 1; pass <= PassCount; pass++)
                {
                    RunPass($"Incursa.Quic  pass {pass}/{PassCount}", count,
                        () => RunIncursaConnectAcceptDisposeAsync(serverAuthOptions, clientAuthOptions)
                            .GetAwaiter().GetResult());
                }
                Console.WriteLine();
            }

            if (SystemNetClientConnection.IsSupported && SystemNetListener.IsSupported)
            {
                for (int pass = 1; pass <= PassCount; pass++)
                {
                    RunPass($"System.Net.Quic  pass {pass}/{PassCount}", count,
                        () => RunSystemNetConnectAcceptDisposeAsync(serverAuthOptions, clientAuthOptions)
                            .GetAwaiter().GetResult());
                }
                Console.WriteLine();
            }
        }
        finally
        {
            trustAnchor.Dispose();
            serverCertificate.Dispose();
        }

        return 0;
    }

    private static void RunPass(string label, int count, Action operation)
    {
        // Warmup — settle JIT and early allocations
        for (int i = 0; i < WarmupCount; i++)
        {
            operation();
        }

        // Forced GC settle before measurement
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var process = Process.GetCurrentProcess();
        process.Refresh();

        long startManaged = GC.GetTotalAllocatedBytes(precise: true);
        long startWorkingSet = process.WorkingSet64;
        long startPrivateBytes = process.PrivateMemorySize64;
        long startStopwatch = Stopwatch.GetTimestamp();

        for (int i = 0; i < count; i++)
        {
            operation();
        }

        process.Refresh();
        long endStopwatch = Stopwatch.GetTimestamp();
        long endManaged = GC.GetTotalAllocatedBytes(precise: true);
        long endWorkingSet = process.WorkingSet64;
        long endPrivateBytes = process.PrivateMemorySize64;

        double elapsedSec = (double)(endStopwatch - startStopwatch) / Stopwatch.Frequency;
        long managedDelta = endManaged - startManaged;
        long wsDelta = endWorkingSet - startWorkingSet;
        long privDelta = endPrivateBytes - startPrivateBytes;

        Console.WriteLine(
            $"  {label, -28}" +
            $"{count,6:N0} iters  {elapsedSec,7:N3}s  {elapsedSec / count * 1000,8:N3} ms/op");
        Console.WriteLine(
            $"  {"",-28}" +
            $"managed: {managedDelta / (double)count,10:N0} B/op  " +
            $"ws: {wsDelta / (double)count,10:N0} B/op  " +
            $"priv: {privDelta / (double)count,10:N0} B/op");
    }

    private static async Task RunIncursaConnectAcceptDisposeAsync(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(
                listenEndPoint, serverOptions)).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientOptions)).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        IncursaClientConnection serverConnection = await acceptTask.ConfigureAwait(false);
        IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await serverConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await clientConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await serverConnection.DisposeAsync().ConfigureAwait(false);
        await clientConnection.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task RunSystemNetConnectAcceptDisposeAsync(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(
                listenEndPoint, serverOptions)).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientOptions)).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        SystemNetClientConnection serverConnection = await acceptTask.ConfigureAwait(false);
        SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await serverConnection.CloseAsync(0, CancellationToken.None);
        await clientConnection.CloseAsync(0, CancellationToken.None);
        await serverConnection.DisposeAsync().ConfigureAwait(false);
        await clientConnection.DisposeAsync().ConfigureAwait(false);
    }
}
